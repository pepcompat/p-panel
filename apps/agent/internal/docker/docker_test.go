package docker

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyClientOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "dk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	methods := []string{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		switch r.URL.Path {
		case "/containers/json":
			w.Write([]byte(`[{"Id":"abc","Names":["/web"],"Image":"nginx:1","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","DB_PASSWORD":"hunter2"},"Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]`))
		case "/version":
			w.Write([]byte(`{"Version":"27.0.1","ApiVersion":"1.46"}`))
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := New(sock)
	if !c.Accessible() {
		t.Fatal("socket should be accessible")
	}
	cs, err := c.Containers(context.Background())
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %v", err, cs)
	}
	if cs[0].Compose == nil || cs[0].Compose.Project != "shop" || cs[0].Labels["DB_PASSWORD"] != "[redacted]" || cs[0].Ports[0].PublicPort != 8080 {
		t.Fatalf("%+v", cs[0])
	}
	v, err := c.EngineVersion(context.Background())
	if err != nil || v.Version != "27.0.1" {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://docker/containers/abc/restart", nil)
	if _, err := c.hc.Do(req); err == nil {
		t.Fatal("POST must be refused by the read-only transport")
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Fatalf("non-GET reached daemon: %s", m)
		}
	}
	if New(filepath.Join(dir, "missing.sock")).Accessible() {
		t.Fatal("missing socket must not be accessible")
	}
}

func TestEngineTransportRefusesNonAllowlisted(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "dke")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/_ping" {
			w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(204)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	e := NewEngine(sock)
	if err := e.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"POST", "/containers/abc/exec"}, {"POST", "/build"}, {"DELETE", "/volumes/x"}, {"POST", "/containers/abc/kill"}} {
		if _, err := e.do(context.Background(), e.hc, c[0], c[1], nil, nil, nil); err == nil {
			t.Fatalf("%v not refused", c)
		}
	}
	if err := e.StopContainer(context.Background(), "abc", 10); err != nil {
		t.Fatal(err)
	}
	for _, s := range seen {
		if s != "GET /_ping" && s != "POST /containers/abc/stop" {
			t.Fatalf("refused call reached daemon: %s", s)
		}
	}
	c := New(sock)
	if !c.Ping(context.Background()) {
		t.Fatal("GET-only client ping")
	}
	srv.Close()
	if c.Ping(context.Background()) || NewEngine(filepath.Join(dir, "none.sock")).Ping(context.Background()) == nil {
		t.Fatal("ping must fail when the engine is down")
	}
	if !IsUnavailable(NewEngine(filepath.Join(dir, "none.sock")).Ping(context.Background())) {
		t.Fatal("missing socket must be UnavailableError")
	}
}

func TestDemuxAndDigestRef(t *testing.T) {
	in := append([]byte{1, 0, 0, 0, 0, 0, 0, 3}, []byte("ab\n")...)
	in = append(in, append([]byte{2, 0, 0, 0, 0, 0, 0, 2}, []byte("c\n")...)...)
	if got := string(Demux(in)); got != "ab\nc\n" {
		t.Fatalf("%q", got)
	}
	if got := string(Demux([]byte("plain text\n"))); got != "plain text\n" {
		t.Fatalf("%q", got)
	}
	if r, d, ok := SplitDigestRef("reg:5000/a/b@sha256:abc"); !ok || r != "reg:5000/a/b" || d != "sha256:abc" {
		t.Fatal(r, d)
	}
	if _, _, ok := SplitDigestRef("reg/a:v1"); ok {
		t.Fatal("tag accepted")
	}
}
