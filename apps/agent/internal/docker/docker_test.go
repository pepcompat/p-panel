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

func TestBuildEngineAllowlist(t *testing.T) {
	q := func(kv ...string) map[string][]string {
		m := map[string][]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = append(m[kv[i]], kv[i+1])
		}
		return m
	}
	allowed := []struct {
		m, p string
		q    map[string][]string
	}{
		{"POST", "/build", nil}, {"POST", "/build/cancel", q("id", "x")},
		{"POST", "/images/lab-registry:5000/ppanel/websrc/push", q("tag", "build-0123456789ab")},
		{"POST", "/images/ghcr.io/acme/web/push", q("tag", "build-0123456789ab")},
		{"DELETE", "/images/lab-registry:5000/ppanel/websrc:build-0123456789ab", q("noprune", "0")},
		{"POST", "/containers/create", nil}, {"GET", "/_ping", nil},
	}
	refused := []struct {
		m, p string
		q    map[string][]string
	}{
		{"POST", "/images/ghcr.io/acme/web/push", q("tag", "latest")},
		{"POST", "/images/ghcr.io/acme/web/push", nil},
		{"POST", "/images/ghcr.io/acme/web/push", q("tag", "build-0123456789ab", "tag", "latest")},
		{"POST", "/images/web/push", q("tag", "build-0123456789ab")}, // no registry/path
		{"DELETE", "/images/ghcr.io/acme/web:latest", nil},
		{"DELETE", "/images/sha256:" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", nil},
		{"DELETE", "/images/ghcr.io/acme/web:build-0123456789ab", q("force", "1")},
		{"POST", "/build/prune", nil}, {"POST", "/images/prune", nil}, {"POST", "/containers/x/exec", nil},
		{"DELETE", "/volumes/ppanel-shop-data", nil}, {"POST", "/images/ghcr.io/acme/web/tag", q("tag", "build-0123456789ab")},
		{"GET", "/build", nil},
	}
	for _, a := range allowed {
		if !AllowedBuildCall(a.m, a.p, a.q) {
			t.Errorf("%s %s %v should be allowed on a build engine", a.m, a.p, a.q)
		}
	}
	for _, r := range refused {
		if AllowedBuildCall(r.m, r.p, r.q) {
			t.Errorf("%s %s %v must be refused", r.m, r.p, r.q)
		}
	}
	// a non-build engine refuses every build call before reaching the socket
	e := NewEngine("/nonexistent.sock")
	if e.BuildCapable() || e.Build(context.Background(), map[string][]string{}, nil, nil) == nil ||
		e.RemoveImage(context.Background(), "ghcr.io/acme/web:build-0123456789ab") == nil {
		t.Fatal("non-build engine must refuse build calls")
	}
	if AllowedCall("POST", "/build") || AllowedCall("DELETE", "/images/ghcr.io/acme/web:build-0123456789ab") {
		t.Fatal("container-ops allowlist must not include build calls")
	}
	if !NewBuildEngine("/x").BuildCapable() {
		t.Fatal("build engine")
	}
}
