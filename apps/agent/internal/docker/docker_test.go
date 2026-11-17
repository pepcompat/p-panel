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
