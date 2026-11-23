package host

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
)

func TestParseUnits(t *testing.T) {
	u, err := ParseUnitsJSON([]byte(`[{"unit":"nginx.service","load":"loaded","active":"active","sub":"running","description":"A high performance web server"}]`))
	if err != nil || len(u) != 1 || u[0].Sub != "running" {
		t.Fatalf("%v %+v", err, u)
	}
	p := ParseUnitsPlain([]byte("nginx.service loaded active running A web server\n● bad.service not-found inactive dead bad.service\n"))
	if len(p) != 2 || p[1].Unit != "bad.service" || p[0].Description != "A web server" {
		t.Fatalf("%+v", p)
	}
}

func TestParseFPMPools(t *testing.T) {
	src := "; comment\n[global]\npid = /run/x\n[www]\nuser = www-data\ngroup = www-data\nlisten = /run/php/php8.3-fpm.sock\npm = dynamic\n[api]\nlisten = 127.0.0.1:9001\n"
	p := ParseFPMPools(strings.NewReader(src), "/etc/php/8.3/fpm/pool.d/www.conf")
	if len(p) != 2 || p[0].Name != "www" || p[0].Listen != "/run/php/php8.3-fpm.sock" || p[0].PHP != "8.3" || p[1].Listen != "127.0.0.1:9001" {
		t.Fatalf("%+v", p)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "8.2", "fpm", "pool.d"), 0o755)
	os.WriteFile(filepath.Join(dir, "8.2", "fpm", "pool.d", "a.conf"), []byte(src), 0o644)
	e := &Env{PhpFpmPoolGlob: filepath.Join(dir, "*", "fpm", "pool.d", "*.conf")}
	pools, err := e.PhpFpmPools()
	if err != nil || len(pools) != 2 {
		t.Fatalf("%v %+v", err, pools)
	}
	if !e.phpFpmPresent() {
		t.Fatal("php-fpm should be detected from pool files")
	}
}

func TestParseProcNetTCP(t *testing.T) {
	src := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
`
	l := ParseProcNetTCP(strings.NewReader(src), "tcp")
	if len(l) != 1 || l[0].Address != "127.0.0.1" || l[0].Port != 8080 {
		t.Fatalf("%+v", l)
	}
	src6 := "0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 0 0 0 0 0 999 1\n"
	l6 := ParseProcNetTCP(strings.NewReader(src6), "tcp6")
	if len(l6) != 1 || l6[0].Address != "::" || l6[0].Port != 80 {
		t.Fatalf("%+v", l6)
	}
}

func TestNginxVersionProbe(t *testing.T) {
	fake := &fakeExec{stderr: "nginx version: nginx/1.24.0 (Ubuntu)\n"}
	bin, _ := execx.Find("echo", "")
	e := &Env{Exec: fake, NginxBinary: bin}
	info := e.Nginx(context.Background())
	if !info.Present || info.Version != "1.24.0" {
		t.Fatalf("%+v", info)
	}
	if len(fake.calls) != 1 || strings.Join(fake.calls[0], " ") != bin+" -v" {
		t.Fatalf("calls %v", fake.calls)
	}
}

type fakeExec struct {
	stdout, stderr string
	calls          [][]string
}

func (f *fakeExec) Run(_ context.Context, bin string, args []string, _ time.Duration, _ int) (execx.Result, error) {
	f.calls = append(f.calls, append([]string{bin}, args...))
	return execx.Result{Stdout: []byte(f.stdout), Stderr: []byte(f.stderr)}, nil
}

func TestDockerCapabilityRequiresPing(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hcp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	status := 500
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })}
	go srv.Serve(ln)
	defer srv.Close()
	e := &Env{Docker: docker.New(sock), SystemdRunDir: filepath.Join(dir, "none"), PhpFpmPoolGlob: filepath.Join(dir, "none")}
	has := func() bool {
		for _, c := range e.Capabilities() {
			if c == "docker" {
				return true
			}
		}
		return false
	}
	if has() {
		t.Fatal("docker capability reported although /_ping answered 500")
	}
	status = 200
	if !has() {
		t.Fatal("docker capability missing although /_ping answered 200")
	}
	hasBuild := func() bool {
		for _, c := range e.Capabilities() {
			if c == "build" {
				return true
			}
		}
		return false
	}
	if hasBuild() {
		t.Fatal("build capability without build.enabled")
	}
	e.BuildEnabled = true
	if hasBuild() {
		t.Fatal("build capability without a git binary")
	}
	e.GitBinary = "/usr/bin/git"
	if !hasBuild() {
		t.Fatal("build capability missing (enabled + docker + git)")
	}
	status = 500
	if hasBuild() {
		t.Fatal("build capability reported although docker does not answer")
	}
}

func TestBackupCapability(t *testing.T) {
	e := &Env{PhpFpmPoolGlob: filepath.Join(t.TempDir(), "*.conf"), SystemdRunDir: t.TempDir() + "/none"}
	for _, c := range e.Capabilities() {
		if c == "backup" {
			t.Fatal("backup reported without a verified restic")
		}
	}
	e.BackupReady = true
	found := false
	for _, c := range e.Capabilities() {
		found = found || c == "backup"
	}
	if !found {
		t.Fatal("backup capability missing")
	}
}
