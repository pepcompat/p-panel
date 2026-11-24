package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/nginx"
)

type fakeExec struct {
	mu    sync.Mutex
	calls [][]string
	out   map[string]execx.Result // keyed by first arg
}

func (f *fakeExec) Run(_ context.Context, bin string, args []string, _ time.Duration, _ int) (execx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{bin}, args...))
	if len(args) > 0 {
		if r, ok := f.out[args[0]]; ok {
			return r, nil
		}
	}
	return execx.Result{Stdout: []byte("active\n")}, nil
}

func fakeBin(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(p, []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func setup(t *testing.T, owned ...string) (*jobs.Registry, *fakeExec, string) {
	fe := &fakeExec{out: map[string]execx.Result{}}
	bin := fakeBin(t)
	set := map[string]bool{}
	for _, u := range owned {
		set[u] = true
	}
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{
		Host:       &host.Env{Exec: fe, SystemctlBinary: bin, NginxBinary: bin, PhpFpmPoolGlob: filepath.Join(t.TempDir(), "*.conf"), ProcRoot: t.TempDir()},
		Sampler:    &metrics.Sampler{},
		OwnedUnits: func() (map[string]bool, error) { return set, nil },
	})
	return reg, fe, bin
}

func grant(typ string, params any) *jobs.Grant {
	b, _ := json.Marshal(params)
	return &jobs.Grant{JobID: "j1", Type: typ, Params: b, LeaseToken: "l", ServerID: "s", ExpiresAt: time.Now().Add(time.Minute)}
}

func TestRegistryIsAllowlist(t *testing.T) {
	reg, _, _ := setup(t)
	got := strings.Join(reg.Types(), ",")
	if got != "backup.run,backup.snapshots,backup.verify,compose.apply,compose.stop,container.list,container.logs,container.remove,container.restart,container.run_candidate,container.start,container.stop,discovery.scan,http.probe,image.build,inventory.collect,network.diagnose,nginx.apply,nginx.read_files,nginx.revert,nginx.validate,restore.run,service.restart,source.inspect" {
		t.Fatalf("registered handlers: %s", got)
	}
}

func TestServiceRestartRejections(t *testing.T) {
	reg, fe, _ := setup(t, "myapp.service")
	bad := []string{
		"x; rm -rf /", "x; rm -rf /.service", "../etc/passwd.service", "../../x.service", "--help", "--help.service",
		"-x.service", "myapp", "myapp.service\n", "my app.service", "$(id).service", "`id`.service", "a|b.service",
		"", strings.Repeat("a", 200) + ".service", "..service", "a/b.service", "myapp.socket",
	}
	for _, u := range bad {
		_, _, rej := reg.Validate(grant("service.restart", map[string]any{"unit": u}), "s", time.Now())
		if rej == nil || rej.Code != jobs.RejectedInvalidParams {
			t.Errorf("unit %q: want REJECTED_INVALID_PARAMS, got %v", u, rej)
		}
	}
	// well-formed but not owned
	_, _, rej := reg.Validate(grant("service.restart", map[string]any{"unit": "sshd.service"}), "s", time.Now())
	if rej == nil || rej.Code != jobs.RejectedNotOwned {
		t.Fatalf("not-owned: %v", rej)
	}
	// unknown field / extra args smuggling
	_, _, rej = reg.Validate(grant("service.restart", map[string]any{"unit": "myapp.service", "args": []string{"--force"}}), "s", time.Now())
	if rej == nil || rej.Code != jobs.RejectedInvalidParams {
		t.Fatalf("unknown field: %v", rej)
	}
	if len(fe.calls) != 0 {
		t.Fatalf("no process may be spawned for rejected grants: %v", fe.calls)
	}
}

func TestServiceRestartOwnedUnitFixedArgv(t *testing.T) {
	reg, fe, bin := setup(t, "myapp@1.service")
	h, p, rej := reg.Validate(grant("service.restart", map[string]any{"unit": "myapp@1.service"}), "s", time.Now())
	if rej != nil {
		t.Fatal(rej)
	}
	out, err := h.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 2 ||
		strings.Join(fe.calls[0], " ") != bin+" restart --no-ask-password -- myapp@1.service" ||
		strings.Join(fe.calls[1], " ") != bin+" is-active -- myapp@1.service" {
		t.Fatalf("argv %q", fe.calls)
	}
	if m := out.(map[string]any); m["activeState"] != "active" || m["restarted"] != true {
		t.Fatalf("out %v", out)
	}
	// non-zero exit -> HANDLER_FAILED
	fe.out["restart"] = execx.Result{ExitCode: 5, Stderr: []byte("Failed to restart")}
	_, err = h.Run(context.Background(), p)
	var je *jobs.Error
	if !errors.As(err, &je) || je.Code != jobs.HandlerFailed {
		t.Fatalf("want HANDLER_FAILED, got %v", err)
	}
}

func TestDiscoveryParams(t *testing.T) {
	reg, _, _ := setup(t)
	for _, p := range []any{map[string]any{}, map[string]any{"sources": []string{}}, map[string]any{"sources": []string{"nginx", "shell"}},
		map[string]any{"sources": []string{"nginx", "nginx"}}, map[string]any{"sources": []string{"nginx"}, "x": 1}, map[string]any{"sources": "nginx"}} {
		if _, _, rej := reg.Validate(grant("discovery.scan", p), "s", time.Now()); rej == nil || rej.Code != jobs.RejectedInvalidParams {
			t.Errorf("%v: %v", p, rej)
		}
	}
}

func TestDiscoveryNginxFromDump(t *testing.T) {
	reg, fe, bin := setup(t)
	dump, err := os.ReadFile("../../testdata/nginx/nginx-T.txt")
	if err != nil {
		t.Fatal(err)
	}
	fe.out["-T"] = execx.Result{Stdout: dump, Stderr: []byte("nginx: configuration file /etc/nginx/nginx.conf test is successful\n")}
	fe.out["-v"] = execx.Result{Stderr: []byte("nginx version: nginx/1.24.0\n")}
	h, p, rej := reg.Validate(grant("discovery.scan", map[string]any{"sources": []string{"nginx", "ports", "php-fpm"}}), "s", time.Now())
	if rej != nil {
		t.Fatal(rej)
	}
	out, err := h.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	var res struct {
		ReadOnly bool `json:"readOnly"`
		Nginx    struct {
			Status string `json:"status"`
			Data   struct {
				Report struct {
					Servers []json.RawMessage `json:"servers"`
				} `json:"report"`
			} `json:"data"`
		} `json:"nginx"`
		Ports  struct{ Status string } `json:"ports"`
		PhpFpm struct{ Status string } `json:"php-fpm"`
	}
	json.Unmarshal(b, &res)
	if !res.ReadOnly || res.Nginx.Status != "ok" || len(res.Nginx.Data.Report.Servers) != 8 {
		t.Fatalf("nginx discovery: %s", b)
	}
	if res.Ports.Status != "unavailable" || res.PhpFpm.Status != "unavailable" {
		t.Fatalf("ports/php status: %s", b)
	}
	// only read-only invocations were made
	for _, c := range fe.calls {
		if c[0] != bin || (c[1] != "-v" && c[1] != "-T") {
			t.Fatalf("unexpected exec %v", c)
		}
	}
}

func TestInventoryCollect(t *testing.T) {
	reg, _, _ := setup(t)
	h, p, rej := reg.Validate(grant("inventory.collect", map[string]any{}), "s", time.Now())
	if rej != nil {
		t.Fatal(rej)
	}
	out, err := h.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	for _, k := range []string{`"host"`, `"metrics"`, `"addresses"`, `"capabilities"`, `"docker"`, `"systemd"`, `"nginx"`, `"phpFpm"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("inventory missing %s: %s", k, b)
		}
	}
	if _, _, rej := reg.Validate(grant("inventory.collect", map[string]any{"x": 1}), "s", time.Now()); rej == nil {
		t.Fatal("inventory.collect must reject unknown params")
	}
}

// Regression (lab E2E 2026-11-23): scan checksums must equal file-byte sha256 used by
// nginx.read_files/apply, otherwise every pPanel apply is reported as external drift.
func TestUseDiskChecksums(t *testing.T) {
	files := []nginx.FileInfo{{Path: "/etc/nginx/a.conf", Sha256: "dump"}, {Path: "/etc/nginx/gone.conf", Sha256: "dump2"}}
	useDiskChecksums(files, func(p string) ([]byte, error) {
		if p == "/etc/nginx/a.conf" {
			return []byte("server {}\n"), nil
		}
		return nil, os.ErrNotExist
	})
	want := sha256.Sum256([]byte("server {}\n"))
	if files[0].Sha256 != hex.EncodeToString(want[:]) || files[0].ShaSource != "disk" {
		t.Fatalf("disk checksum not used: %+v", files[0])
	}
	if files[1].Sha256 != "dump2" || files[1].ShaSource != "nginx-T" {
		t.Fatalf("fallback wrong: %+v", files[1])
	}
}

// P9: network.diagnose / http.probe are read-only and validate before ack.
func TestNetworkJobsValidateBeforeAck(t *testing.T) {
	reg, _, _ := setup(t)
	for _, typ := range []string{"network.diagnose", "http.probe"} {
		h, ok := reg.Get(typ)
		if !ok || h.Mutating() {
			t.Fatalf("%s: registered=%v mutating", typ, ok)
		}
	}
	bad := map[string]any{
		"network.diagnose": map[string]any{"tcp": []any{map[string]any{"host": "8.8.8.8", "port": 443}}},
		"http.probe":       map[string]any{"url": "http://shop.example.lab/", "resolveTo": "169.254.169.254"},
	}
	for typ, p := range bad {
		_, _, rej := reg.Validate(grant(typ, p), "s", time.Now())
		if rej == nil || rej.Code != jobs.RejectedInvalidParams {
			t.Fatalf("%s: %v", typ, rej)
		}
	}
	_, params, rej := reg.Validate(grant("network.diagnose", map[string]any{"tcp": []any{map[string]any{"host": "10.110.0.20", "port": 22}}}), "s", time.Now())
	if rej != nil || params == nil {
		t.Fatalf("valid diagnose rejected: %v", rej)
	}
}
