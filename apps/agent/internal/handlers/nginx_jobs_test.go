package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/nginxops"
)

func nginxGrant(jobID, typ string, params any) *jobs.Grant {
	b, _ := json.Marshal(params)
	return &jobs.Grant{JobID: jobID, Type: typ, Params: b, LeaseToken: "l", ServerID: "s", ExpiresAt: time.Now().Add(time.Minute)}
}

func TestNginxHandlersRegisteredWithContractFlags(t *testing.T) {
	reg, _, _ := setup(t)
	want := map[string]bool{"nginx.read_files": false, "nginx.validate": true, "nginx.apply": true, "nginx.revert": true}
	for typ, mut := range want {
		h, ok := reg.Get(typ)
		if !ok || h.Mutating() != mut {
			t.Fatalf("%s registered=%v mutating=%v", typ, ok, h != nil && h.Mutating())
		}
	}
	// without a configured manager the jobs are rejected with NGINX_NOT_PRESENT
	_, _, rej := reg.Validate(nginxGrant("j", "nginx.read_files", map[string]any{"paths": []string{"/etc/nginx/nginx.conf"}}), "s", time.Now())
	if rej == nil || rej.Code != nginxops.CodeNginxNotPresent {
		t.Fatalf("rej=%v", rej)
	}
}

func TestNginxGrantRejectedBeforeAck(t *testing.T) {
	t.Setenv(config.TestNginxRootEnv, "1")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sites-available"), 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := nginxops.New(nginxops.Options{Root: root, StateDir: t.TempDir(), Exec: execx.System{}})
	if err != nil {
		t.Fatal(err)
	}
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Host: &host.Env{Exec: execx.System{}}, Sampler: &metrics.Sampler{},
		OwnedUnits: func() (map[string]bool, error) { return nil, nil }, Nginx: m})
	rid := "11111111-2222-4333-8444-555555555555"
	for name, files := range map[string][]map[string]any{
		"traversal":      {{"path": "/etc/nginx/../etc/passwd", "expectedSha256Before": nil, "content": "x"}},
		"create-outside": {{"path": "/etc/nginx/sites-available/new.conf", "expectedSha256Before": nil, "content": "x"}},
		"nul":            {{"path": "/etc/nginx/ppanel-managed/a.conf", "expectedSha256Before": nil, "content": "a\x00"}},
	} {
		for _, typ := range []string{"nginx.validate", "nginx.apply"} {
			_, _, rej := reg.Validate(nginxGrant("j", typ, map[string]any{"revisionId": rid, "files": files}), "s", time.Now())
			if rej == nil || rej.Code != nginxops.CodePathNotAllowed {
				t.Fatalf("%s/%s: %v", name, typ, rej)
			}
		}
	}
	// filesystem policy also checked at preflight (dir symlink escaping root)
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	_, _, rej := reg.Validate(nginxGrant("j", "nginx.read_files", map[string]any{"paths": []string{"/etc/nginx/evil/x"}}), "s", time.Now())
	if rej == nil || rej.Code != nginxops.CodePathNotAllowed {
		t.Fatalf("preflight: %v", rej)
	}
	// unknown param → REJECTED_INVALID_PARAMS
	_, _, rej = reg.Validate(nginxGrant("j", "nginx.revert", map[string]any{"revisionId": rid, "expectedCurrent": []any{}, "force": true}), "s", time.Now())
	if rej == nil || rej.Code != jobs.RejectedInvalidParams {
		t.Fatalf("unknown field: %v", rej)
	}
	// a valid read through the registry
	h, p, rej := reg.Validate(nginxGrant("j", "nginx.read_files", map[string]any{"paths": []string{"/etc/nginx/sites-available/none.conf"}}), "s", time.Now())
	if rej != nil {
		t.Fatal(rej)
	}
	out, err := h.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	var je *jobs.Error
	if errors.As(err, &je) {
		t.Fatal(je)
	}
	if out.(*nginxops.ReadOutput).Files[0].Exists {
		t.Fatal("non-existent file reported as existing")
	}
}
