package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/nginxops"
)

// TestLabNginxOps runs the P3 nginx jobs against the REAL nginx and /etc/nginx
// of a disposable lab node (scripts/lab/up.sh). Opt-in, run inside the node:
//
//	PPANEL_LAB_HOST=1 ./handlers.test -test.run TestLabNginxOps -test.v
func TestLabNginxOps(t *testing.T) {
	if os.Getenv("PPANEL_LAB_HOST") != "1" {
		t.Skip("set PPANEL_LAB_HOST=1 to run against a real Linux lab host")
	}
	const site = "/etc/nginx/sites-available/01-static-multi.conf"
	state := t.TempDir()
	m, err := nginxops.New(nginxops.Options{StateDir: state, Exec: execx.System{}})
	if err != nil {
		t.Fatal(err)
	}
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Host: &host.Env{Exec: execx.System{}}, Sampler: &metrics.Sampler{},
		OwnedUnits: func() (map[string]bool, error) { return nil, nil }, Nginx: m})
	outDir := os.Getenv("PPANEL_LAB_OUT")
	n := 0
	run := func(typ string, params any) (any, *jobs.Error) {
		t.Helper()
		n++
		jobID := "0000000" + strconv.Itoa(n) + "-aaaa-4bbb-8ccc-dddddddddddd"
		h, p, rej := reg.Validate(nginxGrant(jobID, typ, params), "s", time.Now())
		var out any
		var je *jobs.Error
		if rej != nil {
			je = rej
		} else {
			o, err := h.Run(jobs.WithJobID(context.Background(), jobID), p)
			out = o
			if err != nil && !errors.As(err, &je) {
				t.Fatalf("%s: non-job error %v", typ, err)
			}
		}
		b, _ := json.MarshalIndent(map[string]any{"type": typ, "output": out, "error": je}, "", " ")
		t.Logf("step %d %s → %s", n, typ, b)
		if outDir != "" {
			_ = os.WriteFile(filepath.Join(outDir, "nginx-step-"+strconv.Itoa(n)+"-"+typ+".json"), b, 0o644)
		}
		return out, je
	}
	treeSum := func() map[string]string {
		out := map[string]string{}
		_ = filepath.WalkDir("/etc/nginx", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				l, _ := os.Readlink(p)
				out[p] = "-> " + l
			} else if d.Type().IsRegular() {
				b, _ := os.ReadFile(p)
				s := sha256.Sum256(b)
				out[p] = hex.EncodeToString(s[:])
			}
			return nil
		})
		return out
	}
	same := func(label string, a, b map[string]string) {
		t.Helper()
		if len(a) != len(b) {
			t.Fatalf("%s: /etc/nginx file count changed %d → %d", label, len(a), len(b))
		}
		for k, v := range a {
			if b[k] != v {
				t.Fatalf("%s: %s changed", label, k)
			}
		}
		t.Logf("%s: /etc/nginx checksums identical (%d entries)", label, len(a))
	}
	masterPid := func() string {
		b, err := os.ReadFile("/run/nginx.pid")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	get := func(hostHeader, path string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = hostHeader
		c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s%s: %v", hostHeader, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	sha := func(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }

	// read_files (incl. a sites-enabled symlink)
	ro, je := run("nginx.read_files", map[string]any{"paths": []string{site, "/etc/nginx/sites-enabled/01-static-multi.conf"}})
	if je != nil {
		t.Fatal(je)
	}
	rf := ro.(*nginxops.ReadOutput).Files
	if !rf[1].IsSymlink || rf[1].ResolvedPath != site || rf[0].Content == nil {
		t.Fatalf("read_files: %+v", rf)
	}
	orig := *rf[0].Content
	origSha := *rf[0].Sha256
	t.Cleanup(func() { // lab safety net: never leave the node modified if a step fails
		if b, err := os.ReadFile(site); err == nil && string(b) != orig {
			_ = os.WriteFile(site, []byte(orig), 0o644)
			_ = os.Remove("/etc/nginx/ppanel-managed/p3-lab.conf")
			_, _ = execx.System{}.Run(context.Background(), "/usr/sbin/nginx", []string{"-s", "reload"}, 10*time.Second, 4096)
			t.Log("cleanup: restored original fixture and reloaded")
		}
	})
	initial := treeSum()
	pid0 := masterPid()
	if get("static.example.lab", "/") != 200 || get("static.example.lab", "/p3-probe") != 404 {
		t.Fatal("fixture precondition: static.example.lab / must be 200 and /p3-probe 404")
	}
	good := strings.Replace(orig, "    location / {", "    location = /p3-probe { return 200 \"p3-ok\\n\"; }\n\n    location / {", 1)
	if good == orig {
		t.Fatal("could not build candidate")
	}
	broken := orig + "\nBROKEN_DIRECTIVE_P3 on;\n"

	// P3-T04 on the real host: symlink target / traversal / create outside managed
	for _, files := range [][]map[string]any{
		{{"path": "/etc/nginx/sites-enabled/01-static-multi.conf", "expectedSha256Before": origSha, "content": good}},
		{{"path": "/etc/nginx/../etc/passwd", "expectedSha256Before": origSha, "content": "x"}},
		{{"path": "/etc/nginx/conf.d/new.conf", "expectedSha256Before": nil, "content": "x"}},
	} {
		if _, je := run("nginx.apply", map[string]any{"revisionId": "aaaaaaaa-0000-4000-8000-000000000001", "files": files}); je == nil || je.Code != nginxops.CodePathNotAllowed {
			t.Fatalf("expected PATH_NOT_ALLOWED, got %v", je)
		}
	}
	// P3-T05: drift
	if _, je := run("nginx.apply", map[string]any{"revisionId": "aaaaaaaa-0000-4000-8000-000000000001",
		"files": []map[string]any{{"path": site, "expectedSha256Before": sha("stale"), "content": good}}}); je == nil || je.Code != nginxops.CodeDriftDetected {
		t.Fatalf("expected DRIFT_DETECTED, got %v", je)
	}
	same("after rejected jobs", initial, treeSum())

	// validate good / broken: never reloads, always restores
	vo, je := run("nginx.validate", map[string]any{"revisionId": "aaaaaaaa-0000-4000-8000-000000000001",
		"files": []map[string]any{{"path": site, "expectedSha256Before": origSha, "content": good}, {"path": "/etc/nginx/ppanel-managed/p3-lab.conf", "expectedSha256Before": nil, "content": "# ppanel managed\n"}}})
	if je != nil || !vo.(*nginxops.ValidateOutput).Valid {
		t.Fatalf("validate good: %v %+v", je, vo)
	}
	same("after validate(good)", initial, treeSum())
	vo, je = run("nginx.validate", map[string]any{"revisionId": "aaaaaaaa-0000-4000-8000-000000000001",
		"files": []map[string]any{{"path": site, "expectedSha256Before": origSha, "content": broken}}})
	if je != nil || vo.(*nginxops.ValidateOutput).Valid {
		t.Fatalf("validate broken: %v %+v", je, vo)
	}
	same("after validate(broken)", initial, treeSum())
	if masterPid() != pid0 || get("static.example.lab", "/p3-probe") != 404 {
		t.Fatal("validate affected the running nginx")
	}

	// apply broken → NGINX_TEST_FAILED, nothing reloaded
	if _, je := run("nginx.apply", map[string]any{"revisionId": "aaaaaaaa-0000-4000-8000-000000000002",
		"files": []map[string]any{{"path": site, "expectedSha256Before": origSha, "content": broken}}}); je == nil || je.Code != nginxops.CodeNginxTestFailed {
		t.Fatalf("expected NGINX_TEST_FAILED, got %v", je)
	}
	same("after apply(broken)", initial, treeSum())

	// apply good with postchecks → reload, master pid unchanged, new location live
	const rev = "bbbbbbbb-0000-4000-8000-000000000001"
	ao, je := run("nginx.apply", map[string]any{"revisionId": rev,
		"files": []map[string]any{{"path": site, "expectedSha256Before": origSha, "content": good}},
		"postchecks": []map[string]any{
			{"hostHeader": "static.example.lab", "path": "/p3-probe", "expectStatus": []int{200}},
			{"hostHeader": "static.example.lab", "path": "/"},
			{"hostHeader": "secure.example.lab", "scheme": "https", "path": "/", "expectStatus": []int{200, 301, 302, 404}},
		}})
	if je != nil {
		t.Fatalf("apply good: %v", je)
	}
	a := ao.(*nginxops.ApplyOutput)
	if !a.Applied || a.ReloadMethod == "" || a.BackupID != rev {
		t.Fatalf("apply output: %+v", a)
	}
	if pid1 := masterPid(); pid1 != pid0 {
		t.Fatalf("nginx master pid changed on reload: %s → %s", pid0, pid1)
	}
	if get("static.example.lab", "/p3-probe") != 200 {
		t.Fatal("new location not live after reload")
	}
	t.Logf("apply good: reloadMethod=%q master pid unchanged=%s, /p3-probe now 200", a.ReloadMethod, pid0)
	goodSha := sha(good)

	// apply with failing postcheck → POSTCHECK_FAILED_REVERTED, site still 200
	two := strings.Replace(good, "location = /p3-probe", "location = /p3-two { return 200; }\n    location = /p3-probe", 1)
	_, je = run("nginx.apply", map[string]any{"revisionId": "bbbbbbbb-0000-4000-8000-000000000002",
		"files":      []map[string]any{{"path": site, "expectedSha256Before": goodSha, "content": two}},
		"postchecks": []map[string]any{{"hostHeader": "static.example.lab", "path": "/p3-does-not-exist", "expectStatus": []int{200}}}})
	if je == nil || je.Code != nginxops.CodePostcheckReverted {
		t.Fatalf("expected POSTCHECK_FAILED_REVERTED, got %v", je)
	}
	cur, _ := os.ReadFile(site)
	if sha(string(cur)) != goodSha || get("static.example.lab", "/") != 200 || get("static.example.lab", "/p3-probe") != 200 || get("static.example.lab", "/p3-two") != 404 {
		t.Fatal("postcheck failure did not restore the previous live config")
	}
	if masterPid() != pid0 {
		t.Fatal("master pid changed")
	}

	// revert drift, then revert the good apply
	if _, je := run("nginx.revert", map[string]any{"revisionId": rev, "expectedCurrent": []map[string]any{{"path": site, "sha256": origSha}}}); je == nil || je.Code != nginxops.CodeDriftDetected {
		t.Fatalf("expected DRIFT_DETECTED, got %v", je)
	}
	if _, je := run("nginx.revert", map[string]any{"revisionId": "cccccccc-0000-4000-8000-000000000001", "expectedCurrent": []map[string]any{{"path": site, "sha256": goodSha}}}); je == nil || je.Code != nginxops.CodeBackupNotFound {
		t.Fatalf("expected BACKUP_NOT_FOUND, got %v", je)
	}
	rvo, je := run("nginx.revert", map[string]any{"revisionId": rev, "expectedCurrent": []map[string]any{{"path": site, "sha256": goodSha}}})
	if je != nil || !rvo.(*nginxops.RevertOutput).Reverted {
		t.Fatalf("revert: %v", je)
	}
	same("after revert", initial, treeSum())
	if get("static.example.lab", "/p3-probe") != 404 || get("static.example.lab", "/") != 200 || masterPid() != pid0 {
		t.Fatal("revert did not restore live behaviour")
	}
	t.Logf("all lab steps passed; master pid %s unchanged throughout", pid0)
}
