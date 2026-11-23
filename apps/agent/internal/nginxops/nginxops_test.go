package nginxops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

func TestMain(m *testing.M) {
	os.Setenv(config.TestNginxRootEnv, "1")
	os.Exit(m.Run())
}

// fakeNginx is an execx.Executor emulating nginx/systemctl against the temp root.
// `nginx -t` fails when any config file contains the token "BROKEN".
type fakeNginx struct {
	mu          sync.Mutex
	root        string
	pidFile     string
	calls       [][]string
	reloads     int
	reloadFail  bool
	unitActive  bool
	testDelay   time.Duration
	inTest      int32
	maxInTest   int32
	testSeen    []map[string]string // root snapshot at each nginx -t
	failAfterNT int                 // >0: the N-th and later nginx -t fail
	nTests      int
}

func (f *fakeNginx) Run(_ context.Context, bin string, args []string, _ time.Duration, _ int) (execx.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{filepath.Base(bin)}, args...))
	f.mu.Unlock()
	base := filepath.Base(bin)
	last := args[len(args)-1]
	switch {
	case strings.HasPrefix(base, "systemctl") && args[0] == "is-active":
		if f.unitActive {
			return execx.Result{}, nil
		}
		return execx.Result{ExitCode: 3}, nil
	case strings.HasPrefix(base, "systemctl") && args[0] == "reload", len(args) >= 2 && args[len(args)-2] == "-s" && last == "reload":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reloads++
		if f.reloadFail {
			return execx.Result{ExitCode: 1, Stderr: []byte("nginx: [error] reload failed")}, nil
		}
		return execx.Result{}, nil
	case last == "-T":
		return execx.Result{Stdout: []byte("# configuration file /etc/nginx/nginx.conf:\nuser www-data;\npid " + f.pidFile + ";\n")}, nil
	case last == "-t":
		n := atomic.AddInt32(&f.inTest, 1)
		for {
			mx := atomic.LoadInt32(&f.maxInTest)
			if n <= mx || atomic.CompareAndSwapInt32(&f.maxInTest, mx, n) {
				break
			}
		}
		defer atomic.AddInt32(&f.inTest, -1)
		if f.testDelay > 0 {
			time.Sleep(f.testDelay)
		}
		snap := tree(f.root)
		f.mu.Lock()
		f.testSeen = append(f.testSeen, snap)
		f.nTests++
		forced := f.failAfterNT > 0 && f.nTests >= f.failAfterNT
		f.mu.Unlock()
		for p, c := range snap {
			if strings.Contains(c, "BROKEN") || forced {
				return execx.Result{ExitCode: 1, Stderr: []byte(fmt.Sprintf("nginx: [emerg] unknown directive \"BROKEN\" in /etc/nginx/%s:1\nnginx: configuration file /etc/nginx/nginx.conf test failed\n", p))}, nil
			}
		}
		return execx.Result{Stderr: []byte("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n")}, nil
	}
	return execx.Result{ExitCode: 127}, fmt.Errorf("fake: unexpected %v", args)
}

func (f *fakeNginx) reloadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloads
}

// tree snapshots every regular file (content) and symlink ("-> target") under root.
func tree(root string) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[rel] = "-> " + l
		case d.Type().IsRegular():
			b, _ := os.ReadFile(p)
			out[rel] = string(b)
		case d.IsDir():
			out[rel+"/"] = "dir"
		}
		return nil
	})
	return out
}

func sameTree(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("tree changed: before=%d entries after=%d\nbefore=%v\nafter=%v", len(before), len(after), keys(before), keys(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("tree changed at %s", k)
		}
	}
}

func keys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

const (
	origA   = "server { listen 80; server_name a.example; }\n"
	origX   = "map $a $b { default 1; }\n"
	origCfg = "events {}\nhttp { include /etc/nginx/conf.d/*.conf; include /etc/nginx/sites-enabled/*; }\n"
)

type env struct {
	m     *Manager
	f     *fakeNginx
	root  string
	state string
	out   string // a directory outside root
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "nginx")
	state := filepath.Join(base, "state")
	out := filepath.Join(base, "outside")
	for _, d := range []string{root + "/sites-available", root + "/sites-enabled", root + "/conf.d", state, out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must(t, os.WriteFile(root+"/nginx.conf", []byte(origCfg), 0o644))
	must(t, os.WriteFile(root+"/sites-available/a.conf", []byte(origA), 0o640))
	must(t, os.WriteFile(root+"/conf.d/x.conf", []byte(origX), 0o644))
	must(t, os.Symlink("../sites-available/a.conf", root+"/sites-enabled/a.conf"))
	must(t, os.WriteFile(out+"/secret", []byte("secret\n"), 0o600))
	pidFile := filepath.Join(base, "nginx.pid")
	must(t, os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644))
	bin := filepath.Join(base, "nginx-bin")
	must(t, os.WriteFile(bin, []byte("#!/bin/false\n"), 0o755))
	sc := filepath.Join(base, "systemctl-bin")
	must(t, os.WriteFile(sc, []byte("#!/bin/false\n"), 0o755))
	f := &fakeNginx{root: root, pidFile: pidFile}
	m, err := New(Options{Root: root, StateDir: state, NginxBinary: bin, SystemctlBinary: sc,
		SystemdRunDir: filepath.Join(base, "no-systemd"), Exec: f, Settle: -1, ProbeTimeout: 2 * time.Second})
	must(t, err)
	return &env{m: m, f: f, root: root, state: state, out: out}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func code(t *testing.T, err error) string {
	t.Helper()
	var je *jobs.Error
	if !errors.As(err, &je) {
		t.Fatalf("expected *jobs.Error, got %v", err)
	}
	return je.Code
}

func details(t *testing.T, err error) map[string]any {
	t.Helper()
	var je *jobs.Error
	if !errors.As(err, &je) {
		t.Fatalf("expected *jobs.Error, got %v", err)
	}
	b, _ := json.Marshal(je.Details)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func backupEntries(t *testing.T, e *env) []string {
	ents, _ := os.ReadDir(filepath.Join(e.state, "nginx-backups"))
	var n []string
	for _, x := range ents {
		n = append(n, x.Name())
	}
	return n
}

const rev1 = "11111111-2222-4333-8444-555555555555"
const rev2 = "21111111-2222-4333-8444-555555555555"

func ctxJob(id string) context.Context { return jobs.WithJobID(context.Background(), id) }

// ---------------- decode / lexical policy ----------------

func TestDecodeStrictAndLexicalPolicy(t *testing.T) {
	good := `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}]}`
	if _, err := DecodeValidate(json.RawMessage(good)); err != nil {
		t.Fatalf("good params rejected: %v", err)
	}
	pathCases := map[string]string{
		"traversal":       `/etc/nginx/../shadow`,
		"traversal-mid":   `/etc/nginx/sites-available/../../etc/passwd`,
		"double-slash":    `/etc/nginx//sites-available/a.conf`,
		"outside":         `/etc/passwd`,
		"prefix-trick":    `/etc/nginxx/a.conf`,
		"dot-segment":     `/etc/nginx/./a.conf`,
		"trailing-slash":  `/etc/nginx/sites-available/`,
		"space":           `/etc/nginx/a b.conf`,
		"glob":            `/etc/nginx/*.conf`,
		"newline":         "/etc/nginx/a\\n.conf",
		"nul":             `/etc/nginx/a\u0000.conf`,
		"create-outside":  `/etc/nginx/conf.d/new.conf`,
		"create-root":     `/etc/nginx/new.conf`,
		"managed-lookali": `/etc/nginx/ppanel-managedX/a.conf`,
	}
	for name, p := range pathCases {
		raw := `{"revisionId":"` + rev1 + `","files":[{"path":"` + p + `","expectedSha256Before":null,"content":"x"}]}`
		_, err := DecodeValidate(json.RawMessage(raw))
		if err == nil {
			t.Fatalf("%s: accepted %q", name, p)
		}
		var je *jobs.Error
		if errors.As(err, &je) && je.Code != CodePathNotAllowed {
			t.Fatalf("%s: code %s", name, je.Code)
		}
	}
	other := map[string]string{
		"unknown-field":          `{"revisionId":"` + rev1 + `","files":[],"x":1}`,
		"unknown-nested":         `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x","mode":"777"}]}`,
		"missing-expected":       `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","content":"x"}]}`,
		"bad-sha":                `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/sites-available/a.conf","expectedSha256Before":"ABC","content":"x"}]}`,
		"bad-uuid":               `{"revisionId":"nope","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}]}`,
		"no-files":               `{"revisionId":"` + rev1 + `","files":[]}`,
		"dup-path":               `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"},{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"y"}]}`,
		"postchecks-in-validate": `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}],"postchecks":[]}`,
		"trailing":               good + `{}`,
	}
	for name, raw := range other {
		if _, err := DecodeValidate(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// NUL and oversize content → PATH_NOT_ALLOWED at decode
	for name, c := range map[string]string{"nul": `a\u0000b`, "oversize": strings.Repeat("a", MaxFileBytes+1)} {
		raw := `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"` + c + `"}]}`
		_, err := DecodeValidate(json.RawMessage(raw))
		if code(t, err) != CodePathNotAllowed {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// 21 files rejected
	var fl []string
	for i := 0; i < 21; i++ {
		fl = append(fl, fmt.Sprintf(`{"path":"/etc/nginx/ppanel-managed/%d.conf","expectedSha256Before":null,"content":"x"}`, i))
	}
	if _, err := DecodeValidate(json.RawMessage(`{"revisionId":"` + rev1 + `","files":[` + strings.Join(fl, ",") + `]}`)); err == nil {
		t.Fatal("21 files accepted")
	}
}

func TestDecodeApplyPostcheckDefaultsAndRejections(t *testing.T) {
	raw := `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}],"postchecks":[{"hostHeader":"a.example"},{"hostHeader":"b.example","scheme":"https","path":"/health?x=1","expectStatus":[200,301]}]}`
	p, err := DecodeApply(json.RawMessage(raw))
	must(t, err)
	if p.Postchecks[0].Port != 80 || p.Postchecks[0].Path != "/" || p.Postchecks[0].Scheme != "http" || p.Postchecks[0].ExpectStatus[0] != 200 {
		t.Fatalf("defaults: %+v", p.Postchecks[0])
	}
	if p.Postchecks[1].Port != 443 {
		t.Fatalf("https default port: %+v", p.Postchecks[1])
	}
	noPC := `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}]}`
	if p, err := DecodeApply(json.RawMessage(noPC)); err != nil || len(p.Postchecks) != 0 {
		t.Fatalf("postchecks default []: %v %v", p, err)
	}
	for name, pc := range map[string]string{
		"host-url":   `{"hostHeader":"http://evil"}`,
		"host-at":    `{"hostHeader":"a@b"}`,
		"host-port":  `{"hostHeader":"a.example:8080"}`,
		"path-abs":   `{"hostHeader":"a","path":"http://x/"}`,
		"path-space": `{"hostHeader":"a","path":"/a b"}`,
		"scheme":     `{"hostHeader":"a","scheme":"gopher"}`,
		"port":       `{"hostHeader":"a","port":70000}`,
		"status":     `{"hostHeader":"a","expectStatus":[99]}`,
		"status-0":   `{"hostHeader":"a","expectStatus":[]}`,
		"unknown":    `{"hostHeader":"a","targetIp":"10.0.0.1"}`,
	} {
		raw := `{"revisionId":"` + rev1 + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}],"postchecks":[` + pc + `]}`
		if _, err := DecodeApply(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestDecodeRevertAndRead(t *testing.T) {
	if _, err := DecodeRevert(json.RawMessage(`{"revisionId":"` + rev1 + `","expectedCurrent":[{"path":"/etc/nginx/a.conf","sha256":null}]}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"revisionId":"` + rev1 + `","expectedCurrent":[]}`,
		`{"revisionId":"` + rev1 + `","expectedCurrent":[{"path":"/etc/nginx/a.conf"}]}`,
		`{"revisionId":"` + rev1 + `","expectedCurrent":[{"path":"/etc/nginx/../a","sha256":null}]}`,
		`{"revisionId":"` + rev1 + `","expectedCurrent":[{"path":"/etc/nginx/a.conf","sha256":null,"x":1}]}`,
	} {
		if _, err := DecodeRevert(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := DecodeRead(json.RawMessage(`{"paths":["/etc/nginx/nginx.conf"]}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"paths":[]}`, `{"paths":["/etc/shadow"]}`, `{"paths":["/etc/nginx/a"],"follow":true}`} {
		if _, err := DecodeRead(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestRootGate(t *testing.T) {
	os.Unsetenv(config.TestNginxRootEnv)
	defer os.Setenv(config.TestNginxRootEnv, "1")
	if _, err := New(Options{Root: t.TempDir(), StateDir: t.TempDir(), Exec: &fakeNginx{}}); err == nil {
		t.Fatal("non-/etc/nginx root accepted without test env")
	}
	if _, err := New(Options{Root: "/etc/nginx", Prefix: "/tmp", StateDir: t.TempDir(), Exec: &fakeNginx{}}); err == nil {
		t.Fatal("prefix accepted without test env")
	}
	if _, err := New(Options{StateDir: t.TempDir(), Exec: &fakeNginx{}}); err != nil {
		t.Fatalf("default root rejected: %v", err)
	}
}

// ---------------- P3-T04: filesystem path policy ----------------

func TestPathPolicyRejectsNothingWritten(t *testing.T) {
	e := newEnv(t)
	must(t, os.Symlink(e.out, e.root+"/evil"))                       // dir symlink escaping root
	must(t, os.Symlink(e.out+"/secret", e.root+"/conf.d/leak.conf")) // file symlink escaping root
	shaA := shaHex([]byte(origA))
	before := tree(e.root)
	cases := map[string][]FileChange{
		"write-through-symlink":  {{Path: "/etc/nginx/sites-enabled/a.conf", ExpectedSha256Before: &shaA, Content: "x"}},
		"parent-symlink-escape":  {{Path: "/etc/nginx/evil/secret", ExpectedSha256Before: strp(shaHex([]byte("secret\n"))), Content: "x"}},
		"file-symlink-escape":    {{Path: "/etc/nginx/conf.d/leak.conf", ExpectedSha256Before: strp(shaHex([]byte("secret\n"))), Content: "x"}},
		"create-outside-managed": {{Path: "/etc/nginx/conf.d/new.conf", Content: "x"}},
		"create-in-missing-dir":  {{Path: "/etc/nginx/nope/new.conf", ExpectedSha256Before: &shaA, Content: "x"}},
		"traversal":              {{Path: "/etc/nginx/../outside/secret", ExpectedSha256Before: &shaA, Content: "x"}},
		"double-slash":           {{Path: "/etc/nginx//conf.d/x.conf", ExpectedSha256Before: &shaA, Content: "x"}},
		"nul":                    {{Path: "/etc/nginx/ppanel-managed/a.conf", Content: "a\x00b"}},
		"invalid-utf8":           {{Path: "/etc/nginx/ppanel-managed/a.conf", Content: "a\xffb"}},
		"oversize":               {{Path: "/etc/nginx/ppanel-managed/a.conf", Content: strings.Repeat("a", MaxFileBytes+1)}},
		"directory-target":       {{Path: "/etc/nginx/conf.d", ExpectedSha256Before: &shaA, Content: "x"}},
		"second-file-bad":        {{Path: "/etc/nginx/ppanel-managed/ok.conf", Content: "ok"}, {Path: "/etc/nginx/sites-enabled/a.conf", ExpectedSha256Before: &shaA, Content: "x"}},
		"same-file-two-paths":    {{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "x"}, {Path: "/etc/nginx/sites-available/../sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "y"}},
	}
	for name, files := range cases {
		for _, op := range []string{"validate", "apply"} {
			var err error
			p := RevisionParams{RevisionID: rev1, Files: files}
			if op == "validate" {
				_, err = e.m.Validate(ctxJob(rev2), p)
			} else {
				_, err = e.m.Apply(ctxJob(rev2), p)
			}
			if c := code(t, err); c != CodePathNotAllowed {
				t.Fatalf("%s/%s: code %s (%v)", name, op, c, err)
			}
		}
	}
	sameTree(t, before, tree(e.root))
	if b := backupEntries(t, e); len(b) != 0 {
		t.Fatalf("backups written for rejected jobs: %v", b)
	}
	if e.f.reloadCount() != 0 || len(e.f.testSeen) != 0 {
		t.Fatal("nginx invoked for a rejected job")
	}
	// ppanel-managed symlinked to another dir inside root: creation refused
	must(t, os.Symlink("sites-available", e.root+"/ppanel-managed"))
	_, err := e.m.Validate(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/n.conf", Content: "x"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("symlinked ppanel-managed: %v", err)
	}
	if _, err := os.Stat(e.root + "/sites-available/n.conf"); err == nil {
		t.Fatal("file created through symlinked ppanel-managed")
	}
}

func TestAllowedRootsNarrow(t *testing.T) {
	e := newEnv(t)
	e.m.o.AllowedRoots = []string{"/etc/nginx/ppanel-managed"}
	shaX := shaHex([]byte(origX))
	_, err := e.m.Validate(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/conf.d/x.conf", ExpectedSha256Before: &shaX, Content: "y"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("allowedRoots not enforced: %v", err)
	}
	if _, err := e.m.Validate(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/a.conf", Content: "ok"}}}); err != nil {
		t.Fatalf("allowed path rejected: %v", err)
	}
}

// ---------------- P3-T05: drift ----------------

func TestDriftDetectedNothingWritten(t *testing.T) {
	e := newEnv(t)
	wrong := shaHex([]byte("something else"))
	shaA := shaHex([]byte(origA))
	before := tree(e.root)
	for _, op := range []string{"validate", "apply"} {
		p := RevisionParams{RevisionID: rev1, Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { ok; }"},
			{Path: "/etc/nginx/conf.d/x.conf", ExpectedSha256Before: &wrong, Content: "changed"},
			{Path: "/etc/nginx/conf.d/gone.conf", ExpectedSha256Before: &wrong, Content: "changed"},
		}}
		var err error
		if op == "validate" {
			_, err = e.m.Validate(ctxJob(rev2), p)
		} else {
			_, err = e.m.Apply(ctxJob(rev2), p)
		}
		if code(t, err) != CodeDriftDetected {
			t.Fatalf("%s: %v", op, err)
		}
		files := details(t, err)["files"].([]any)
		if len(files) != 2 {
			t.Fatalf("drift details: %v", files)
		}
		f0 := files[0].(map[string]any)
		if f0["path"] != "/etc/nginx/conf.d/x.conf" || f0["expected"] != wrong || f0["actual"] != shaHex([]byte(origX)) {
			t.Fatalf("drift entry: %v", f0)
		}
		if f1 := files[1].(map[string]any); f1["actual"] != nil {
			t.Fatalf("missing file actual must be null: %v", f1)
		}
	}
	// create where file already exists → drift
	must(t, os.MkdirAll(e.root+"/ppanel-managed", 0o755))
	must(t, os.WriteFile(e.root+"/ppanel-managed/exists.conf", []byte("operator"), 0o644))
	before = tree(e.root)
	_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/exists.conf", Content: "mine"}}})
	if code(t, err) != CodeDriftDetected {
		t.Fatalf("create-over-existing: %v", err)
	}
	sameTree(t, before, tree(e.root))
	if b := backupEntries(t, e); len(b) != 0 {
		t.Fatalf("backups written: %v", b)
	}
	if e.f.reloadCount() != 0 {
		t.Fatal("reload on drift")
	}
}

// ---------------- validate ----------------

func TestValidateAlwaysRestores(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%v", broken), func(t *testing.T) {
			e := newEnv(t)
			before := tree(e.root)
			stBefore, _ := os.Stat(e.root + "/sites-available/a.conf")
			shaA := shaHex([]byte(origA))
			newA := "server { listen 80; server_name a.example b.example; }\n"
			if broken {
				newA = "BROKEN;\n"
			}
			out, err := e.m.Validate(ctxJob("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), RevisionParams{RevisionID: rev1, Files: []FileChange{
				{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: newA},
				{Path: "/etc/nginx/ppanel-managed/new.conf", Content: "server { listen 81; }\n"},
			}})
			must(t, err) // valid:false is a SUCCEEDED job
			if out.Valid == broken {
				t.Fatalf("valid=%v broken=%v out=%s", out.Valid, broken, out.NginxTestOutput)
			}
			if broken && !strings.Contains(out.NginxTestOutput, "test failed") {
				t.Fatalf("nginxTestOutput: %q", out.NginxTestOutput)
			}
			if !broken && !strings.Contains(out.NginxTestOutput, "successful") {
				t.Fatalf("nginxTestOutput: %q", out.NginxTestOutput)
			}
			// candidate was on disk during nginx -t
			seen := e.f.testSeen[0]
			if seen["sites-available/a.conf"] != newA || seen["ppanel-managed/new.conf"] == "" {
				t.Fatalf("candidate not on disk during nginx -t: %v", keys(seen))
			}
			// originals restored byte-identically; created file + created dir removed
			sameTree(t, before, tree(e.root))
			stAfter, _ := os.Stat(e.root + "/sites-available/a.conf")
			if stAfter.Mode() != stBefore.Mode() {
				t.Fatalf("mode changed %v → %v", stBefore.Mode(), stAfter.Mode())
			}
			if e.f.reloadCount() != 0 {
				t.Fatal("validate reloaded nginx")
			}
			if len(out.FilesChecked) != 2 || *out.FilesChecked[0].Sha256Before != shaA || out.FilesChecked[1].Sha256Before != nil ||
				*out.FilesChecked[0].Sha256After != shaHex([]byte(newA)) {
				t.Fatalf("filesChecked: %+v", out.FilesChecked)
			}
			if b := backupEntries(t, e); len(b) != 0 {
				t.Fatalf("validate backup not cleaned: %v", b)
			}
		})
	}
}

// ---------------- apply ----------------

func TestApplyNginxTestFailedRestoresNoReload(t *testing.T) { // P3-T03
	e := newEnv(t)
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
		{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "BROKEN;\n"},
		{Path: "/etc/nginx/ppanel-managed/new.conf", Content: "server {}\n"},
	}})
	if code(t, err) != CodeNginxTestFailed {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(details(t, err)["nginxTestOutput"].(string), "BROKEN") {
		t.Fatalf("details: %v", details(t, err))
	}
	sameTree(t, before, tree(e.root))
	if e.f.reloadCount() != 0 {
		t.Fatal("reload invoked after failed nginx -t")
	}
	// backup kept and permits recovery: manifest + blob with the original
	man, err := e.m.loadManifest(rev1)
	must(t, err)
	if man.Status != statusAutoReverted || len(man.Files) != 2 || man.Files[1].Existed {
		t.Fatalf("manifest: %+v", man)
	}
	blob, _ := os.ReadFile(filepath.Join(e.m.backupDir(rev1), man.Files[0].Blob))
	if string(blob) != origA || *man.Files[0].Sha256 != shaA || man.Files[0].Mode != 0o640 {
		t.Fatalf("backup blob/manifest wrong: %+v", man.Files[0])
	}
	// a failed apply cannot be "reverted" (nothing applied)
	_, err = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaA}, {Path: "/etc/nginx/ppanel-managed/new.conf"}}})
	if code(t, err) != CodeBackupNotFound {
		t.Fatalf("revert of failed apply: %v", err)
	}
}

func probeServer(t *testing.T, status func(host, path string) int) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
			return
		}
		w.WriteHeader(status(r.Host, r.URL.Path))
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().(*net.TCPAddr).Port
}

func TestApplyPostcheckFailedReverts(t *testing.T) { // P7-T04
	e := newEnv(t)
	port := probeServer(t, func(host, path string) int {
		if host == "a.example" && path == "/" {
			return 200
		}
		return 503
	})
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1,
		Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 80; }\n"}},
		Postchecks: []Postcheck{
			{HostHeader: "a.example", Path: "/", Scheme: "http", Port: port, ExpectStatus: []int{200}},
			{HostHeader: "a.example", Path: "/health", Scheme: "http", Port: port, ExpectStatus: []int{200}},
		}})
	if code(t, err) != CodePostcheckReverted {
		t.Fatalf("got %v", err)
	}
	d := details(t, err)
	pcs := d["postchecks"].([]any)
	if len(pcs) != 2 || pcs[0].(map[string]any)["ok"] != true || pcs[1].(map[string]any)["ok"] != false || pcs[1].(map[string]any)["status"].(float64) != 503 {
		t.Fatalf("postcheck details: %v", pcs)
	}
	if d["revertReloadOk"] != true || d["masterPidAlive"] != true {
		t.Fatalf("details: %v", d)
	}
	sameTree(t, before, tree(e.root))
	if n := e.f.reloadCount(); n != 2 {
		t.Fatalf("expected 2 reloads (apply + revert), got %d", n)
	}
	if len(e.f.testSeen) != 2 {
		t.Fatalf("expected nginx -t on candidate and on restored config, got %d", len(e.f.testSeen))
	}
}

func TestApplyDeadMasterRevertsAndRedirectNotFollowed(t *testing.T) {
	e := newEnv(t)
	port := probeServer(t, func(string, string) int { return 200 })
	shaA := shaHex([]byte(origA))
	// redirect is not followed → 302 is reported (and accepted when expected)
	out, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1,
		Files:      []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 80; }\n"}},
		Postchecks: []Postcheck{{HostHeader: "a.example", Path: "/redirect", Scheme: "http", Port: port, ExpectStatus: []int{302}}}})
	must(t, err)
	if out.Postchecks[0].Status != 302 || !out.Postchecks[0].OK {
		t.Fatalf("redirect: %+v", out.Postchecks[0])
	}
	// now a dead master pid → POSTCHECK_FAILED_REVERTED
	must(t, os.WriteFile(e.f.pidFile, []byte("999999\n"), 0o644))
	sha2 := shaHex([]byte("server { listen 80; }\n"))
	before := tree(e.root)
	_, err = e.m.Apply(ctxJob(rev1), RevisionParams{RevisionID: "31111111-2222-4333-8444-555555555555",
		Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &sha2, Content: "server { listen 82; }\n"}}})
	if code(t, err) != CodePostcheckReverted || details(t, err)["masterPidAlive"] != false {
		t.Fatalf("dead master: %v", err)
	}
	sameTree(t, before, tree(e.root))
}

func TestApplyReloadFailedReverted(t *testing.T) {
	e := newEnv(t)
	e.f.reloadFail = true
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1,
		Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 80; }\n"}}})
	// revert's reload also fails → files restored but running config uncertain → manual recovery
	if code(t, err) != CodeRevertFailedManual {
		t.Fatalf("got %v", err)
	}
	sameTree(t, before, tree(e.root))
	// reload fails only once → RELOAD_FAILED_REVERTED
	e2 := newEnv(t)
	e2.f.reloadFail = true
	var once sync.Once
	e2.m.o.Exec = execFunc(func(ctx context.Context, bin string, args []string, to time.Duration, mx int) (execx.Result, error) {
		r, err := e2.f.Run(ctx, bin, args, to, mx)
		if args[len(args)-1] == "reload" {
			once.Do(func() { e2.f.reloadFail = false })
		}
		return r, err
	})
	before = tree(e2.root)
	_, err = e2.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1,
		Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 80; }\n"}}})
	if code(t, err) != CodeReloadFailedReverted || details(t, err)["revertReloadOk"] != true {
		t.Fatalf("got %v %v", err, details(t, err))
	}
	sameTree(t, before, tree(e2.root))
}

type execFunc func(context.Context, string, []string, time.Duration, int) (execx.Result, error)

func (f execFunc) Run(ctx context.Context, b string, a []string, t time.Duration, m int) (execx.Result, error) {
	return f(ctx, b, a, t, m)
}

func TestApplySuccessThenRevert(t *testing.T) {
	e := newEnv(t)
	port := probeServer(t, func(host, _ string) int {
		if host == "a.example" {
			return 200
		}
		return 404
	})
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	newA := "server { listen 80; server_name a.example; location /x {} }\n"
	newM := "server { listen 8080; }\n"
	out, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1,
		Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: newA},
			{Path: "/etc/nginx/ppanel-managed/site.conf", Content: newM},
		},
		Postchecks: []Postcheck{{HostHeader: "a.example", Path: "/", Scheme: "http", Port: port, ExpectStatus: []int{200}}}})
	must(t, err)
	if !out.Applied || out.BackupID != rev1 || out.ReloadMethod != ReloadSignal || len(out.Postchecks) != 1 || !out.Postchecks[0].OK ||
		!strings.Contains(out.NginxTestOutput, "successful") || *out.Files[0].Sha256After != shaHex([]byte(newA)) || out.Files[1].Sha256Before != nil {
		t.Fatalf("apply output: %+v", out)
	}
	b, _ := json.Marshal(out)
	for _, k := range []string{`"applied":true`, `"files":[`, `"sha256Before":`, `"sha256After":`, `"nginxTestOutput":`, `"reloadMethod":"nginx -s reload"`, `"postchecks":[{"hostHeader":"a.example","path":"/","status":200,"ok":true}]`, `"backupId":"` + rev1 + `"`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("apply JSON missing %s: %s", k, b)
		}
	}
	got, _ := os.ReadFile(e.root + "/sites-available/a.conf")
	st, _ := os.Stat(e.root + "/sites-available/a.conf")
	stM, _ := os.Stat(e.root + "/ppanel-managed/site.conf")
	stD, _ := os.Stat(e.root + "/ppanel-managed")
	if string(got) != newA || st.Mode().Perm() != 0o640 || stM.Mode().Perm() != 0o644 || stD.Mode().Perm() != 0o755 {
		t.Fatalf("applied state wrong: %q %v %v %v", got, st.Mode(), stM.Mode(), stD.Mode())
	}
	if e.f.reloadCount() != 1 {
		t.Fatal("expected exactly one reload")
	}
	// re-applying the same revision is refused (backup must not be overwritten)
	shaNew := shaHex([]byte(newA))
	if _, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaNew, Content: "y"}}}); err == nil {
		t.Fatal("re-apply of applied revision accepted")
	}

	shaM := shaHex([]byte(newM))
	// revert without backup
	_, err = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: "99999999-2222-4333-8444-555555555555", ExpectedCurrent: []ExpectedFile{{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaNew}}})
	if code(t, err) != CodeBackupNotFound {
		t.Fatalf("missing backup: %v", err)
	}
	// revert with drift
	_, err = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{
		{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaA}, {Path: "/etc/nginx/ppanel-managed/site.conf", Sha256: &shaM}}})
	if code(t, err) != CodeDriftDetected {
		t.Fatalf("revert drift: %v", err)
	}
	// revert must cover all revision files
	_, err = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaNew}}})
	if code(t, err) != jobs.RejectedInvalidParams {
		t.Fatalf("partial expectedCurrent: %v", err)
	}
	if e.f.reloadCount() != 1 {
		t.Fatal("rejected revert reloaded")
	}
	rout, err := e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{
		{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaNew}, {Path: "/etc/nginx/ppanel-managed/site.conf", Sha256: &shaM}}})
	must(t, err)
	if !rout.Reverted || *rout.Files[0].Sha256Before != shaNew || *rout.Files[0].Sha256After != shaA || rout.Files[1].Sha256After != nil || rout.BackupID != rev1 {
		t.Fatalf("revert output: %+v", rout)
	}
	sameTree(t, before, tree(e.root)) // created file and created ppanel-managed dir removed
	if e.f.reloadCount() != 2 {
		t.Fatal("revert did not reload")
	}
	// second revert: backup no longer "applied"
	_, err = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{
		{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaA}, {Path: "/etc/nginx/ppanel-managed/site.conf"}}})
	if code(t, err) != CodeBackupNotFound {
		t.Fatalf("double revert: %v", err)
	}
}

func TestRevertNginxTestFailedPutsBack(t *testing.T) {
	e := newEnv(t)
	shaA := shaHex([]byte(origA))
	newA := "server { listen 80; }\n"
	_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: newA}}})
	must(t, err)
	applied := tree(e.root)
	e.f.failAfterNT = 2 // the revert's nginx -t fails
	shaNew := shaHex([]byte(newA))
	_, err = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaNew}}})
	if code(t, err) != CodeNginxTestFailed {
		t.Fatalf("got %v", err)
	}
	sameTree(t, applied, tree(e.root))
	if e.f.reloadCount() != 1 {
		t.Fatal("reload after failed revert nginx -t")
	}
	man, _ := e.m.loadManifest(rev1)
	if man.Status != statusApplied {
		t.Fatalf("manifest status after failed revert: %s", man.Status)
	}
}

func TestSystemdReloadPath(t *testing.T) {
	e := newEnv(t)
	e.m.o.SystemdRunDir = t.TempDir()
	e.f.unitActive = true
	shaA := shaHex([]byte(origA))
	out, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server {}\n"}}})
	must(t, err)
	if out.ReloadMethod != ReloadSystemctl {
		t.Fatalf("reloadMethod %s", out.ReloadMethod)
	}
	found := false
	for _, c := range e.f.calls {
		if strings.Join(c, " ") == "systemctl-bin reload --no-ask-password nginx.service" {
			found = true
		}
	}
	if !found {
		t.Fatalf("systemctl reload argv not seen: %v", e.f.calls)
	}
}

func TestBackupRetention(t *testing.T) {
	e := newEnv(t)
	cur := origA
	clock := time.Now()
	e.m.o.Now = func() time.Time { clock = clock.Add(time.Second); return clock }
	var first string
	for i := 0; i < BackupRetention+3; i++ {
		id := fmt.Sprintf("%08d-2222-4333-8444-555555555555", i)
		if i == 0 {
			first = id
		}
		sha := shaHex([]byte(cur))
		next := fmt.Sprintf("server { listen %d; }\n", 1000+i)
		_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: id, Files: []FileChange{{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &sha, Content: next}}})
		must(t, err)
		cur = next
	}
	if n := len(backupEntries(t, e)); n != BackupRetention {
		t.Fatalf("retention: %d backups", n)
	}
	if _, err := e.m.loadManifest(first); err == nil {
		t.Fatal("oldest backup not pruned")
	}
}

func TestNginxNotPresent(t *testing.T) {
	e := newEnv(t)
	e.m.o.NginxBinary = "/nonexistent/nginx"
	before := tree(e.root)
	_, err := e.m.Validate(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/a.conf", Content: "x"}}})
	if code(t, err) != CodeNginxNotPresent {
		t.Fatalf("got %v", err)
	}
	sameTree(t, before, tree(e.root))
}

// ---------------- concurrency ----------------

func TestMutatingJobsSerialized(t *testing.T) {
	e := newEnv(t)
	e.f.testDelay = 150 * time.Millisecond
	shaA := shaHex([]byte(origA))
	var wg sync.WaitGroup
	errs := make([]error, 4)
	start := time.Now()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.m.Validate(ctxJob(fmt.Sprintf("%08d-bbbb-4ccc-8ddd-eeeeeeeeeeee", i)), RevisionParams{RevisionID: rev1, Files: []FileChange{
				{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: fmt.Sprintf("server { listen %d; }\n", 9000+i)}}})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("job %d: %v (a concurrent job must not see another's candidate as drift)", i, err)
		}
	}
	if mx := atomic.LoadInt32(&e.f.maxInTest); mx != 1 {
		t.Fatalf("nginx -t ran concurrently (max %d)", mx)
	}
	if time.Since(start) < 4*e.f.testDelay {
		t.Fatal("jobs were not serialized")
	}
	// lock wait honours ctx
	unlock, _ := lock(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := e.m.Validate(ctx, RevisionParams{RevisionID: rev1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/a.conf", Content: "x"}}})
	unlock()
	if code(t, err) != jobs.HandlerTimeout {
		t.Fatalf("lock timeout: %v", err)
	}
}

// ---------------- read_files ----------------

func TestReadFiles(t *testing.T) {
	e := newEnv(t)
	big := strings.Repeat("#", MaxFileBytes+10)
	must(t, os.WriteFile(e.root+"/conf.d/big.conf", []byte(big), 0o644))
	out, err := e.m.Read(context.Background(), ReadParams{Paths: []string{
		"/etc/nginx/sites-enabled/a.conf", "/etc/nginx/conf.d/x.conf", "/etc/nginx/conf.d/missing.conf", "/etc/nginx/conf.d/big.conf",
		"/etc/nginx/sites-available/a.conf"}})
	must(t, err)
	b, _ := json.Marshal(out)
	var got struct {
		Files []map[string]any `json:"files"`
	}
	must(t, json.Unmarshal(b, &got))
	l := got.Files[0]
	if l["path"] != "/etc/nginx/sites-enabled/a.conf" || l["isSymlink"] != true || l["resolvedPath"] != "/etc/nginx/sites-available/a.conf" ||
		l["content"] != origA || l["sha256"] != shaHex([]byte(origA)) || l["exists"] != true || l["sizeBytes"].(float64) != float64(len(origA)) {
		t.Fatalf("symlink entry: %v", l)
	}
	x := got.Files[1]
	if x["isSymlink"] != false || x["resolvedPath"] != "/etc/nginx/conf.d/x.conf" || x["content"] != origX {
		t.Fatalf("regular entry: %v", x)
	}
	m := got.Files[2]
	if m["exists"] != false || m["sha256"] != nil || m["content"] != nil || m["sizeBytes"].(float64) != 0 {
		t.Fatalf("missing entry: %v", m)
	}
	bg := got.Files[3]
	if bg["content"] != nil || bg["truncated"] != true || bg["sha256"] != shaHex([]byte(big)) {
		t.Fatalf("big entry: %v", bg)
	}
	for _, k := range []string{"path", "exists", "sha256", "sizeBytes", "content", "isSymlink", "resolvedPath"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("read_files output missing key %s", k)
		}
	}
	// symlink escaping root is refused
	must(t, os.Symlink(e.out+"/secret", e.root+"/conf.d/leak.conf"))
	if _, err := e.m.Read(context.Background(), ReadParams{Paths: []string{"/etc/nginx/conf.d/leak.conf"}}); code(t, err) != CodePathNotAllowed {
		t.Fatalf("leak: %v", err)
	}
	must(t, os.Symlink(e.out, e.root+"/evil"))
	if _, err := e.m.Read(context.Background(), ReadParams{Paths: []string{"/etc/nginx/evil/secret"}}); code(t, err) != CodePathNotAllowed {
		t.Fatalf("dir escape: %v", err)
	}
}

func TestProbeRefusesNonLoopback(t *testing.T) {
	e := newEnv(t)
	// hostHeader is only a header: the connection always goes to 127.0.0.1
	port := probeServer(t, func(host, _ string) int {
		if host == "example.com" {
			return 204
		}
		return 500
	})
	r := e.m.probe(context.Background(), Postcheck{HostHeader: "example.com", Path: "/", Scheme: "http", Port: port, ExpectStatus: []int{204}})
	if !r.OK || r.Status != 204 {
		t.Fatalf("probe: %+v", r)
	}
	// closed port → error, not ok
	r = e.m.probe(context.Background(), Postcheck{HostHeader: "a", Path: "/", Scheme: "http", Port: 1, ExpectStatus: []int{200}})
	if r.OK || r.Error == "" {
		t.Fatalf("closed port probe: %+v", r)
	}
	// https with SNI = hostHeader, self-signed accepted on loopback
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != "secure.example" || r.Host != "secure.example" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	tp := ts.Listener.Addr().(*net.TCPAddr).Port
	r = e.m.probe(context.Background(), Postcheck{HostHeader: "secure.example", Path: "/", Scheme: "https", Port: tp, ExpectStatus: []int{200}})
	if !r.OK {
		t.Fatalf("https probe: %+v", r)
	}
}
