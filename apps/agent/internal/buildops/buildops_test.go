package buildops

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/buildtemplates"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/docker/dockertest"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

const (
	buildID  = "4a1f0d3e-5b6c-4d7e-8f90-0123456789ab"
	pushRepo = "lab-registry:5000/ppanel/websrc"
	token    = "ghs_SuperSecretToken123456"
)

var authHeader = "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))

// ---------------- git fixture: bare repo served by a local `git daemon` ----------------

type gitFixture struct {
	base string // git://127.0.0.1:<port>
	host string // 127.0.0.1:<port>
	shas map[string]string
	work string
}

func gitBin(t *testing.T) string {
	t.Helper()
	b, ok := execx.Find("git", "")
	if !ok {
		t.Skip("git binary not installed")
	}
	return b
}

func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@example.test", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// newGitFixture builds repo "app.git" with commit "v1" (files) and serves it.
func newGitFixture(t *testing.T, files map[string]string, symlinks map[string]string) *gitFixture {
	git := gitBin(t)
	root := t.TempDir()
	work, srv := filepath.Join(root, "work"), filepath.Join(root, "srv")
	os.MkdirAll(work, 0o755)
	os.MkdirAll(srv, 0o755)
	for p, c := range files {
		fp := filepath.Join(work, p)
		os.MkdirAll(filepath.Dir(fp), 0o755)
		mode := os.FileMode(0o644)
		if strings.HasSuffix(p, ".sh") {
			mode = 0o755
		}
		if err := os.WriteFile(fp, []byte(c), mode); err != nil {
			t.Fatal(err)
		}
	}
	for p, target := range symlinks {
		os.MkdirAll(filepath.Dir(filepath.Join(work, p)), 0o755)
		if err := os.Symlink(target, filepath.Join(work, p)); err != nil {
			t.Fatal(err)
		}
	}
	run(t, work, git, "init", "-q", "-b", "main")
	run(t, work, git, "add", "-A")
	run(t, work, git, "commit", "-q", "-m", "v1")
	f := &gitFixture{shas: map[string]string{"v1": run(t, work, git, "rev-parse", "HEAD")}, work: work}
	run(t, root, git, "clone", "-q", "--bare", work, filepath.Join(srv, "app.git"))
	port := freePort(t)
	cmd := exec.Command(git, "daemon", "--export-all", "--base-path="+srv, "--reuseaddr", "--informative-errors",
		"--listen=127.0.0.1", "--port="+strconv.Itoa(port), srv)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+root)
	if err := cmd.Start(); err != nil {
		t.Skipf("git daemon unavailable: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	f.host = "127.0.0.1:" + strconv.Itoa(port)
	f.base = "git://" + f.host
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", f.host); err == nil {
			c.Close()
			return f
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Skip("git daemon did not start")
	return nil
}

// recorder wraps execx.System and records every Cmd (argv + env).
type recorder struct {
	mu   sync.Mutex
	cmds []execx.Cmd
	next execx.CmdRunner
}

func (r *recorder) RunCmd(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	r.mu.Lock()
	r.cmds = append(r.cmds, c)
	r.mu.Unlock()
	return r.next.RunCmd(ctx, c)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	fe      *dockertest.Engine
	m       *Manager
	rec     *recorder
	logs    *syncBuf
	workDir string
	fetches int
	secrets *transport.JobSecrets
}

func newHarness(t *testing.T, hosts ...string) *harness {
	h := &harness{fe: dockertest.New(t), rec: &recorder{next: execx.System{}}, logs: &syncBuf{}, workDir: filepath.Join(t.TempDir(), "builds")}
	h.secrets = &transport.JobSecrets{Env: map[string]string{}, GitAuth: &transport.GitAuth{Header: authHeader},
		RegistryAuth: &transport.RegistryAuth{Username: "ci", Password: "reg-PASSWORD-xyz", ServerAddress: "lab-registry:5000"}}
	h.m = New(Options{Engine: docker.NewBuildEngine(h.fe.Socket), Exec: h.rec, GitBinary: gitBin(t), WorkDir: h.workDir,
		AllowedHosts: hosts, Log: slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Secrets: func(context.Context) (*transport.JobSecrets, error) {
			h.fetches++
			if h.fetches > 1 {
				return nil, &transport.APIError{HTTPStatus: 409, Code: "SECRETS_ALREADY_FETCHED"}
			}
			return h.secrets, nil
		}})
	return h
}

func params(t *testing.T, url, sha string, extra map[string]any) BuildParams {
	t.Helper()
	raw := map[string]any{"buildId": buildID, "app": "websrc", "source": map[string]any{"url": url, "commitSha": sha},
		"dockerfile": "Dockerfile", "pushRepo": pushRepo}
	for k, v := range extra {
		if v == nil {
			delete(raw, k)
		} else {
			raw[k] = v
		}
	}
	b, _ := json.Marshal(raw)
	p, err := DecodeBuild(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

func code(t *testing.T, err error) string {
	t.Helper()
	var je *jobs.Error
	if !errors.As(err, &je) {
		t.Fatalf("want *jobs.Error, got %T %v", err, err)
	}
	return je.Code
}

func tarEntries(t *testing.T, b []byte) map[string]*tar.Header {
	t.Helper()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = h
	}
}

func tarFile(t *testing.T, b []byte, name string) string {
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("%s not in tar", name)
		}
		if h.Name == name {
			c, _ := io.ReadAll(tr)
			return string(c)
		}
	}
}

var appFiles = map[string]string{
	"Dockerfile":         "FROM busybox:1.37\nCOPY . /srv\n",
	"index.html":         "v1\n",
	"run.sh":             "#!/bin/sh\necho hi\n",
	"secret.txt":         "do-not-ship\n",
	"node_modules/x.js":  "big\n",
	"docs/keep.md":       "keep\n",
	".dockerignore":      "# comment\nsecret.txt\nnode_modules\n*.log\n!important.log\n",
	"important.log":      "kept by negation\n",
	"debug.log":          "ignored\n",
	"sub/Dockerfile.alt": "FROM busybox:1.37\n",
}

// ---------------- decode ----------------

func TestDecodeBuildStrict(t *testing.T) {
	good := `{"buildId":"` + buildID + `","app":"websrc","source":{"url":"https://github.com/acme/web","commitSha":"` + strings.Repeat("a", 40) + `"},"template":"nextjs","pushRepo":"ghcr.io/acme/web"}`
	p, err := DecodeBuild(json.RawMessage(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != "default" || p.Limits != (Limits{MemoryMb: 2048, Cpus: 2, TimeoutSec: 900}) || p.Source.Subdir != "" || p.Source.Auth || p.Tag() != "build-4a1f0d3e5b6c" {
		t.Fatalf("defaults: %+v tag=%s", p, p.Tag())
	}
	bad := map[string]string{
		"unknown field":      strings.Replace(good, `"app":`, `"evil":1,"app":`, 1),
		"null":               strings.Replace(good, `"template":"nextjs"`, `"template":"nextjs","target":null`, 1),
		"both":               strings.Replace(good, `"template":"nextjs"`, `"template":"nextjs","dockerfile":"Dockerfile"`, 1),
		"neither":            strings.Replace(good, `"template":"nextjs",`, ``, 1),
		"bad template":       strings.Replace(good, `"nextjs"`, `"rails"`, 1),
		"subdir traversal":   strings.Replace(good, `"commitSha"`, `"subdir":"../etc","commitSha"`, 1),
		"subdir absolute":    strings.Replace(good, `"commitSha"`, `"subdir":"/etc","commitSha"`, 1),
		"subdir .git":        strings.Replace(good, `"commitSha"`, `"subdir":"a/.git","commitSha"`, 1),
		"dockerfile escape":  strings.Replace(good, `"template":"nextjs"`, `"dockerfile":"../Dockerfile"`, 1),
		"dockerfile in .git": strings.Replace(good, `"template":"nextjs"`, `"dockerfile":".git/config"`, 1),
		"creds in url":       strings.Replace(good, `https://github.com`, `https://u:p@github.com`, 1),
		"ssh url":            strings.Replace(good, `https://github.com/acme/web`, `ssh://github.com/acme/web`, 1),
		"file url":           strings.Replace(good, `https://github.com/acme/web`, `file:///etc/passwd`, 1),
		"short sha":          strings.Replace(good, strings.Repeat("a", 40), "abc123", 1),
		"repo with tag":      strings.Replace(good, `"ghcr.io/acme/web"`, `"ghcr.io/acme/web:latest"`, 1),
		"repo no path":       strings.Replace(good, `"ghcr.io/acme/web"`, `"ghcr.io"`, 1),
		"network host":       strings.Replace(good, `"pushRepo"`, `"network":"host","pushRepo"`, 1),
		"timeout too big":    strings.Replace(good, `"pushRepo"`, `"limits":{"timeoutSec":7200},"pushRepo"`, 1),
		"limits unknown":     strings.Replace(good, `"pushRepo"`, `"limits":{"disk":1},"pushRepo"`, 1),
		"buildarg key":       strings.Replace(good, `"pushRepo"`, `"buildArgs":{"lower":"x"},"pushRepo"`, 1),
		"not uuid":           strings.Replace(good, buildID, "build-1", 1),
	}
	for name, raw := range bad {
		if _, err := DecodeBuild(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if code(t, err) != jobs.RejectedInvalidParams {
			t.Errorf("%s: code %s", name, code(t, err))
		}
	}
	if _, err := DecodeInspect(json.RawMessage(`{"source":{"url":"https://h/x","commitSha":"` + strings.Repeat("b", 40) + `"},"x":1}`)); err == nil {
		t.Fatal("inspect accepted unknown field")
	}
}

// ---------------- build ----------------

func TestBuildDockerfileSuccess(t *testing.T) {
	g := newGitFixture(t, appFiles, map[string]string{"link-inside": "docs/keep.md"})
	h := newHarness(t, g.host)
	p := params(t, g.base+"/app.git", g.shas["v1"], map[string]any{
		"buildArgs": map[string]string{"VERSION": "v1"}, "network": "none", "target": "runtime",
		"limits": map[string]any{"memoryMb": 1024, "cpus": 1.5, "timeoutSec": 120}})
	out, err := h.m.Build(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if out.Image != pushRepo+"@sha256:"+strings.Repeat("d", 64) || out.Tag != "build-4a1f0d3e5b6c" || out.CommitSha != g.shas["v1"] || out.Template != "" {
		t.Fatalf("output: %+v", out)
	}
	if len(out.LogTail) == 0 || len(out.Log) < len(out.LogTail) {
		t.Fatalf("log: %v", out.Log)
	}
	for _, l := range out.Log {
		if strings.Contains(l, "\x1b") {
			t.Fatalf("ANSI not stripped: %q", l)
		}
	}
	// exact output field names
	b, _ := json.Marshal(out)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"image", "tag", "commitSha", "durationMs", "logTail", "log"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("output missing %s: %s", k, b)
		}
	}
	if _, ok := m["template"]; ok {
		t.Fatal("template must be omitted for dockerfile builds")
	}
	q := h.fe.LastBuildQuery
	want := map[string]string{"t": pushRepo + ":build-4a1f0d3e5b6c", "dockerfile": "Dockerfile", "rm": "1", "forcerm": "1", "pull": "1",
		"networkmode": "none", "memory": strconv.Itoa(1024 << 20), "memswap": strconv.Itoa(1024 << 20), "cpuperiod": "100000",
		"cpuquota": "150000", "target": "runtime", "version": "1", "buildargs": `{"VERSION":"v1"}`}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("query %s=%q want %q", k, q.Get(k), v)
		}
	}
	var labels map[string]string
	json.Unmarshal([]byte(q.Get("labels")), &labels)
	if labels["ppanel.build"] != buildID || labels["ppanel.app"] != "websrc" || labels["ppanel.commit"] != g.shas["v1"] {
		t.Fatalf("labels %v", labels)
	}
	ents := tarEntries(t, h.fe.LastBuildTar)
	for _, n := range []string{"Dockerfile", "index.html", "run.sh", "docs/keep.md", "important.log", ".dockerignore", "link-inside", "sub/Dockerfile.alt"} {
		if ents[n] == nil {
			t.Errorf("tar missing %s", n)
		}
	}
	for n, hdr := range ents {
		if strings.HasPrefix(n, ".git/") || n == ".git" || strings.Contains(n, "/.git/") {
			t.Errorf("tar contains %s", n)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 || len(hdr.PAXRecords) != 0 {
			t.Errorf("tar header %s: uid=%d gid=%d pax=%v", n, hdr.Uid, hdr.Gid, hdr.PAXRecords)
		}
	}
	for _, n := range []string{"secret.txt", "node_modules/x.js", "node_modules/", "debug.log"} {
		if ents[n] != nil {
			t.Errorf("tar must not contain %s (.dockerignore)", n)
		}
	}
	if ents["run.sh"].Mode != 0o755 || ents["index.html"].Mode != 0o644 || ents["link-inside"].Typeflag != tar.TypeSymlink {
		t.Errorf("modes: run.sh=%o index=%o", ents["run.sh"].Mode, ents["index.html"].Mode)
	}
	// local tag removed, push carried X-Registry-Auth "{}" (no registry auth requested)
	var sawDelete, sawPush bool
	for _, c := range h.fe.MutatingCalls() {
		if c.Method == http.MethodDelete && c.Path == "/images/"+pushRepo+":build-4a1f0d3e5b6c" {
			sawDelete = true
		}
		if strings.HasSuffix(c.Path, "/push") {
			sawPush = true
			if c.Query != "tag=build-4a1f0d3e5b6c" || c.Header.Get("X-Registry-Auth") != base64.URLEncoding.EncodeToString([]byte("{}")) {
				t.Errorf("push call %+v", c)
			}
		}
	}
	if !sawDelete || !sawPush || len(h.fe.Images) != 0 {
		t.Fatalf("delete=%v push=%v images=%v", sawDelete, sawPush, h.fe.Images)
	}
	if h.fetches != 0 {
		t.Fatal("no secrets needed, none must be fetched")
	}
	if ents, _ := os.ReadDir(h.workDir); len(ents) != 0 {
		t.Fatalf("work dir not cleaned: %v", ents)
	}
	// git argv is exactly the protocol's fixed argv
	var argv []string
	for _, c := range h.rec.cmds {
		argv = append(argv, strings.Join(c.Args, " "))
	}
	wantArgv := []string{"init -q", "remote add origin " + g.base + "/app.git",
		"-c protocol.version=2 fetch --depth 1 --no-tags origin " + g.shas["v1"], "checkout -q --detach FETCH_HEAD", "rev-parse HEAD"}
	if strings.Join(argv, "|") != strings.Join(wantArgv, "|") {
		t.Fatalf("git argv:\n%v\nwant\n%v", argv, wantArgv)
	}
	env := strings.Join(h.rec.cmds[2].Env, "\n")
	for _, w := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_ALLOW_PROTOCOL=git", "GIT_CONFIG_KEY_0=core.hooksPath"} {
		if !strings.Contains(env, w) {
			t.Errorf("git env missing %s", w)
		}
	}
	if strings.Contains(env, "http.extraHeader") {
		t.Error("no auth requested: no extraHeader expected")
	}
}

func TestBuildTemplateAndSubdir(t *testing.T) {
	files := map[string]string{"api/package.json": `{"name":"api"}`, "api/src/main.ts": "x", "api/Dockerfile.ppanel": "FROM evil\n", "README.md": "r"}
	g := newGitFixture(t, files, nil)
	h := newHarness(t, g.host)
	p := params(t, g.base+"/app.git", g.shas["v1"], map[string]any{"dockerfile": nil, "template": "nestjs",
		"source": map[string]any{"url": g.base + "/app.git", "commitSha": g.shas["v1"], "subdir": "api"}})
	out, err := h.m.Build(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if out.Template != "nestjs" || h.fe.LastBuildQuery.Get("dockerfile") != "Dockerfile.ppanel" {
		t.Fatalf("template output %+v query %v", out, h.fe.LastBuildQuery)
	}
	tpl, _ := buildtemplates.Get("nestjs")
	if got := tarFile(t, h.fe.LastBuildTar, "Dockerfile.ppanel"); got != string(tpl) {
		t.Fatalf("Dockerfile.ppanel is not the embedded template:\n%s", got)
	}
	ents := tarEntries(t, h.fe.LastBuildTar)
	if ents["package.json"] == nil || ents["src/main.ts"] == nil || ents["README.md"] != nil {
		t.Fatalf("subdir context wrong: %v", ents)
	}
}

func TestBuildFailures(t *testing.T) {
	g := newGitFixture(t, map[string]string{"Dockerfile": "FROM x\n", "big.bin": strings.Repeat("z", 4096), "etc-link/.keep": ""},
		map[string]string{"escape": "/etc", "updir": "../../..", "Dockerfile.link": "/etc/passwd", "inner/bad": "../../outside"})
	url := g.base + "/app.git"
	sha := g.shas["v1"]
	clean := newGitFixture(t, map[string]string{"Dockerfile": "FROM x\n"}, nil)
	curl, csha := clean.base+"/app.git", clean.shas["v1"]

	t.Run("errorDetail→BUILD_FAILED", func(t *testing.T) {
		h := newHarness(t, clean.host)
		h.fe.BuildLines = []string{`{"stream":"Step 1/1 : RUN false\n"}`, `{"errorDetail":{"message":"The command '/bin/sh -c false' returned a non-zero code: 1"},"error":"The command '/bin/sh -c false' returned a non-zero code: 1"}`}
		_, err := h.m.Build(context.Background(), params(t, curl, csha, nil))
		if code(t, err) != CodeBuildFailed {
			t.Fatal(err)
		}
		d := err.(*jobs.Error).Details.(map[string]any)
		if tl := strings.Join(d["logTail"].([]string), "\n"); !strings.Contains(tl, "non-zero code: 1") {
			t.Fatalf("logTail %q", tl)
		}
		for _, c := range h.fe.MutatingCalls() {
			if strings.HasSuffix(c.Path, "/push") {
				t.Fatal("pushed a failed build")
			}
		}
	})
	t.Run("missing digest→PUSH_FAILED", func(t *testing.T) {
		h := newHarness(t, clean.host)
		h.fe.PushLines = []string{`{"status":"The push refers to repository [x]"}`, `{"status":"build-x: pushed"}`}
		_, err := h.m.Build(context.Background(), params(t, curl, csha, nil))
		if code(t, err) != CodePushFailed || !strings.Contains(err.Error(), "aux.Digest") {
			t.Fatal(err)
		}
		if len(h.fe.Images) != 0 {
			t.Fatal("local tag not removed after failed push")
		}
	})
	t.Run("no aux, digest status line (Docker 29 containerd store)", func(t *testing.T) {
		h := newHarness(t, clean.host)
		h.fe.PushLines = []string{`{"status":"The push refers to repository [x]"}`, `{"status":"Pushed","progressDetail":{},"id":"fd68b2a81aaf"}`,
			`{"status":"build-ffffffffffff: digest: sha256:` + strings.Repeat("9", 64) + ` size: 1"}`, // another tag: ignored
			`{"status":"build-4a1f0d3e5b6c: digest: sha256:` + strings.Repeat("e", 64) + ` size: 743"}`}
		out, err := h.m.Build(context.Background(), params(t, curl, csha, nil))
		if err != nil || out.Image != pushRepo+"@sha256:"+strings.Repeat("e", 64) {
			t.Fatalf("%v %+v", err, out)
		}
	})
	t.Run("push errorDetail→PUSH_FAILED", func(t *testing.T) {
		h := newHarness(t, clean.host)
		h.fe.PushLines = []string{`{"errorDetail":{"message":"denied: requested access to the resource is denied"},"error":"denied"}`}
		_, err := h.m.Build(context.Background(), params(t, curl, csha, nil))
		if code(t, err) != CodePushFailed || !strings.Contains(err.Error(), "denied") {
			t.Fatal(err)
		}
	})
	t.Run("timeout→cancel+BUILD_TIMEOUT", func(t *testing.T) {
		h := newHarness(t, clean.host)
		h.fe.BuildHang = true
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		start := time.Now()
		_, err := h.m.Build(ctx, params(t, curl, csha, map[string]any{"limits": map[string]any{"timeoutSec": 60}}))
		if code(t, err) != CodeBuildTimeout || time.Since(start) > 15*time.Second {
			t.Fatalf("%v after %s", err, time.Since(start))
		}
		deadline := time.Now().Add(3 * time.Second)
		for !h.fe.BuildCancelled && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if !h.fe.BuildCancelled || h.fe.CancelCalls != 1 {
			t.Fatalf("build request not cancelled: cancelled=%v cancelCalls=%d", h.fe.BuildCancelled, h.fe.CancelCalls)
		}
	})
	cases := []struct {
		name  string
		extra map[string]any
		code  string
	}{
		{"dockerfile missing", map[string]any{"dockerfile": "nope/Dockerfile"}, CodeDockerfileNotFound},
		{"dockerfile symlink outside", map[string]any{"dockerfile": "Dockerfile.link"}, CodeDockerfileNotFound},
		{"dockerfile is a dir", map[string]any{"dockerfile": "etc-link"}, CodeDockerfileNotFound},
		{"subdir symlink escape", map[string]any{"source": map[string]any{"url": url, "commitSha": sha, "subdir": "escape"}}, CodeSourceFetchFailed},
		{"subdir updir escape", map[string]any{"source": map[string]any{"url": url, "commitSha": sha, "subdir": "updir"}}, CodeSourceFetchFailed},
		{"subdir missing", map[string]any{"source": map[string]any{"url": url, "commitSha": sha, "subdir": "nope"}}, CodeSourceFetchFailed},
		{"unknown commit", map[string]any{"source": map[string]any{"url": url, "commitSha": strings.Repeat("e", 40)}}, CodeSourceFetchFailed},
		{"unknown repo", map[string]any{"source": map[string]any{"url": g.base + "/nope.git", "commitSha": sha}}, CodeSourceFetchFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, g.host)
			_, err := h.m.Build(context.Background(), params(t, url, sha, c.extra))
			if code(t, err) != c.code {
				t.Fatalf("got %v want %s", err, c.code)
			}
			for _, call := range h.fe.MutatingCalls() {
				if call.Path == "/build" {
					t.Fatal("/build called despite a source/context error")
				}
			}
			if ents, _ := os.ReadDir(h.workDir); len(ents) != 0 {
				t.Fatalf("work dir not cleaned: %v", ents)
			}
		})
	}
	t.Run("symlink inside context escaping", func(t *testing.T) {
		g2 := newGitFixture(t, map[string]string{"Dockerfile": "FROM x\n"}, map[string]string{"inner/bad": "../../outside"})
		h := newHarness(t, g2.host)
		_, err := h.m.Build(context.Background(), params(t, g2.base+"/app.git", g2.shas["v1"], nil))
		if code(t, err) != CodeSourceFetchFailed || !strings.Contains(err.Error(), "symlink") {
			t.Fatal(err)
		}
	})
	t.Run("context too large", func(t *testing.T) {
		g2 := newGitFixture(t, map[string]string{"Dockerfile": "FROM x\n", "big.bin": strings.Repeat("z", 8192)}, nil)
		h := newHarness(t, g2.host)
		h.m.o.MaxContextBytes = 4096
		_, err := h.m.Build(context.Background(), params(t, g2.base+"/app.git", g2.shas["v1"], nil))
		if code(t, err) != CodeSourceFetchFailed || !strings.Contains(err.Error(), "exceeds") {
			t.Fatal(err)
		}
	})
}

func TestGitHostNotAllowedNoSideEffects(t *testing.T) {
	h := newHarness(t, "github.com")
	p := params(t, "git://127.0.0.1:9/app.git", strings.Repeat("a", 40), nil)
	if code(t, h.m.CheckHost(p.Source)) != CodeGitHostNotAllowed {
		t.Fatal("pure check")
	}
	_, err := h.m.Build(context.Background(), p)
	if code(t, err) != CodeGitHostNotAllowed {
		t.Fatal(err)
	}
	// host match is exact host[:port]
	p2 := params(t, "https://github.com:8443/acme/web", strings.Repeat("a", 40), nil)
	if code(t, h.m.CheckHost(p2.Source)) != CodeGitHostNotAllowed {
		t.Fatal("port must be part of the exact match")
	}
	p3 := params(t, "https://GitHub.com/acme/web", strings.Repeat("a", 40), nil)
	if h.m.CheckHost(p3.Source) != nil {
		t.Fatal("host match is case-insensitive")
	}
	if len(h.rec.cmds) != 0 || len(h.fe.CallsSnapshot()) != 0 {
		t.Fatalf("side effects: git=%d docker=%d", len(h.rec.cmds), len(h.fe.CallsSnapshot()))
	}
}

func TestAuthHeaderNeverInArgvLogsOrResults(t *testing.T) {
	g := newGitFixture(t, map[string]string{"Dockerfile": "FROM x\n"}, nil)
	h := newHarness(t, g.host)
	p := params(t, g.base+"/app.git", g.shas["v1"], map[string]any{"registryAuth": true,
		"source": map[string]any{"url": g.base + "/app.git", "commitSha": g.shas["v1"], "auth": true}})
	h.fe.BuildLines = []string{`{"stream":"echo ` + token + ` reg-PASSWORD-xyz\n"}`, `{"aux":{"ID":"sha256:` + strings.Repeat("2", 64) + `"}}`}
	out, err := h.m.Build(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if h.fetches != 1 {
		t.Fatalf("secrets fetched %d times", h.fetches)
	}
	b, _ := json.Marshal(out)
	sawHeaderEnv := false
	for _, c := range h.rec.cmds {
		for _, a := range c.Args {
			if strings.Contains(a, token) || strings.Contains(a, "Authorization") {
				t.Fatalf("auth in argv: %v", c.Args)
			}
		}
		for _, e := range c.Env {
			if e == "GIT_CONFIG_VALUE_5="+authHeader {
				sawHeaderEnv = true
			}
		}
	}
	if !sawHeaderEnv {
		t.Fatal("auth header not passed via GIT_CONFIG_* env")
	}
	enc := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	for name, s := range map[string]string{"result": string(b), "logs": h.logs.String()} {
		for _, secret := range []string{token, enc, "reg-PASSWORD-xyz"} {
			if strings.Contains(s, secret) {
				t.Fatalf("%s leaks %q: %s", name, secret, s)
			}
		}
	}
	if !strings.Contains(string(b), "[REDACTED]") {
		t.Fatalf("secret echoed in build output not redacted: %s", b)
	}
	var auth string
	for _, c := range h.fe.MutatingCalls() {
		if strings.HasSuffix(c.Path, "/push") {
			auth = c.Header.Get("X-Registry-Auth")
		}
	}
	dec, _ := base64.URLEncoding.DecodeString(auth)
	if !strings.Contains(string(dec), `"password":"reg-PASSWORD-xyz"`) {
		t.Fatalf("push X-Registry-Auth %q", dec)
	}

	// git stderr carrying the token is redacted in error messages
	fake := &fakeRunner{stderr: "fatal: unable to access: header " + authHeader + " token " + token}
	h2 := newHarness(t, g.host)
	h2.m.o.Exec = fake
	_, err = h2.m.Build(context.Background(), p)
	if code(t, err) != CodeSourceFetchFailed || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), enc) {
		t.Fatalf("stderr not redacted: %v", err)
	}

	// auth requested but no header delivered → SECRETS_UNAVAILABLE, nothing fetched
	h3 := newHarness(t, g.host)
	h3.secrets.GitAuth = nil
	_, err = h3.m.Build(context.Background(), p)
	if code(t, err) != "SECRETS_UNAVAILABLE" || len(h3.rec.cmds) != 0 {
		t.Fatalf("%v cmds=%d", err, len(h3.rec.cmds))
	}
}

type fakeRunner struct{ stderr string }

func (f *fakeRunner) RunCmd(_ context.Context, c execx.Cmd) (execx.Result, error) {
	if c.Args[0] == "-c" {
		return execx.Result{ExitCode: 128, Stderr: []byte(f.stderr)}, nil
	}
	return execx.Result{}, nil
}

func TestNoBuildEngineRefused(t *testing.T) {
	fe := dockertest.New(t)
	m := New(Options{Engine: docker.NewEngine(fe.Socket), WorkDir: t.TempDir(), AllowedHosts: []string{"h"}, GitBinary: "/usr/bin/git"})
	_, err := m.Build(context.Background(), params(t, "https://h/x", strings.Repeat("a", 40), nil))
	if code(t, err) != CodeNotABuildNode {
		t.Fatal(err)
	}
}

// ---------------- source.inspect ----------------

func TestSourceInspect(t *testing.T) {
	files := map[string]string{
		"package.json": `{"name":"web","dependencies":{"next":"15.0.0"}}`, "next.config.mjs": "export default {output:'standalone'}",
		"composer.json": strings.Repeat("x", maxInspectLen+1), "src/index.js": "not returned", "README.md": "no",
	}
	g := newGitFixture(t, files, map[string]string{"Dockerfile": "/etc/passwd"})
	h := newHarness(t, g.host)
	out, err := h.m.Inspect(jobs.WithJobID(context.Background(), "job-123"), InspectParams{Source: GitSource{URL: g.base + "/app.git", CommitSha: g.shas["v1"]}})
	if err != nil {
		t.Fatal(err)
	}
	if out.CommitSha != g.shas["v1"] || out.Files["package.json"] != files["package.json"] || out.Files["next.config.mjs"] == "" {
		t.Fatalf("%+v", out)
	}
	if len(out.Files) != 2 || len(out.Truncated) != 1 || out.Truncated[0] != "composer.json" {
		t.Fatalf("files=%v truncated=%v (symlinked Dockerfile must not be followed)", out.Files, out.Truncated)
	}
	if ents, _ := os.ReadDir(h.workDir); len(ents) != 0 {
		t.Fatalf("inspect temp dir not removed: %v", ents)
	}
	if len(h.fe.CallsSnapshot()) != 0 {
		t.Fatal("inspect must not call docker")
	}
	// not allowlisted
	h2 := newHarness(t, "github.com")
	if _, err := h2.m.Inspect(context.Background(), InspectParams{Source: GitSource{URL: g.base + "/app.git", CommitSha: g.shas["v1"]}}); code(t, err) != CodeGitHostNotAllowed {
		t.Fatal(err)
	}
}

// ---------------- helpers ----------------

func TestDockerignoreMatcher(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte("**/*.tmp\nbuild/\n/vendor\n*.md\n!README.md\ndocs/**/private\n[ab].txt\n"), 0o644)
	ig, err := loadIgnore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{"x.tmp": true, "a/b/c.tmp": true, "build": true, "build/out.js": true, "vendor/a/b.php": true,
		"CHANGES.md": true, "README.md": false, "docs/x/y/private": true, "docs/private": true, "a.txt": true, "c.txt": false,
		"src/main.go": false, "sub/README.md": false}
	for p, want := range cases {
		if got := ig.ignored(p); got != want {
			t.Errorf("ignored(%q)=%v want %v", p, got, want)
		}
	}
}

func TestGitEnvAndSecretFragments(t *testing.T) {
	env := gitEnv("/w/home", "https", authHeader)
	joined := strings.Join(env, "\n")
	for _, w := range []string{"HOME=/w/home", "GIT_ALLOW_PROTOCOL=https", "GIT_CONFIG_COUNT=6", "GIT_CONFIG_KEY_5=http.extraHeader",
		"GIT_CONFIG_VALUE_5=" + authHeader, "GIT_CONFIG_KEY_1=http.followRedirects", "GIT_CONFIG_VALUE_1=false"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %s", w)
		}
	}
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if !execx.ExtraEnvKeyRe.MatchString(k) {
			t.Errorf("env key %s would be refused by execx", k)
		}
	}
	fr := strings.Join(secretFragments(authHeader), "|")
	if !strings.Contains(fr, token) || !strings.Contains(fr, "x-access-token:"+token) {
		t.Fatalf("fragments %s", fr)
	}
}
