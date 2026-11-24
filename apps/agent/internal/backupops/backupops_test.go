package backupops

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/docker/dockertest"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

const (
	repoPW   = "repo-SECRET-pw-1a2b3c4d"
	restPW   = "rest-SECRET-pw-5e6f7a8b"
	dbPW     = "db-SECRET-pw-9c0d1e2f"
	helperIm = "lab-registry:5000/ppanel-backup/helper@sha256:" + "ab0000000000000000000000000000000000000000000000000000000000cdef"
	runID    = "11111111-1111-4111-8111-111111111111"
	policyID = "22222222-2222-4222-8222-222222222222"
	repoID   = "33333333-3333-4333-8333-333333333333"
	restID   = "44444444-4444-4444-8444-444444444444"
	snapFull = "483ee5adb0d8a5b9146b6a15eb871db9bb282ddc7cf5492a62cc337b26f67fb1"
)

// fakeRestic is an execx.CmdRunner standing in for the host restic binary.
type fakeRestic struct {
	mu    sync.Mutex
	calls []execx.Cmd
	fn    func(c execx.Cmd) (execx.Result, error)
}

func (f *fakeRestic) RunCmd(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	fn := f.fn
	f.mu.Unlock()
	if fn == nil {
		return execx.Result{}, nil
	}
	return fn(c)
}

func (f *fakeRestic) Calls() []execx.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]execx.Cmd(nil), f.calls...)
}

func subcmd(args []string) string {
	for i, a := range args {
		if a == "-r" && i+2 < len(args) {
			return args[i+2]
		}
	}
	return ""
}

func summary(id string) []byte {
	return []byte(`{"message_type":"status","percent_done":0.5}` + "\n" +
		`{"message_type":"summary","files_new":2,"files_changed":1,"files_unmodified":0,"data_added":4944,"total_files_processed":3,"total_bytes_processed":12,"total_duration":0.7,"snapshot_id":"` + id + `"}` + "\n")
}

func secrets() (*transport.JobSecrets, error) {
	return &transport.JobSecrets{Env: map[string]string{"DB_PASSWORD": dbPW},
		Restic: &transport.ResticSecrets{RepoPassword: repoPW, RestUser: "node-b", RestPassword: restPW}}, nil
}

func newMgr(t *testing.T, fr *fakeRestic, e *docker.Engine) (*Manager, string) {
	t.Helper()
	state := t.TempDir()
	m := New(Options{Engine: e, Exec: fr, ResticBin: "/usr/local/bin/restic", ResticVersion: "0.19.1", HelperImage: helperIm,
		StateDir: state, WorkDir: filepath.Join(state, "backup"), Hostname: "lab-node-b",
		Secrets:             func(context.Context) (*transport.JobSecrets, error) { return secrets() },
		Resolve:             func(context.Context, string) ([]string, error) { return []string{"172.20.0.9"}, nil },
		ScratchReadyTimeout: 2 * time.Second, ReadyInterval: 10 * time.Millisecond})
	return m, state
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func repo() map[string]any {
	return map[string]any{"url": "http://lab-backup:8000/node-b/", "repositoryId": repoID}
}

func backupRaw(targets ...map[string]any) map[string]any {
	ts := make([]any, len(targets))
	for i, t := range targets {
		ts[i] = t
	}
	return map[string]any{"runId": runID, "policyId": policyID, "repo": repo(), "targets": ts}
}

func asJobErr(t *testing.T, err error) *jobs.Error {
	t.Helper()
	var je *jobs.Error
	if !errors.As(err, &je) {
		t.Fatalf("want *jobs.Error, got %T %v", err, err)
	}
	return je
}

func noSecrets(t *testing.T, what string, b []byte) {
	t.Helper()
	for _, s := range []string{repoPW, restPW, dbPW} {
		if strings.Contains(string(b), s) {
			t.Fatalf("%s leaks a secret: %s", what, b)
		}
	}
}

// ---------------- decode strictness ----------------

func TestDecodeStrictness(t *testing.T) {
	good := backupRaw(map[string]any{"type": "paths", "paths": []string{"/srv/data"}})
	p, err := DecodeBackup(mustJSON(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Limits.TimeoutSec != 3600 || p.Limits.UploadKiBps != 0 || len(p.Tags) != 0 || len(p.Targets[0].Excludes) != 0 {
		t.Fatalf("defaults: %+v", p)
	}
	mut := func(f func(m map[string]any)) json.RawMessage {
		m := backupRaw(map[string]any{"type": "paths", "paths": []string{"/srv/data"}})
		f(m)
		return mustJSON(m)
	}
	bad := map[string]json.RawMessage{
		"unknown top": mut(func(m map[string]any) { m["extra"] = 1 }),
		"unknown target": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "paths", "paths": []string{"/a"}, "x": 1}}
		}),
		"unknown repo": mut(func(m map[string]any) {
			m["repo"] = map[string]any{"url": "http://b:8000/x/", "repositoryId": repoID, "pw": "x"}
		}),
		"repo creds": mut(func(m map[string]any) {
			m["repo"] = map[string]any{"url": "http://u:p@b:8000/x/", "repositoryId": repoID}
		}),
		"unknown limits": mut(func(m map[string]any) { m["limits"] = map[string]any{"timeoutSec": 60, "foo": 1} }),
		"timeout low":    mut(func(m map[string]any) { m["limits"] = map[string]any{"timeoutSec": 10} }),
		"null tags":      mut(func(m map[string]any) { m["tags"] = nil }),
		"bad tag":        mut(func(m map[string]any) { m["tags"] = []string{"UPPER"} }),
		"relative path": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "paths", "paths": []string{"srv"}}}
		}),
		"dotdot": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "paths", "paths": []string{"/srv/../etc"}}}
		}),
		"proc": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "paths", "paths": []string{"/proc/1"}}}
		}),
		"exclude opt": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "paths", "paths": []string{"/a"}, "excludes": []string{"--x"}}}
		}),
		"bad type":        mut(func(m map[string]any) { m["targets"] = []any{map[string]any{"type": "shell", "cmd": "rm"}} }),
		"no targets":      mut(func(m map[string]any) { m["targets"] = []any{} }),
		"tag helperImage": mut(func(m map[string]any) { m["helperImage"] = "lab-registry:5000/helper:latest" }),
		"runId":           mut(func(m map[string]any) { m["runId"] = "x" }),
		"db dash":         mut(func(m map[string]any) { m["targets"] = []any{dbTarget("-oops")} }),
		"db unknown":      mut(func(m map[string]any) { t := dbTarget("app"); t["extra"] = true; m["targets"] = []any{t} }),
		"volume bad": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "volume", "app": "shop", "volume": "Data!"}}
		}),
		"trailing": json.RawMessage(string(mustJSON(good)) + "{}"),
		"array":    json.RawMessage(`[]`),
		"volume extra mode": mut(func(m map[string]any) {
			m["targets"] = []any{map[string]any{"type": "volume", "app": "shop", "volume": "data", "mode": "staging"}}
		}),
	}
	for name, raw := range bad {
		if _, err := DecodeBackup(raw); err == nil {
			t.Errorf("%s: accepted", name)
		} else if je := asJobErr(t, err); je.Code != jobs.RejectedInvalidParams {
			t.Errorf("%s: code %s", name, je.Code)
		}
	}
	// restore
	rbase := func(target map[string]any) map[string]any {
		return map[string]any{"restoreId": restID, "repo": repo(), "snapshotId": snapFull[:8], "target": target}
	}
	r, err := DecodeRestore(mustJSON(rbase(map[string]any{"type": "paths", "mode": "staging"})))
	if err != nil || !r.Verify || r.DryRun || r.TimeoutSec != 3600 {
		t.Fatalf("restore defaults: %+v %v", r, err)
	}
	for name, tgt := range map[string]map[string]any{
		"in_place no include": {"type": "paths", "mode": "in_place"},
		"paths scratch":       {"type": "paths", "mode": "scratch"},
		"db staging":          {"type": "postgres", "app": "shop", "service": "db", "database": "shop", "user": "shop", "passwordSecretKey": "DB_PASSWORD", "mode": "staging"},
		"db port (not in restore schema)": {"type": "postgres", "app": "shop", "service": "db", "database": "shop", "user": "shop",
			"passwordSecretKey": "DB_PASSWORD", "mode": "scratch", "port": 5432},
		"volume scratch": {"type": "volume", "app": "shop", "volume": "data", "mode": "scratch"},
	} {
		if _, err := DecodeRestore(mustJSON(rbase(tgt))); err == nil {
			t.Errorf("restore %s: accepted", name)
		}
	}
	if _, err := DecodeRestore(mustJSON(map[string]any{"restoreId": restID, "repo": repo(), "snapshotId": "zz", "target": map[string]any{"type": "paths", "mode": "staging"}})); err == nil {
		t.Error("bad snapshot id accepted")
	}
	// verify manifest is strict
	vr := map[string]any{"repo": repo(), "snapshotId": snapFull, "manifest": map[string]any{"target": 0, "type": "paths", "snapshotId": snapFull, "fileCount": 0, "truncated": false, "bogus": 1}}
	if _, err := DecodeVerify(mustJSON(vr)); err == nil {
		t.Error("verify manifest with unknown field accepted")
	}
	vr["manifest"] = []any{map[string]any{"target": 0, "type": "paths", "snapshotId": snapFull, "fileCount": 1, "truncated": false,
		"files": []any{map[string]any{"path": "/srv/a", "size": 1, "sha256": strings.Repeat("a", 64)}}}}
	v, err := DecodeVerify(mustJSON(vr))
	if err != nil || len(v.Manifest) != 1 || v.ReadDataSubsetPct != 5 {
		t.Fatalf("verify decode: %+v %v", v, err)
	}
	if _, err := DecodeSnapshots(mustJSON(map[string]any{"repo": repo(), "tag": "run=" + runID})); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshots(mustJSON(map[string]any{"repo": repo(), "all": true})); err == nil {
		t.Error("snapshots unknown field accepted")
	}
}

func dbTarget(db string) map[string]any {
	return map[string]any{"type": "postgres", "app": "shop", "service": "db", "database": db, "user": "shop", "passwordSecretKey": "DB_PASSWORD"}
}

// ---------------- argv / env / summary ----------------

func TestPathsBackupArgvEnvAndSummary(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello\n"), 0o644)
	fr := &fakeRestic{fn: func(c execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: summary(snapFull)}, nil }}
	m, state := newMgr(t, fr, nil)
	raw := backupRaw(map[string]any{"type": "paths", "paths": []string{src}, "excludes": []string{"*.tmp"}})
	raw["tags"] = []string{"env=lab"}
	raw["limits"] = map[string]any{"timeoutSec": 120, "uploadKiBps": 512}
	p, err := DecodeBackup(mustJSON(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Backup(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	calls := fr.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls: %d", len(calls))
	}
	// bounded repository preflight first (no lock, no secret in argv)
	if pre := calls[0]; !slices.Equal(pre.Args, []string{"--no-lock", "-r", "rest:http://lab-backup:8000/node-b/", "cat", "config"}) || !pre.Interrupt {
		t.Fatalf("preflight: %+v", pre.Args)
	}
	c := calls[1]
	want := []string{"-r", "rest:http://lab-backup:8000/node-b/", "backup", "--json", "--quiet", "--tag", "ppanel", "--tag", "run=" + runID,
		"--tag", "policy=" + policyID, "--tag", "target=0", "--tag", "env=lab", "--exclude", "*.tmp", "--exclude", state,
		"--limit-upload", "512", "--", src}
	if !slices.Equal(c.Args, want) {
		t.Fatalf("argv:\n got %q\nwant %q", c.Args, want)
	}
	if c.Binary != "/usr/local/bin/restic" || !c.Long || !c.Interrupt {
		t.Fatalf("cmd: %+v", c)
	}
	noSecrets(t, "argv", []byte(strings.Join(c.Args, " ")))
	env := strings.Join(c.Env, "\n")
	for _, kv := range []string{"RESTIC_PASSWORD=" + repoPW, "RESTIC_REST_USERNAME=node-b", "RESTIC_REST_PASSWORD=" + restPW, "RESTIC_CACHE_DIR="} {
		if !strings.Contains(env, kv) {
			t.Fatalf("env misses %q: %v", kv, c.Env)
		}
	}
	for _, kv := range c.Env {
		k, _, _ := strings.Cut(kv, "=")
		if !execx.ExtraEnvKeyRe.MatchString(k) {
			t.Fatalf("env key %s would be refused by execx", k)
		}
	}
	b, _ := json.Marshal(out)
	var o BackupOutput
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	s := o.Snapshots[0]
	if s.SnapshotID != snapFull || s.ShortID != "483ee5ad" || s.SizeBytes != 12 || s.FilesNew != 2 || s.FilesChanged != 1 || o.ResticVersion != "0.19.1" {
		t.Fatalf("snapshot: %+v", o)
	}
	mf := o.Manifest[0]
	sum := sha256.Sum256([]byte("hello\n"))
	if mf.Type != "paths" || mf.FileCount != 1 || mf.Files[0].Sha256 != hex.EncodeToString(sum[:]) || mf.Files[0].Size != 6 || mf.Truncated {
		t.Fatalf("manifest: %+v", mf)
	}
	noSecrets(t, "output", b)
}

func TestParseSummaryAndErrors(t *testing.T) {
	s, err := ParseSummary(summary(snapFull))
	if err != nil || s.SnapshotID != snapFull || s.TotalBytesProcessed != 12 {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := ParseSummary([]byte(`{"message_type":"exit_error","code":1,"message":"Fatal: all source directories/files do not exist"}`)); err == nil ||
		!strings.Contains(err.Error(), "do not exist") {
		t.Fatalf("exit error: %v", err)
	}
	cases := map[string]struct {
		code int
		text string
		want string
	}{
		"locked":    {11, "Fatal: unable to create lock", CodeRepoLocked},
		"lock text": {1, "repository is already locked by PID 7", CodeRepoLocked},
		"no repo":   {10, "repository does not exist", CodeRepoUnreachable},
		"wrong pw":  {12, "wrong password", CodeRepoUnreachable},
		"conn":      {1, "dial tcp 172.20.0.9:8000: connect: connection refused", CodeRepoUnreachable},
		"auth":      {1, "unexpected HTTP response (401): 401 Unauthorized", CodeRepoUnreachable},
		"snapshot":  {1, `Fatal: failed to find snapshot: no matching ID found for prefix "deadbeef"`, CodeSnapshotNotFound},
		"other":     {1, "something else", CodeBackupFailed},
	}
	for name, c := range cases {
		if got := ClassifyFailure(c.code, c.text, CodeBackupFailed); got != c.want {
			t.Errorf("%s: %s", name, got)
		}
	}
	if v, ok := ParseResticVersion("restic 0.19.1 compiled with go1.26.4 on linux/arm64"); v != "0.19.1" || !ok {
		t.Fatal(v)
	}
	if _, ok := ParseResticVersion("restic 0.16.4 compiled with go1.21"); ok {
		t.Fatal("0.16 accepted")
	}
	snaps, err := ParseSnapshots([]byte(`[{"time":"2026-11-23T08:42:29Z","paths":["/srv"],"hostname":"h","tags":["ppanel"],"id":"` + snapFull + `","short_id":"483ee5ad","summary":{"total_bytes_processed":12}}]`))
	if err != nil || len(snaps) != 1 || *snaps[0].SizeBytes != 12 || snaps[0].ShortID != "483ee5ad" {
		t.Fatalf("%+v %v", snaps, err)
	}
}

// ---------------- partial ----------------

func TestBackupPartialWhenSecondTargetFails(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(a, "x"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(b, "y"), []byte("y"), 0o644)
	n := 0
	fr := &fakeRestic{fn: func(c execx.Cmd) (execx.Result, error) {
		if subcmd(c.Args) != "backup" {
			return execx.Result{}, nil // repository preflight
		}
		n++
		if n == 2 {
			return execx.Result{ExitCode: 1, Stdout: []byte(`{"message_type":"exit_error","code":1,"message":"Fatal: unable to save snapshot: password ` + repoPW + `"}`)}, nil
		}
		return execx.Result{Stdout: summary(snapFull)}, nil
	}}
	m, _ := newMgr(t, fr, nil)
	p, err := DecodeBackup(mustJSON(backupRaw(map[string]any{"type": "paths", "paths": []string{a}}, map[string]any{"type": "paths", "paths": []string{b}})))
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Backup(context.Background(), p)
	if out != nil || err == nil {
		t.Fatalf("partial run must not succeed: %v", out)
	}
	je := asJobErr(t, err)
	if je.Code != CodeBackupPartial {
		t.Fatalf("code %s", je.Code)
	}
	d, _ := json.Marshal(je.Details)
	noSecrets(t, "partial details", d)
	var det struct {
		Snapshots        []SnapshotResult `json:"snapshots"`
		Failures         []TargetFailure  `json:"failures"`
		CompletedTargets []int            `json:"completedTargets"`
	}
	json.Unmarshal(d, &det)
	if len(det.Snapshots) != 1 || det.Snapshots[0].Target != 0 || len(det.Failures) != 1 || det.Failures[0].Target != 1 || !slices.Equal(det.CompletedTargets, []int{0}) {
		t.Fatalf("details: %s", d)
	}
	if !strings.Contains(det.Failures[0].Message, "[REDACTED]") {
		t.Fatalf("failure message not redacted: %s", det.Failures[0].Message)
	}
	// all targets failing with a lock → REPO_LOCKED (not success, not partial)
	fr.fn = func(execx.Cmd) (execx.Result, error) {
		return execx.Result{ExitCode: 11, Stdout: []byte(`{"message_type":"exit_error","code":11,"message":"Fatal: unable to create lock"}`)}, nil
	}
	_, err = m.Backup(context.Background(), p)
	if je := asJobErr(t, err); je.Code != CodeRepoLocked {
		t.Fatalf("all locked: %s", je.Code)
	}
}

func TestBackupCancelledIsFailure(t *testing.T) {
	a := t.TempDir()
	fr := &fakeRestic{}
	ctx, cancel := context.WithCancel(context.Background())
	fr.fn = func(c execx.Cmd) (execx.Result, error) {
		cancel() // agent/Center aborted the run while restic was uploading
		return execx.Result{ExitCode: 130}, errors.New("execx: restic cancelled: context canceled")
	}
	m, _ := newMgr(t, fr, nil)
	p, _ := DecodeBackup(mustJSON(backupRaw(map[string]any{"type": "paths", "paths": []string{a}})))
	out, err := m.Backup(ctx, p)
	if out != nil {
		t.Fatal("cancelled run returned output")
	}
	if je := asJobErr(t, err); je.Code != CodeBackupFailed || !strings.Contains(je.Message, "aborted") {
		t.Fatalf("%s %s", je.Code, je.Message)
	}
}

func TestPathsUnderStateDirRefused(t *testing.T) {
	m, state := newMgr(t, &fakeRestic{}, nil)
	p, _ := DecodeBackup(mustJSON(backupRaw(map[string]any{"type": "paths", "paths": []string{state + "/keys"}})))
	if je := asJobErr(t, m.PreflightBackup(p)); je.Code != jobs.RejectedInvalidParams {
		t.Fatal(je.Code)
	}
	m2 := New(Options{StateDir: state})
	if je := asJobErr(t, m2.CheckRestic()); je.Code != CodeResticUnavailable {
		t.Fatal(je.Code)
	}
}

// ---------------- manifest ----------------

func TestManifestHashingAndTruncation(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.MkdirAll(state, 0o700)
	os.WriteFile(filepath.Join(dir, "a"), []byte("A"), 0o644)
	os.WriteFile(filepath.Join(dir, "sub", "b"), []byte("BB"), 0o644)
	os.WriteFile(filepath.Join(state, "key.pem"), []byte("never"), 0o600)
	os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "link"))
	files, tr, err := HashPaths(context.Background(), []string{dir}, state, NewBudget())
	if err != nil || tr || len(files) != 2 {
		t.Fatalf("%v %v %+v", err, tr, files)
	}
	for _, f := range files {
		if strings.Contains(f.Path, "state") || strings.HasSuffix(f.Path, "link") {
			t.Fatalf("hashed %s", f.Path)
		}
	}
	files, tr, _ = HashPaths(context.Background(), []string{dir}, state, &Budget{Left: 1})
	if !tr || len(files) != 1 {
		t.Fatalf("truncation: %v %d", tr, len(files))
	}
	// compare
	exp := []ManifestFile{{Path: "/x/a", Size: 1, Sha256: strings.Repeat("a", 64)}, {Path: "/x/b", Size: 2, Sha256: strings.Repeat("b", 64)},
		{Path: "/x/c", Size: 3, Sha256: strings.Repeat("c", 64)}}
	act := map[string]ManifestFile{"/x/a": exp[0], "/x/b": {Path: "/x/b", Size: 2, Sha256: strings.Repeat("f", 64)}}
	n, mm := CompareFiles(exp, act, func(p string) string { return p }, nil)
	if n != 3 || len(mm) != 2 || mm[0].Reason != "sha256" || mm[1].Reason != "missing" {
		t.Fatalf("%d %+v", n, mm)
	}
	n, mm = CompareTables([]TableCount{{"public.a", 3}, {"public.b", 1}}, []TableCount{{"public.a", 3}, {"public.b", 2}}, []string{"public.a:a_pkey"}, []string{})
	if n != 3 || len(mm) != 2 {
		t.Fatalf("tables: %d %+v", n, mm)
	}
}

// ---------------- helper containers (fake Engine) ----------------

func helperEngine(t *testing.T) (*dockertest.Engine, *docker.Engine) {
	fe := dockertest.New(t)
	return fe, docker.NewEngine(fe.Socket)
}

func TestVolumeBackupHelperHardening(t *testing.T) {
	fe, eng := helperEngine(t)
	fe.AddVolume("ppanel-shop-data", map[string]string{"ppanel.managed": "true", "ppanel.app": "shop"})
	fe.SetVolumeFile("ppanel-shop-data", "f1.txt", []byte("one"))
	fe.SetVolumeFile("ppanel-shop-data", "d/f2.txt", []byte("two"))
	fe.HelperHook = func(e *dockertest.Engine, c *dockertest.Container) bool {
		e.Lock()
		c.Stdout = string(summary(snapFull))
		e.Unlock()
		return false
	}
	m, _ := newMgr(t, &fakeRestic{}, eng)
	p, err := DecodeBackup(mustJSON(backupRaw(map[string]any{"type": "volume", "app": "shop", "volume": "data"})))
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Backup(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	rem := fe.RemovedSnapshot()
	if len(rem) != 1 {
		t.Fatalf("helper not removed: %d", len(rem))
	}
	c := rem[0]
	if !docker.HelperNameRe.MatchString(c.Name) || c.RemovedWithVolumes {
		t.Fatalf("name %s v=%v", c.Name, c.RemovedWithVolumes)
	}
	if c.Labels["ppanel.managed"] != "true" || c.Labels["ppanel.app"] != "shop" || c.Labels["ppanel.backup"] != runID {
		t.Fatalf("labels %v", c.Labels)
	}
	if c.Image != helperIm {
		t.Fatal(c.Image)
	}
	hc := c.CreatedBody["HostConfig"].(map[string]any)
	if len(hc["PortBindings"].(map[string]any)) != 0 || hc["PublishAllPorts"] != false || hc["Privileged"] != false {
		t.Fatalf("ports/privileged: %v", hc)
	}
	if d := hc["CapDrop"].([]any); len(d) != 1 || d[0] != "ALL" {
		t.Fatalf("CapDrop %v", d)
	}
	if a := hc["CapAdd"].([]any); len(a) != 1 || a[0] != "DAC_READ_SEARCH" {
		t.Fatalf("CapAdd %v", a)
	}
	if so := hc["SecurityOpt"].([]any); so[0] != "no-new-privileges:true" {
		t.Fatal(so)
	}
	if hc["ReadonlyRootfs"] != true || hc["Memory"].(float64) <= 0 || hc["PidsLimit"].(float64) <= 0 || hc["NetworkMode"] != "bridge" {
		t.Fatalf("limits/rootfs: %v", hc)
	}
	if eh := hc["ExtraHosts"].([]any); len(eh) != 1 || eh[0] != "lab-backup:172.20.0.9" {
		t.Fatalf("ExtraHosts %v", eh)
	}
	ms := c.Mounts()
	if len(ms) != 1 || ms[0]["Source"] != "ppanel-shop-data" || ms[0]["Target"] != "/backup/data" || ms[0]["ReadOnly"] != true {
		t.Fatalf("mounts %v", ms)
	}
	cmd := c.Cmd()
	if cmd[0] != "--no-cache" || subcmd(cmd) != "backup" || cmd[len(cmd)-1] != "/backup/data" || !slices.Contains(cmd, "--host") {
		t.Fatalf("cmd %q", cmd)
	}
	noSecrets(t, "helper cmd", []byte(strings.Join(cmd, " ")))
	if !slices.Contains(c.Env, "RESTIC_PASSWORD="+repoPW) || !slices.Contains(c.Env, "RESTIC_REST_PASSWORD="+restPW) {
		t.Fatalf("env %v", c.Env)
	}
	if _, has := c.CreatedBody["Entrypoint"]; has {
		t.Fatal("restic helper must use the image entrypoint")
	}
	for _, call := range fe.CallsSnapshot() {
		if strings.Contains(call.Path, "/exec") {
			t.Fatalf("exec endpoint used: %s", call.Path)
		}
	}
	b, _ := json.Marshal(out)
	var o BackupOutput
	json.Unmarshal(b, &o)
	if len(o.Manifest) != 1 || o.Manifest[0].FileCount != 2 || o.Manifest[0].Files[0].Path != "/backup/data/d/f2.txt" {
		t.Fatalf("volume manifest: %s", b)
	}
	noSecrets(t, "output", b)
}

func TestVolumeNotManagedRefused(t *testing.T) {
	fe, eng := helperEngine(t)
	fe.AddVolume("ppanel-shop-data", map[string]string{})
	m, _ := newMgr(t, &fakeRestic{}, eng)
	p, _ := DecodeBackup(mustJSON(backupRaw(map[string]any{"type": "volume", "app": "shop", "volume": "data"})))
	_, err := m.Backup(context.Background(), p)
	if je := asJobErr(t, err); je.Code != "CONTAINER_NOT_MANAGED" {
		t.Fatal(je.Code, je.Message)
	}
	if len(fe.RemovedSnapshot()) != 0 {
		t.Fatal("helper created for an unmanaged volume")
	}
}

func TestHelperImageNotAllowed(t *testing.T) {
	_, eng := helperEngine(t)
	m, _ := newMgr(t, &fakeRestic{}, eng)
	raw := backupRaw(map[string]any{"type": "volume", "app": "shop", "volume": "data"})
	raw["helperImage"] = "lab-registry:5000/evil@sha256:" + strings.Repeat("e", 64)
	p, err := DecodeBackup(mustJSON(raw))
	if err != nil {
		t.Fatal(err)
	}
	if je := asJobErr(t, m.PreflightBackup(p)); je.Code != CodeHelperImageNotAllowed {
		t.Fatal(je.Code)
	}
	if _, err := m.Backup(context.Background(), p); asJobErr(t, err).Code != CodeHelperImageNotAllowed {
		t.Fatal(err)
	}
	m2 := New(Options{ResticBin: "/r", ResticVersion: "0.19.1"})
	delete(raw, "helperImage")
	p, _ = DecodeBackup(mustJSON(raw))
	if je := asJobErr(t, m2.PreflightBackup(p)); je.Code != CodeHelperImageNotAllowed {
		t.Fatal(je.Code)
	}
}

func TestDBBackupDumpArgvAndManifest(t *testing.T) {
	fe, eng := helperEngine(t)
	fe.AddNetwork("ppanel-shop", map[string]string{"ppanel.managed": "true", "ppanel.app": "shop"})
	dump := []byte("CREATE TABLE public.items (id int);\n")
	fe.HelperHook = func(e *dockertest.Engine, c *dockertest.Container) bool {
		e.Lock()
		defer e.Unlock()
		cmd := c.Cmd()
		switch {
		case len(c.Entrypoint()) > 0 && c.Entrypoint()[0] == "psql":
			c.Stdout = "T|public.items|3\nT|public.users|2\nC|public.items:items_pkey|\n"
		case subcmd(cmd) == "backup":
			c.Stdout = string(summary(snapFull))
		case subcmd(cmd) == "dump":
			c.Files = map[string][]byte{"/work/shop.sql": dump}
		}
		return false
	}
	m, _ := newMgr(t, &fakeRestic{}, eng)
	p, _ := DecodeBackup(mustJSON(backupRaw(dbTarget("shop"))))
	out, err := m.Backup(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	rem := fe.RemovedSnapshot()
	if len(rem) != 3 {
		t.Fatalf("helpers: %d", len(rem))
	}
	bk := rem[0]
	cmd := bk.Cmd()
	i := slices.Index(cmd, "--")
	wantTail := []string{"pg_dump", "--no-password", "--format=plain", "--clean", "--if-exists", "--host=db", "--port=5432", "--username=shop", "--dbname=shop"}
	if i < 0 || !slices.Equal(cmd[i+1:], wantTail) || !slices.Contains(cmd, "--stdin-from-command") || cmd[slices.Index(cmd, "--stdin-filename")+1] != "shop.sql" {
		t.Fatalf("dump argv %q", cmd)
	}
	if bk.CreatedBody["HostConfig"].(map[string]any)["NetworkMode"] != "ppanel-shop" || !slices.Contains(bk.Env, "PGPASSWORD="+dbPW) {
		t.Fatalf("db helper net/env: %v", bk.Env)
	}
	noSecrets(t, "dump argv", []byte(strings.Join(cmd, " ")))
	q := rem[2]
	if q.Entrypoint()[0] != "psql" || !slices.Contains(q.Env, "PGOPTIONS=-c default_transaction_read_only=on") {
		t.Fatalf("query helper: %v %v", q.Entrypoint(), q.Env)
	}
	b, _ := json.Marshal(out)
	var o BackupOutput
	json.Unmarshal(b, &o)
	sum := sha256.Sum256(dump)
	mf := o.Manifest[0]
	if mf.Sha256 != hex.EncodeToString(sum[:]) || mf.Bytes != int64(len(dump)) || len(mf.Tables) != 2 || mf.Tables[0].Rows != 3 ||
		!slices.Equal(mf.Constraints, []string{"public.items:items_pkey"}) {
		t.Fatalf("db manifest: %s", b)
	}
	noSecrets(t, "db output", b)
}

// ---------------- restore ----------------

func restoreParams(t *testing.T, target map[string]any, extra map[string]any) RestoreParams {
	raw := map[string]any{"restoreId": restID, "repo": repo(), "snapshotId": snapFull, "target": target}
	for k, v := range extra {
		raw[k] = v
	}
	p, err := DecodeRestore(mustJSON(raw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRestoreStagingPermsAndVerify(t *testing.T) {
	content := []byte("restored-content\n")
	sum := sha256.Sum256(content)
	fr := &fakeRestic{}
	fr.fn = func(c execx.Cmd) (execx.Result, error) {
		if subcmd(c.Args) == "restore" {
			tgt := c.Args[slices.Index(c.Args, "--target")+1]
			os.MkdirAll(filepath.Join(tgt, "srv/app"), 0o755)
			os.WriteFile(filepath.Join(tgt, "srv/app/f.txt"), content, 0o644)
			return execx.Result{Stdout: []byte(`{"message_type":"summary","total_files":1,"files_restored":1,"total_bytes":17,"bytes_restored":17}`)}, nil
		}
		return execx.Result{}, nil
	}
	m, state := newMgr(t, fr, nil)
	man := map[string]any{"target": 0, "type": "paths", "snapshotId": snapFull, "fileCount": 1, "truncated": false,
		"files": []any{map[string]any{"path": "/srv/app/f.txt", "size": len(content), "sha256": hex.EncodeToString(sum[:])}}}
	p := restoreParams(t, map[string]any{"type": "paths", "mode": "staging"}, map[string]any{"manifest": []any{man}})
	out, err := m.Restore(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "restores", restID)
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("staging dir perms: %v %v", st.Mode(), err)
	}
	b, _ := json.Marshal(out)
	var o RestoreOutput
	json.Unmarshal(b, &o)
	if o.StagingPath != dir || o.Verify == nil || !o.Verify.OK || o.Verify.Compared != 1 || o.Verify.Method != "manifest" || o.Restored[0].FilesRestored != 1 {
		t.Fatalf("restore out: %s", b)
	}
	args := fr.Calls()[0].Args
	if !slices.Contains(args, "--verify") || args[slices.Index(args, "--target")+1] != dir {
		t.Fatalf("argv %q", args)
	}
	// a second restore with the same id never overwrites
	if _, err := m.Restore(context.Background(), p); asJobErr(t, err).Code != CodeRestoreTargetExists {
		t.Fatal(err)
	}
}

func TestRestoreVerifyMismatch(t *testing.T) {
	fr := &fakeRestic{fn: func(c execx.Cmd) (execx.Result, error) {
		if subcmd(c.Args) == "restore" {
			tgt := c.Args[slices.Index(c.Args, "--target")+1]
			os.MkdirAll(filepath.Join(tgt, "srv"), 0o755)
			os.WriteFile(filepath.Join(tgt, "srv/f.txt"), []byte("TAMPERED"), 0o644)
		}
		return execx.Result{Stdout: []byte(`{"message_type":"summary","num_errors":0}`)}, nil
	}}
	m, _ := newMgr(t, fr, nil)
	man := []any{map[string]any{"target": 0, "type": "paths", "snapshotId": snapFull, "fileCount": 2, "truncated": false,
		"files": []any{map[string]any{"path": "/srv/f.txt", "size": 8, "sha256": strings.Repeat("0", 64)},
			map[string]any{"path": "/srv/gone.txt", "size": 1, "sha256": strings.Repeat("1", 64)}}}}
	// backup.verify: restic check ok + restore-compare → VERIFY_FAILED with mismatches
	vp, err := DecodeVerify(mustJSON(map[string]any{"repo": repo(), "snapshotId": snapFull[:8], "readDataSubsetPct": 10, "manifest": man}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Verify(context.Background(), vp)
	je := asJobErr(t, err)
	if je.Code != CodeVerifyFailed {
		t.Fatal(je.Code, je.Message)
	}
	d, _ := json.Marshal(je.Details)
	var vo VerifyOutput
	json.Unmarshal(d, &vo)
	if !vo.RepoCheckOk || vo.FilesCompared != 2 || len(vo.Mismatches) != 2 || vo.Mismatches[0].Reason != "sha256" || vo.Mismatches[1].Reason != "missing" {
		t.Fatalf("verify details: %s", d)
	}
	check := fr.Calls()[0].Args
	if subcmd(check) != "check" || !slices.Contains(check, "--read-data-subset=10%") {
		t.Fatalf("check argv %q", check)
	}
	// verify temp dir cleaned up
	ents, _ := os.ReadDir(filepath.Join(m.o.WorkDir, "verify"))
	if len(ents) != 0 {
		t.Fatalf("verify dir left behind: %v", ents)
	}
	// without a manifest: repository_checked only
	vp.Manifest = nil
	out, err := m.Verify(context.Background(), vp)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), `"level":"repository_checked"`) {
		t.Fatalf("%s", b)
	}
	// restore.run staging with the same manifest → VERIFY_FAILED
	rp := restoreParams(t, map[string]any{"type": "paths", "mode": "staging"}, map[string]any{"manifest": man})
	if _, err := m.Restore(context.Background(), rp); asJobErr(t, err).Code != CodeVerifyFailed {
		t.Fatal(err)
	}
}

func TestRestoreDryRunWritesNothing(t *testing.T) {
	fr := &fakeRestic{fn: func(c execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte(`{"message_type":"verbose_status","action":"restored","item":"/srv/a","size":3}` + "\n" +
			`{"message_type":"summary","total_files":1,"files_restored":1,"total_bytes":3,"bytes_restored":3}`)}, nil
	}}
	m, state := newMgr(t, fr, nil)
	p := restoreParams(t, map[string]any{"type": "paths", "mode": "staging", "include": []string{"/srv"}}, map[string]any{"dryRun": true})
	out, err := m.Restore(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "restores")); !os.IsNotExist(err) {
		t.Fatal("dry run created the restores dir")
	}
	args := fr.Calls()[0].Args
	if !slices.Contains(args, "--dry-run") || slices.Contains(args, "--verify") || args[slices.Index(args, "--include")+1] != "/srv" {
		t.Fatalf("argv %q", args)
	}
	b, _ := json.Marshal(out)
	var o RestoreOutput
	json.Unmarshal(b, &o)
	if !o.DryRun || o.Plan == nil || o.Plan.ItemCount != 1 || o.Plan.Items[0].Item != "/srv/a" || len(o.Restored) != 0 {
		t.Fatalf("dry run out: %s", b)
	}
	// DB dry run: dump scanned, no scratch container / network
	fe, eng := helperEngine(t)
	fe.HelperHook = func(e *dockertest.Engine, c *dockertest.Container) bool {
		e.Lock()
		c.Files = map[string][]byte{"/work/shop.sql": []byte("CREATE TABLE public.items (\nid int);\nCREATE TABLE public.users (id int);\n")}
		e.Unlock()
		return false
	}
	m2, _ := newMgr(t, &fakeRestic{}, eng)
	dp := restoreParams(t, map[string]any{"type": "postgres", "app": "shop", "service": "db", "database": "shop", "user": "shop",
		"passwordSecretKey": "DB_PASSWORD", "mode": "scratch"}, map[string]any{"dryRun": true})
	out, err = m2.Restore(context.Background(), dp)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(out)
	if !strings.Contains(string(b), `"tables":["public.items","public.users"]`) {
		t.Fatalf("db dry run: %s", b)
	}
	for _, c := range fe.MutatingCalls() {
		if strings.Contains(c.Path, "/networks/create") || strings.Contains(c.Query, "restore-") {
			t.Fatalf("dry run created %s %s", c.Path, c.Query)
		}
	}
}

func TestScratchRemovedEvenOnFailure(t *testing.T) {
	scratchImg := "lab-registry:5000/postgres@sha256:" + strings.Repeat("5", 64)
	for _, failLoad := range []bool{true, false} {
		fe, eng := helperEngine(t)
		fe.HelperHook = func(e *dockertest.Engine, c *dockertest.Container) bool {
			e.Lock()
			defer e.Unlock()
			ep := c.Entrypoint()
			switch {
			case len(ep) > 0 && ep[0] == "psql" && slices.Contains(c.Cmd(), "-f"):
				if failLoad {
					c.ExitCode, c.Stderr = 3, "psql: error: FATAL password "+c.Env[0]
				}
			case len(ep) > 0 && ep[0] == "psql":
				c.Stdout = "T|public.items|3\nC|public.items:items_pkey|\n"
			case len(ep) == 0:
				c.Files = map[string][]byte{"/work/shop.sql": []byte("CREATE TABLE public.items (id int);\n")}
			}
			return false
		}
		m, _ := newMgr(t, &fakeRestic{}, eng)
		man := []any{map[string]any{"target": 0, "type": "postgres", "snapshotId": snapFull, "fileCount": 0, "truncated": false, "database": "shop",
			"tables": []any{map[string]any{"name": "public.items", "rows": 3}}, "constraints": []string{"public.items:items_pkey"}}}
		p := restoreParams(t, map[string]any{"type": "postgres", "app": "shop", "service": "db", "database": "shop", "user": "shop",
			"passwordSecretKey": "DB_PASSWORD", "mode": "scratch", "scratchImage": scratchImg}, map[string]any{"manifest": man})
		out, err := m.Restore(context.Background(), p)
		var scratch *dockertest.Container
		for _, c := range fe.RemovedSnapshot() {
			if c.Labels["ppanel.backup.role"] == "scratch" {
				scratch = c
			}
		}
		if scratch == nil || !scratch.RemovedWithVolumes || !docker.ScratchNameRe.MatchString(scratch.Name) {
			t.Fatalf("failLoad=%v: scratch container not removed with its volumes: %+v", failLoad, scratch)
		}
		hc := scratch.CreatedBody["HostConfig"].(map[string]any)
		if len(hc["PortBindings"].(map[string]any)) != 0 || hc["CapDrop"].([]any)[0] != "ALL" || !strings.HasPrefix(hc["NetworkMode"].(string), "ppanel-restore-") {
			t.Fatalf("scratch hardening: %v", hc)
		}
		if len(fe.Networks) != 0 {
			t.Fatalf("restore network left: %v", fe.Networks)
		}
		if len(fe.Containers) != 0 {
			t.Fatalf("containers left: %d", len(fe.Containers))
		}
		var pw string
		for _, kv := range scratch.Env {
			if v, ok := strings.CutPrefix(kv, "POSTGRES_PASSWORD="); ok {
				pw = v
			}
		}
		if len(pw) < 32 {
			t.Fatalf("scratch password not random/long: %q", pw)
		}
		if failLoad {
			je := asJobErr(t, err)
			d, _ := json.Marshal(je)
			if je.Code != CodeRestoreFailed || strings.Contains(string(d), pw) {
				t.Fatalf("load failure: %s", d)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), pw) {
			t.Fatal("scratch password in output")
		}
		var o RestoreOutput
		json.Unmarshal(b, &o)
		if o.Scratch == nil || !o.Scratch.Removed || !o.Verify.OK || o.Verify.Compared != 2 {
			t.Fatalf("scratch out: %s", b)
		}
	}
}

func TestEngineAllowlistP6(t *testing.T) {
	ok := [][2]string{{"POST", "/containers/abc/wait"}, {"PUT", "/containers/ppanel-bk-0123456789abcdef/archive"},
		{"DELETE", "/networks/ppanel-restore-0a1b2c3d"}, {"GET", "/containers/abc/archive"}, {"GET", "/volumes/ppanel-shop-data"}}
	for _, c := range ok {
		if !docker.AllowedCall(c[0], c[1]) {
			t.Errorf("%v refused", c)
		}
	}
	no := [][2]string{{"PUT", "/containers/ppanel-shop-0a1b2c3d/archive"}, {"DELETE", "/networks/ppanel-shop"}, {"DELETE", "/volumes/ppanel-shop-data"},
		{"POST", "/containers/abc/exec"}, {"POST", "/exec/abc/start"}, {"GET", "/containers/abc/exec"}}
	for _, c := range no {
		if docker.AllowedCall(c[0], c[1]) {
			t.Errorf("%v allowed", c)
		}
	}
	if docker.AllowedQuery("DELETE", "/containers/ppanel-shop-0a1b2c3d", map[string][]string{"v": {"1"}}) {
		t.Error("v=1 delete of an app container allowed")
	}
	if !docker.AllowedQuery("DELETE", "/containers/ppanel-restore-0a1b2c3d-db", map[string][]string{"v": {"1"}}) {
		t.Error("v=1 delete of the scratch container refused")
	}
}

// writeTar writes files (rel path -> data) as a tar stream (lab fixtures).
func writeTar(w io.Writer, files map[string][]byte) error {
	tw := tar.NewWriter(w)
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o640, Size: int64(len(files[n])), Typeflag: tar.TypeReg, Uid: 33, Gid: 33}); err != nil {
			return err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return err
		}
	}
	return tw.Close()
}

func TestRestoreInPlaceModes(t *testing.T) {
	// paths in_place: target "/" with the include list; verify hashes the live paths
	fr := &fakeRestic{fn: func(c execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte(`{"message_type":"summary","total_files":1,"files_restored":1,"total_bytes":1,"bytes_restored":1}`)}, nil
	}}
	m, state := newMgr(t, fr, nil)
	p := restoreParams(t, map[string]any{"type": "paths", "mode": "in_place", "include": []string{"/srv/app"}}, map[string]any{"verify": false})
	if _, err := m.Restore(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	args := fr.Calls()[0].Args
	if args[slices.Index(args, "--target")+1] != "/" || args[slices.Index(args, "--include")+1] != "/srv/app" || slices.Contains(args, "--verify") {
		t.Fatalf("in_place argv %q", args)
	}
	if _, err := os.Stat(filepath.Join(state, "restores")); !os.IsNotExist(err) {
		t.Fatal("in_place created a staging dir")
	}
	// mysql in_place: dump loaded into the app service with the app password (env only)
	fe, eng := helperEngine(t)
	fe.AddNetwork("ppanel-shop", map[string]string{"ppanel.managed": "true", "ppanel.app": "shop"})
	fe.HelperHook = func(e *dockertest.Engine, c *dockertest.Container) bool {
		e.Lock()
		defer e.Unlock()
		ep := c.Entrypoint()
		switch {
		case len(ep) == 0:
			c.Files = map[string][]byte{"/work/shop.sql": []byte("CREATE TABLE `items` (id int);\n")}
		case ep[0] == "mysql" && slices.Contains(c.Cmd(), "source /work/shop.sql"):
			if string(c.Files["/work/shop.sql"]) == "" {
				c.ExitCode, c.Stderr = 1, "dump not handed over"
			}
		case ep[0] == "mysql" && strings.Contains(strings.Join(c.Cmd(), " "), "information_schema"):
			c.Stdout = "T\titems\t\nC\titems:PRIMARY\t\n"
		case ep[0] == "mysql":
			c.Stdout = "items\t4\n"
		}
		return false
	}
	m2, _ := newMgr(t, &fakeRestic{}, eng)
	man := []any{map[string]any{"target": 0, "type": "mysql", "snapshotId": snapFull, "fileCount": 0, "truncated": false, "database": "shop",
		"tables": []any{map[string]any{"name": "items", "rows": 4}}, "constraints": []string{"items:PRIMARY"}}}
	mp := restoreParams(t, map[string]any{"type": "mysql", "app": "shop", "service": "db", "database": "shop", "user": "shop",
		"passwordSecretKey": "DB_PASSWORD", "mode": "in_place"}, map[string]any{"manifest": man})
	out, err := m2.Restore(context.Background(), mp)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	noSecrets(t, "mysql restore output", b)
	if !strings.Contains(string(b), `"ok":true`) || !strings.Contains(string(b), `"compared":2`) {
		t.Fatalf("mysql in_place: %s", b)
	}
	var load *dockertest.Container
	for _, c := range fe.RemovedSnapshot() {
		if c.Labels["ppanel.backup.role"] == "load" {
			load = c
		}
	}
	if load == nil || load.CreatedBody["HostConfig"].(map[string]any)["NetworkMode"] != "ppanel-shop" || !slices.Contains(load.Env, "MYSQL_PWD="+dbPW) ||
		!slices.Contains(load.Cmd(), "--host=db") || !slices.Contains(load.Cmd(), "--port=3306") {
		t.Fatalf("load helper: %+v", load)
	}
	for _, a := range load.Cmd() {
		if strings.Contains(a, dbPW) {
			t.Fatal("password in argv")
		}
	}
	if DumpCommand(dbConn{Type: "mysql", Host: "db", Port: 3306, User: "shop", Database: "shop"})[0] != "mysqldump" {
		t.Fatal("mysql dump command")
	}
	if q := MysqlCountQuery([]string{"items", "bad`name", "orders"}); q != "select 'items', count(*) from `items` union all select 'orders', count(*) from `orders`" {
		t.Fatal(q)
	}
}

// F-12: an unreachable repository fails fast with REPO_UNREACHABLE (bounded
// preflight) instead of after restic's ~15 min of backend retries, and no
// backup is attempted.
func TestBackupUnreachableRepoFailsFast(t *testing.T) {
	src := t.TempDir()
	fr := &fakeRestic{fn: func(c execx.Cmd) (execx.Result, error) {
		if subcmd(c.Args) == "cat" {
			if c.Timeout > 2*time.Second {
				return execx.Result{}, fmt.Errorf("preflight timeout %s not bounded by RepoCheckTimeout", c.Timeout)
			}
			time.Sleep(c.Timeout + 50*time.Millisecond) // restic stuck retrying the backend
			return execx.Result{ExitCode: -1}, context.DeadlineExceeded
		}
		return execx.Result{Stdout: summary(snapFull)}, nil
	}}
	m, _ := newMgr(t, fr, nil)
	m.o.RepoCheckTimeout = 200 * time.Millisecond
	p, _ := DecodeBackup(mustJSON(backupRaw(map[string]any{"type": "paths", "paths": []string{src}})))
	start := time.Now()
	_, err := m.Backup(context.Background(), p)
	je := asJobErr(t, err)
	if je.Code != CodeRepoUnreachable || !strings.Contains(je.Message, "did not answer within") {
		t.Fatalf("%s: %s", je.Code, je.Message)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
	for _, c := range fr.Calls() {
		if subcmd(c.Args) == "backup" {
			t.Fatal("backup attempted against an unreachable repo")
		}
	}
	// a fast restic failure is classified as before (exit 10: repo does not exist)
	fr.fn = func(c execx.Cmd) (execx.Result, error) {
		return execx.Result{ExitCode: 10, Stderr: []byte("Fatal: repository does not exist: unable to open config file")}, nil
	}
	_, err = m.Backup(context.Background(), p)
	if je := asJobErr(t, err); je.Code != CodeRepoUnreachable {
		t.Fatalf("exit 10: %s", je.Code)
	}
}
