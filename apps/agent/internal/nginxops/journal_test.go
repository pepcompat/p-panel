package nginxops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
)

// errKilled simulates the agent process dying at a given exec step: the
// handler panics out (deferred journal clean-up does not run), like SIGKILL.
type errKilled struct{}

// crashAt wraps the fake so that the step for which when(args) is true runs
// and then the "process dies".
func crashAt(e *env, when func(args []string) bool) {
	e.m.o.Exec = execFunc(func(ctx context.Context, bin string, args []string, to time.Duration, mx int) (execx.Result, error) {
		r, err := e.f.Run(ctx, bin, args, to, mx)
		if when(args) {
			panic(errKilled{})
		}
		return r, err
	})
}

func isReload(args []string) bool { return args[len(args)-1] == "reload" }

func runCrashing(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected simulated crash")
		} else if _, ok := r.(errKilled); !ok {
			panic(r)
		}
	}()
	f()
}

func journalExists(e *env) bool {
	_, err := os.Lstat(filepath.Join(e.state, "nginx-backups", journalName))
	return err == nil
}

// restart builds a fresh Manager on the same root/state (new process).
func restart(t *testing.T, e *env) *Manager {
	t.Helper()
	m, err := New(e.m.o)
	must(t, err)
	m.o.Exec = e.f
	return m
}

// F-3: agent killed right after the reload of an apply → the candidate is
// live. On restart the backup is restored, nginx -t + reload run, and the
// backup is marked auto-reverted (host = "not applied", like the Center says).
func TestRecoverInterruptedApplyAfterReload(t *testing.T) {
	e := newEnv(t)
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	crashAt(e, isReload)
	runCrashing(t, func() {
		_, _ = e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 80; location /new {} }\n"},
			{Path: "/etc/nginx/ppanel-managed/new.conf", Content: "server {}\n"},
		}})
	})
	if !journalExists(e) {
		t.Fatal("journal must survive a crash")
	}
	if e.f.reloadCount() != 1 {
		t.Fatalf("reloads %d", e.f.reloadCount())
	}
	m := restart(t, e)
	rec, err := m.RecoverInterrupted(context.Background())
	must(t, err)
	if rec == nil || rec.Outcome != RecoveryRestored || rec.Kind != kindApply || rec.RevisionID != rev1 || rec.JobID != rev2 || rec.Info["filesChanged"] != true {
		t.Fatalf("recovery %+v", rec)
	}
	sameTree(t, before, tree(e.root))
	if e.f.reloadCount() != 2 {
		t.Fatalf("restored config not reloaded: %d", e.f.reloadCount())
	}
	if journalExists(e) {
		t.Fatal("journal not cleared")
	}
	man, err := m.loadManifest(rev1)
	must(t, err)
	if man.Status != statusAutoReverted {
		t.Fatalf("status %s", man.Status)
	}
	// second start: nothing to do
	rec, err = m.RecoverInterrupted(context.Background())
	if rec != nil || err != nil {
		t.Fatalf("second recovery %+v %v", rec, err)
	}
	// the revision can be applied again (not blocked as "already applied")
	if _, err := m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
		{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 81; }\n"}}}); err != nil {
		t.Fatal(err)
	}
	if journalExists(e) {
		t.Fatal("successful apply must clear its journal")
	}
}

// Killed after writing candidates but before nginx -t: restored, reloaded.
func TestRecoverInterruptedApplyBeforeTest(t *testing.T) {
	e := newEnv(t)
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	crashAt(e, func(args []string) bool { return args[len(args)-1] == "-t" })
	runCrashing(t, func() {
		_, _ = e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 99; }\n"}}})
	})
	rec, err := restart(t, e).RecoverInterrupted(context.Background())
	must(t, err)
	if rec.Outcome != RecoveryRestored {
		t.Fatalf("%+v", rec)
	}
	sameTree(t, before, tree(e.root))
}

// A file changed by someone else after the crash is never overwritten.
func TestRecoverInterruptedRefusesForeignChange(t *testing.T) {
	e := newEnv(t)
	shaA := shaHex([]byte(origA))
	crashAt(e, isReload)
	runCrashing(t, func() {
		_, _ = e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 80; location /new {} }\n"}}})
	})
	must(t, os.WriteFile(e.root+"/sites-available/a.conf", []byte("operator fixed it by hand\n"), 0o640))
	before := tree(e.root)
	reloads := e.f.reloadCount()
	m := restart(t, e)
	rec, err := m.RecoverInterrupted(context.Background())
	must(t, err)
	if rec.Outcome != RecoveryManual || !strings.Contains(rec.Reason, "neither the original") {
		t.Fatalf("%+v", rec)
	}
	sameTree(t, before, tree(e.root))
	if e.f.reloadCount() != reloads {
		t.Fatal("must not reload")
	}
	man, _ := m.loadManifest(rev1)
	if man.Status != statusInterruptedManual || journalExists(e) {
		t.Fatalf("status %s journal %v", man.Status, journalExists(e))
	}
}

// A dry-run validate killed after writing candidates: restored, never reloaded,
// dry-run backup removed.
func TestRecoverInterruptedValidate(t *testing.T) {
	e := newEnv(t)
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	job := "41111111-2222-4333-8444-555555555555"
	crashAt(e, func(args []string) bool { return args[len(args)-1] == "-t" })
	runCrashing(t, func() {
		_, _ = e.m.Validate(ctxJob(job), RevisionParams{RevisionID: rev1, Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 7; }\n"}}})
	})
	rec, err := restart(t, e).RecoverInterrupted(context.Background())
	must(t, err)
	if rec.Outcome != RecoveryRestored || rec.Kind != kindValidate {
		t.Fatalf("%+v", rec)
	}
	sameTree(t, before, tree(e.root))
	if e.f.reloadCount() != 0 {
		t.Fatal("validate recovery must not reload")
	}
	if _, err := os.Stat(filepath.Join(e.state, "nginx-backups", job)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("dry-run backup kept")
	}
}

// A revert killed after its reload: the revision stays applied on the host
// (the Center did not record the revert).
func TestRecoverInterruptedRevert(t *testing.T) {
	e := newEnv(t)
	shaA := shaHex([]byte(origA))
	newA := "server { listen 80; server_name a.example; location /x {} }\n"
	_, err := e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
		{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: newA}}})
	must(t, err)
	applied := tree(e.root)
	shaNew := shaHex([]byte(newA))
	crashAt(e, isReload)
	runCrashing(t, func() {
		_, _ = e.m.Revert(ctxJob(rev2), RevertParams{RevisionID: rev1, ExpectedCurrent: []ExpectedFile{
			{Path: "/etc/nginx/sites-available/a.conf", Sha256: &shaNew}}})
	})
	if b, _ := os.ReadFile(e.root + "/sites-available/a.conf"); string(b) != origA {
		t.Fatal("crash point: original should be on disk")
	}
	m := restart(t, e)
	rec, err := m.RecoverInterrupted(context.Background())
	must(t, err)
	if rec.Outcome != RecoveryRestored || rec.Kind != kindPreRevert {
		t.Fatalf("%+v", rec)
	}
	sameTree(t, applied, tree(e.root))
	man, _ := m.loadManifest(rev1)
	if man.Status != statusApplied {
		t.Fatalf("revision backup status %s", man.Status)
	}
	if e.f.reloadCount() != 3 { // apply, crashed revert, recovery
		t.Fatalf("reloads %d", e.f.reloadCount())
	}
}

// Recovery whose reload fails still restores the files and says so.
func TestRecoverInterruptedReloadFails(t *testing.T) {
	e := newEnv(t)
	before := tree(e.root)
	shaA := shaHex([]byte(origA))
	crashAt(e, isReload)
	runCrashing(t, func() {
		_, _ = e.m.Apply(ctxJob(rev2), RevisionParams{RevisionID: rev1, Files: []FileChange{
			{Path: "/etc/nginx/sites-available/a.conf", ExpectedSha256Before: &shaA, Content: "server { listen 5; }\n"}}})
	})
	e.f.reloadFail = true
	rec, err := restart(t, e).RecoverInterrupted(context.Background())
	must(t, err)
	if rec.Outcome != RecoveryReloadFailed || rec.Info["reloadError"] == nil {
		t.Fatalf("%+v", rec)
	}
	sameTree(t, before, tree(e.root))
}
