package nginxops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Options configure a Manager.
type Options struct {
	// Root is the physical nginx config root (default /etc/nginx; others only
	// with PPANEL_AGENT_TEST_NGINX_ROOT=1).
	Root         string
	AllowedRoots []string // logical /etc/nginx/... prefixes (narrowing only)
	StateDir     string   // backups under <StateDir>/nginx-backups
	// NginxBinary / SystemctlBinary are absolute overrides ("" = discover).
	NginxBinary     string
	SystemctlBinary string
	// Prefix / ConfFile become nginx -p / -c (test-only, same env gate as Root).
	Prefix   string
	ConfFile string
	// SystemdRunDir (default /run/systemd/system) decides "systemd is PID 1".
	SystemdRunDir  string
	DefaultPidFile string // default /run/nginx.pid
	Exec           execx.Executor
	// Settle is the wait between reload and postchecks (default 2 s; <0 = none).
	Settle       time.Duration
	ProbeTimeout time.Duration
	Now          func() time.Time
}

// Manager runs the nginx typed jobs.
type Manager struct {
	o    Options
	root string
}

// New validates options (root gate) and returns a Manager.
func New(o Options) (*Manager, error) {
	nc := config.NginxConfig{Root: o.Root, AllowedRoots: o.AllowedRoots, Prefix: o.Prefix, ConfFile: o.ConfFile}
	if errs := nc.ValidateNginx(); len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	if o.StateDir == "" || !filepath.IsAbs(o.StateDir) {
		return nil, errors.New("nginxops: StateDir must be absolute")
	}
	if o.Exec == nil {
		return nil, errors.New("nginxops: Exec is required")
	}
	if o.Settle == 0 {
		o.Settle = 2 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Manager{o: o, root: nc.Root}, nil
}

func (m *Manager) now() time.Time { return m.o.Now() }

// opSem is the PROCESS-WIDE lock for nginx jobs (shared by all Managers).
// Mutating jobs hold it for their whole duration; read_files also takes it so
// it never observes a validate's transient candidate files.
var opSem = make(chan struct{}, 1)

func lock(ctx context.Context) (func(), error) {
	select {
	case opSem <- struct{}{}:
		return func() { <-opSem }, nil
	case <-ctx.Done():
		return func() {}, jobs.Errorf(jobs.HandlerTimeout, "timed out waiting for the nginx operation lock")
	}
}

// recoveryCtx gives restore/reload steps their own budget even if the job's
// context is nearly expired.
func recoveryCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "local-" + hex.EncodeToString(b)
}

// FileResult is output.files[] / filesChecked[].
type FileResult struct {
	Path         string  `json:"path"`
	Sha256Before *string `json:"sha256Before"`
	Sha256After  *string `json:"sha256After"`
}

// ReadFile is nginx.read_files output.files[].
type ReadFile struct {
	Path         string  `json:"path"`
	Exists       bool    `json:"exists"`
	Sha256       *string `json:"sha256"`
	SizeBytes    int64   `json:"sizeBytes"`
	Content      *string `json:"content"`
	IsSymlink    bool    `json:"isSymlink"`
	ResolvedPath string  `json:"resolvedPath"`
	Truncated    bool    `json:"truncated,omitempty"`
}

// ReadOutput is nginx.read_files output.
type ReadOutput struct {
	Files []ReadFile `json:"files"`
}

// ValidateOutput is nginx.validate output.
type ValidateOutput struct {
	Valid           bool         `json:"valid"`
	NginxTestOutput string       `json:"nginxTestOutput"`
	FilesChecked    []FileResult `json:"filesChecked"`
}

// ApplyOutput is nginx.apply output.
type ApplyOutput struct {
	Applied         bool          `json:"applied"`
	Files           []FileResult  `json:"files"`
	NginxTestOutput string        `json:"nginxTestOutput"`
	ReloadMethod    string        `json:"reloadMethod"`
	Postchecks      []ProbeResult `json:"postchecks"`
	BackupID        string        `json:"backupId"`
}

// RevertOutput is nginx.revert output ("like apply").
type RevertOutput struct {
	Reverted        bool          `json:"reverted"`
	Files           []FileResult  `json:"files"`
	NginxTestOutput string        `json:"nginxTestOutput"`
	ReloadMethod    string        `json:"reloadMethod"`
	Postchecks      []ProbeResult `json:"postchecks"`
	BackupID        string        `json:"backupId"`
}

// DriftFile is DRIFT_DETECTED details.files[].
type DriftFile struct {
	Path     string  `json:"path"`
	Expected *string `json:"expected"`
	Actual   *string `json:"actual"`
}

func eqSha(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// CheckPaths runs the filesystem path policy without locking (used by the
// handlers' Preflight before ack; Run re-checks under the lock).
func (m *Manager) CheckPaths(paths []string, write bool) error {
	for _, p := range paths {
		if _, err := m.resolve(p, write); err != nil {
			return err
		}
	}
	return nil
}

// resolveAll applies the path policy to all paths (PATH_NOT_ALLOWED first)
// and, for writes, rejects two logical paths resolving to the same file
// (reading a sites-enabled link and its target together is fine).
func (m *Manager) resolveAll(paths []string, write bool) ([]*target, error) {
	ts := make([]*target, 0, len(paths))
	seen := map[string]string{}
	for _, p := range paths {
		t, err := m.resolve(p, write)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[t.ResolvedPhys]; dup && write {
			return nil, pathErr("%s and %s resolve to the same file", prev, p)
		}
		seen[t.ResolvedPhys] = p
		ts = append(ts, t)
	}
	return ts, nil
}

// preflight = path policy + creation rule + drift check for a file set.
func (m *Manager) preflight(files []FileChange) ([]*target, error) {
	paths := make([]string, len(files))
	for i, f := range files {
		if err := ValidContent(f.Path, f.Content); err != nil {
			return nil, err
		}
		paths[i] = f.Path
	}
	ts, err := m.resolveAll(paths, true)
	if err != nil {
		return nil, err
	}
	for i, f := range files {
		if f.ExpectedSha256Before == nil && !ts[i].creatable() {
			return nil, pathErr("creating %s is not allowed: %s", f.Path, createRule)
		}
	}
	var drift []DriftFile
	for i, f := range files {
		if !eqSha(f.ExpectedSha256Before, ts[i].Sha) {
			drift = append(drift, DriftFile{Path: f.Path, Expected: f.ExpectedSha256Before, Actual: ts[i].Sha})
		}
	}
	if len(drift) > 0 {
		e := jobs.Errorf(CodeDriftDetected, "%d file(s) changed since the revision was prepared; nothing written", len(drift))
		e.Details = map[string]any{"files": drift}
		return nil, e
	}
	return ts, nil
}

// revertFailed reports REVERT_FAILED_MANUAL_RECOVERY. When the files were
// restored and verified (extra["restored"] == true, set by autoRevert) and
// only nginx -t / reload of the restored config failed, the message says so
// and details.restoredFiles carries the verified sha256 of every file.
func revertFailed(backupDir string, probs []RestoreProblem, extra map[string]any) *jobs.Error {
	e := jobs.Errorf(CodeRevertFailedManual, "CRITICAL: could not restore original nginx config; manual recovery required from %s", backupDir)
	if restored, _ := extra["restored"].(bool); restored {
		e = jobs.Errorf(CodeRevertFailedManual, "nginx config files restored and verified (sha256 match), but nginx could not be tested/reloaded on them; manual nginx reload required (backup in %s)", backupDir)
	}
	d := map[string]any{"backupDir": backupDir, "problems": probs}
	for k, v := range extra {
		d[k] = v
	}
	e.Details = d
	return e
}

// ---------------- read_files ----------------

// Read implements nginx.read_files.
func (m *Manager) Read(ctx context.Context, p ReadParams) (*ReadOutput, error) {
	unlock, err := lock(ctx)
	defer unlock()
	if err != nil {
		return nil, err
	}
	ts, err := m.resolveAll(p.Paths, false)
	if err != nil {
		return nil, err
	}
	out := &ReadOutput{Files: make([]ReadFile, 0, len(ts))}
	for _, t := range ts {
		rf := ReadFile{Path: t.Logical, Exists: t.Exists, Sha256: t.Sha, IsSymlink: t.IsSymlink, ResolvedPath: t.ResolvedLogical}
		if t.Exists {
			rf.SizeBytes = int64(len(t.Content))
			switch {
			case len(t.Content) > MaxFileBytes:
				rf.Truncated = true
			case utf8.Valid(t.Content):
				rf.Content = strp(string(t.Content))
			}
		}
		out.Files = append(out.Files, rf)
	}
	return out, nil
}

// ---------------- validate ----------------

func fileResults(ts []*target, files []FileChange) []FileResult {
	out := make([]FileResult, len(ts))
	for i, t := range ts {
		out[i] = FileResult{Path: t.Logical, Sha256Before: t.Sha, Sha256After: strp(shaHex([]byte(files[i].Content)))}
	}
	return out
}

// Validate implements nginx.validate (dry run; never reloads; always restores).
func (m *Manager) Validate(ctx context.Context, p RevisionParams) (*ValidateOutput, error) {
	unlock, err := lock(ctx)
	defer unlock()
	if err != nil {
		return nil, err
	}
	if _, err := m.nginxBin(); err != nil {
		return nil, err
	}
	ts, err := m.preflight(p.Files)
	if err != nil {
		return nil, err
	}
	jobID := jobs.JobID(ctx)
	if !uuidRe.MatchString(jobID) {
		jobID = randomID()
	}
	man, err := m.writeBackup(jobID, kindValidate, p.RevisionID, jobID, ts)
	if err != nil {
		return nil, jobs.Errorf(jobs.HandlerFailed, "backup failed, nothing written: %v", err)
	}
	if err := m.writeJournal(man, candidatesOf(p.Files)); err != nil {
		_ = os.RemoveAll(m.backupDir(man.ID))
		return nil, jobs.Errorf(jobs.HandlerFailed, "writing the nginx job journal failed, nothing written: %v", err)
	}
	defer m.clearJournalUnlessPanic()
	werr := m.writeCandidates(ts, p.Files)
	valid, testOut := false, ""
	if werr == nil {
		valid, testOut = m.nginxTest(ctx)
	}
	if probs := m.restore(man); len(probs) > 0 {
		return nil, revertFailed(m.backupDir(man.ID), probs, map[string]any{"nginxTestOutput": testOut})
	}
	_ = os.RemoveAll(m.backupDir(man.ID)) // verified restored; dry-run backup no longer needed
	if werr != nil {
		return nil, jobs.Errorf(jobs.HandlerFailed, "writing candidate files failed (originals restored): %v", werr)
	}
	return &ValidateOutput{Valid: valid, NginxTestOutput: testOut, FilesChecked: fileResults(ts, p.Files)}, nil
}

// ---------------- apply ----------------

// autoRevert restores originals, then runs nginx -t and reload so the running
// nginx is back on the original config. It returns (testOK, reloadErr, probs).
func (m *Manager) autoRevert(ctx context.Context, man *manifest, reloadToo bool) (map[string]any, []RestoreProblem) {
	rctx, cancel := recoveryCtx(ctx)
	defer cancel()
	probs := m.restore(man)
	info := map[string]any{"restored": len(probs) == 0}
	if len(probs) > 0 || !reloadToo {
		return info, probs
	}
	info["restoredFiles"] = restoredFiles(man)
	ok, out := m.nginxTest(rctx)
	info["revertNginxTestOk"] = ok
	if !ok {
		info["revertNginxTestOutput"] = out
		return info, []RestoreProblem{{Path: LogicalRoot, Error: "nginx -t failed on the restored original config"}}
	}
	method, err := m.reload(rctx)
	info["revertReloadMethod"] = method
	info["revertReloadOk"] = err == nil
	if err != nil {
		info["revertReloadError"] = err.Error()
		return info, []RestoreProblem{{Path: LogicalRoot, Error: "reload of the restored original config failed: " + err.Error()}}
	}
	m.settle(rctx)
	return info, nil
}

// settle waits for the reloaded workers to take over (nginx -s reload and
// systemctl reload return before old workers exit).
func (m *Manager) settle(ctx context.Context) {
	if m.o.Settle <= 0 {
		return
	}
	t := time.NewTimer(m.o.Settle)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (m *Manager) markStatus(man *manifest, status string) {
	man.Status = status
	_ = m.saveManifest(man)
}

// Apply implements nginx.apply.
func (m *Manager) Apply(ctx context.Context, p RevisionParams) (*ApplyOutput, error) {
	unlock, err := lock(ctx)
	defer unlock()
	if err != nil {
		return nil, err
	}
	if _, err := m.nginxBin(); err != nil {
		return nil, err
	}
	ts, err := m.preflight(p.Files)
	if err != nil {
		return nil, err
	}
	if prev, err := m.loadManifest(p.RevisionID); err == nil && prev.Status == statusApplied {
		return nil, jobs.Errorf(jobs.HandlerFailed, "revision %s is already applied (backup kept); revert it or use a new revisionId", p.RevisionID)
	}
	man, err := m.writeBackup(p.RevisionID, kindApply, p.RevisionID, jobs.JobID(ctx), ts)
	if err != nil {
		return nil, jobs.Errorf(jobs.HandlerFailed, "backup failed, nothing written: %v", err)
	}
	bdir := m.backupDir(man.ID)
	results := fileResults(ts, p.Files)
	if err := m.writeJournal(man, candidatesOf(p.Files)); err != nil {
		m.markStatus(man, statusAutoReverted)
		return nil, jobs.Errorf(jobs.HandlerFailed, "writing the nginx job journal failed, nothing written: %v", err)
	}
	defer m.clearJournalUnlessPanic()

	if werr := m.writeCandidates(ts, p.Files); werr != nil {
		if _, probs := m.autoRevert(ctx, man, false); len(probs) > 0 {
			return nil, revertFailed(bdir, probs, map[string]any{"writeError": werr.Error()})
		}
		m.markStatus(man, statusAutoReverted)
		return nil, jobs.Errorf(jobs.HandlerFailed, "writing candidate files failed (originals restored): %v", werr)
	}

	ok, testOut := m.nginxTest(ctx)
	if !ok {
		if _, probs := m.autoRevert(ctx, man, false); len(probs) > 0 {
			return nil, revertFailed(bdir, probs, map[string]any{"nginxTestOutput": testOut})
		}
		m.markStatus(man, statusAutoReverted)
		e := jobs.Errorf(CodeNginxTestFailed, "nginx -t rejected the candidate config; originals restored, no reload")
		e.Details = map[string]any{"nginxTestOutput": testOut, "backupId": man.ID}
		return nil, e
	}

	pidFile := m.pidFile(ctx)
	method, rerr := m.reload(ctx)
	if rerr != nil {
		info, probs := m.autoRevert(ctx, man, true)
		if len(probs) > 0 {
			info["reloadError"] = rerr.Error()
			return nil, revertFailed(bdir, probs, info)
		}
		m.markStatus(man, statusAutoReverted)
		e := jobs.Errorf(CodeReloadFailedReverted, "reload failed; originals restored and reloaded")
		info["reloadError"], info["reloadMethod"], info["nginxTestOutput"], info["backupId"] = rerr.Error(), method, testOut, man.ID
		e.Details = info
		return nil, e
	}

	m.settle(ctx)
	probes := make([]ProbeResult, 0, len(p.Postchecks))
	allOK := true
	for _, pc := range p.Postchecks {
		r := m.probe(ctx, pc)
		allOK = allOK && r.OK
		probes = append(probes, r)
	}
	pid, alive, perr := masterAlive(pidFile)
	if !alive {
		allOK = false
	}
	if !allOK {
		info, probs := m.autoRevert(ctx, man, true)
		info["postchecks"], info["masterPidAlive"], info["masterPid"], info["pidFile"] = probes, alive, pid, pidFile
		if perr != nil {
			info["masterPidError"] = perr.Error()
		}
		if len(probs) > 0 {
			return nil, revertFailed(bdir, probs, info)
		}
		m.markStatus(man, statusAutoReverted)
		info["reloadMethod"], info["nginxTestOutput"], info["backupId"] = method, testOut, man.ID
		e := jobs.Errorf(CodePostcheckReverted, "postcheck failed after reload; originals restored and reloaded")
		e.Details = info
		return nil, e
	}

	for i := range man.Files {
		man.Files[i].AfterSha256 = results[i].Sha256After
	}
	m.markStatus(man, statusApplied)
	m.pruneBackups()
	return &ApplyOutput{Applied: true, Files: results, NginxTestOutput: testOut, ReloadMethod: method, Postchecks: probes, BackupID: man.ID}, nil
}

// ---------------- revert ----------------

// Revert implements nginx.revert.
func (m *Manager) Revert(ctx context.Context, p RevertParams) (*RevertOutput, error) {
	unlock, err := lock(ctx)
	defer unlock()
	if err != nil {
		return nil, err
	}
	if _, err := m.nginxBin(); err != nil {
		return nil, err
	}
	paths := make([]string, len(p.ExpectedCurrent))
	for i, e := range p.ExpectedCurrent {
		paths[i] = e.Path
	}
	ts, err := m.resolveAll(paths, true)
	if err != nil {
		return nil, err
	}
	var drift []DriftFile
	for i, e := range p.ExpectedCurrent {
		if !eqSha(e.Sha256, ts[i].Sha) {
			drift = append(drift, DriftFile{Path: e.Path, Expected: e.Sha256, Actual: ts[i].Sha})
		}
	}
	if len(drift) > 0 {
		e := jobs.Errorf(CodeDriftDetected, "%d file(s) differ from the revision's expected state; nothing changed", len(drift))
		e.Details = map[string]any{"files": drift}
		return nil, e
	}
	man, err := m.loadManifest(p.RevisionID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, jobs.Errorf(CodeBackupNotFound, "no backup for revision %s on this agent", p.RevisionID)
		}
		return nil, jobs.Errorf(CodeBackupNotFound, "backup for revision %s unreadable: %v", p.RevisionID, err)
	}
	if man.Kind != kindApply || man.Status != statusApplied {
		return nil, jobs.Errorf(CodeBackupNotFound, "revision %s has no applied backup (status %q)", p.RevisionID, man.Status)
	}
	// expectedCurrent must cover exactly the revision's files (no unchecked overwrite).
	idx := map[string]int{}
	for i, e := range p.ExpectedCurrent {
		idx[e.Path] = i
	}
	if len(idx) != len(man.Files) {
		return nil, jobs.Errorf(jobs.RejectedInvalidParams, "expectedCurrent must list exactly the %d file(s) of revision %s", len(man.Files), p.RevisionID)
	}
	for _, f := range man.Files {
		if _, ok := idx[f.Path]; !ok {
			return nil, jobs.Errorf(jobs.RejectedInvalidParams, "expectedCurrent is missing %s (part of revision %s)", f.Path, p.RevisionID)
		}
	}
	// Snapshot current (pre-revert) content so a failed revert can be undone.
	pre, err := m.writeBackup(p.RevisionID+".pre-revert", kindPreRevert, p.RevisionID, jobs.JobID(ctx), ts)
	if err != nil {
		return nil, jobs.Errorf(jobs.HandlerFailed, "pre-revert snapshot failed, nothing changed: %v", err)
	}
	// Directories created by the apply are removed (if empty) when reverting.
	pre.CreatedDirs = nil
	files := make([]FileResult, len(ts))
	for i, t := range ts {
		files[i] = FileResult{Path: t.Logical, Sha256Before: t.Sha}
	}
	undo := func(reload bool) (map[string]any, []RestoreProblem) { return m.autoRevert(ctx, pre, reload) }
	jf := make([]journalFile, 0, len(man.Files))
	for _, f := range man.Files {
		var c *string
		if f.Existed {
			c = f.Sha256
		}
		jf = append(jf, journalFile{Path: f.Path, Candidate: c})
	}
	if err := m.writeJournal(pre, jf); err != nil {
		_ = os.RemoveAll(m.backupDir(pre.ID))
		return nil, jobs.Errorf(jobs.HandlerFailed, "writing the nginx job journal failed, nothing changed: %v", err)
	}
	defer m.clearJournalUnlessPanic()

	if probs := m.restore(man); len(probs) > 0 {
		if _, uprobs := undo(false); len(uprobs) > 0 {
			return nil, revertFailed(m.backupDir(pre.ID), append(probs, uprobs...), nil)
		}
		return nil, revertFailed(m.backupDir(man.ID), probs, map[string]any{"preRevertRestored": true})
	}
	ok, testOut := m.nginxTest(ctx)
	if !ok {
		if _, uprobs := undo(false); len(uprobs) > 0 {
			return nil, revertFailed(m.backupDir(pre.ID), uprobs, map[string]any{"nginxTestOutput": testOut})
		}
		_ = os.RemoveAll(m.backupDir(pre.ID))
		e := jobs.Errorf(CodeNginxTestFailed, "nginx -t rejected the restored revision backup; pre-revert content put back, no reload")
		e.Details = map[string]any{"nginxTestOutput": testOut}
		return nil, e
	}
	method, rerr := m.reload(ctx)
	if rerr != nil {
		info, uprobs := undo(true)
		info["reloadError"] = rerr.Error()
		if len(uprobs) > 0 {
			return nil, revertFailed(m.backupDir(pre.ID), uprobs, info)
		}
		_ = os.RemoveAll(m.backupDir(pre.ID))
		e := jobs.Errorf(CodeReloadFailedReverted, "reload failed; pre-revert content put back and reloaded")
		info["reloadMethod"] = method
		e.Details = info
		return nil, e
	}
	m.settle(ctx)
	for i, t := range ts {
		if b, err := os.ReadFile(t.Phys); err == nil {
			files[i].Sha256After = strp(shaHex(b))
		}
	}
	m.markStatus(man, statusReverted)
	_ = os.RemoveAll(m.backupDir(pre.ID))
	return &RevertOutput{Reverted: true, Files: files, NginxTestOutput: testOut, ReloadMethod: method, Postchecks: []ProbeResult{}, BackupID: man.ID}, nil
}

// String is for logs.
func (m *Manager) String() string { return fmt.Sprintf("nginxops(root=%s)", m.root) }
