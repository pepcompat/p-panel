package nginxops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/safefs"
)

// journalName is the in-flight journal of a mutating nginx job, in
// <stateDir>/nginx-backups/. It is written (fsync file + dir, through
// safefs) AFTER the backup and BEFORE the first change to /etc/nginx, and
// removed once the job has reached a final state (committed, auto-reverted or
// reported as needing manual recovery). A journal found at agent start means
// the agent died in the middle of the job: RecoverInterrupted then puts the
// host back to the pre-job state, which is what the Center records for a job
// that never reported success.
const journalName = "inflight.json"

// statusInterruptedManual marks a backup whose interrupted job could not be
// rolled back automatically (files changed by someone else, or restore failed).
const statusInterruptedManual = "interrupted-manual"

type journalFile struct {
	Path string `json:"path"`
	// Candidate is the sha256 the job writes to Path (nil = the job deletes it).
	Candidate *string `json:"candidate"`
}

type journal struct {
	Version    int           `json:"version"`
	BackupID   string        `json:"backupId"`
	Kind       string        `json:"kind"`
	RevisionID string        `json:"revisionId,omitempty"`
	JobID      string        `json:"jobId,omitempty"`
	StartedAt  time.Time     `json:"startedAt"`
	Files      []journalFile `json:"files"`
}

// journalDir opens <stateDir>/nginx-backups without following symlinks in any
// component (the state dir itself may sit below a symlinked prefix: it is
// resolved first, like the nginx root).
func (m *Manager) journalDir() (*safefs.Dir, error) {
	if err := os.MkdirAll(m.backupsDir(), 0o700); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(m.backupsDir())
	if err != nil {
		return nil, err
	}
	return safefs.OpenDir(real)
}

// writeJournal durably records that the job of man is about to change files.
func (m *Manager) writeJournal(man *manifest, files []journalFile) error {
	j := journal{Version: 1, BackupID: man.ID, Kind: man.Kind, RevisionID: man.RevisionID, JobID: man.JobID,
		StartedAt: m.now().UTC(), Files: files}
	b, err := json.Marshal(&j)
	if err != nil {
		return err
	}
	d, err := m.journalDir()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.WriteFileAtomic(journalName, b, 0o600, 0, 0, false)
}

// clearJournal removes the journal (fsync dir).
func (m *Manager) clearJournal() error {
	d, err := m.journalDir()
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Remove(journalName); err != nil {
		return err
	}
	return d.Sync()
}

// clearJournalUnlessPanic is deferred by mutating jobs: a panicking job keeps
// its journal (host state unknown) so the next agent start rolls it back.
func (m *Manager) clearJournalUnlessPanic() {
	if r := recover(); r != nil {
		panic(r)
	}
	_ = m.clearJournal()
}

func (m *Manager) readJournal() (*journal, error) {
	d, err := m.journalDir()
	if err != nil {
		return nil, err
	}
	defer d.Close()
	b, _, err := d.ReadFile(journalName, 1<<20)
	if err != nil {
		return nil, err
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("nginx journal corrupt: %w", err)
	}
	return &j, nil
}

func candidatesOf(files []FileChange) []journalFile {
	out := make([]journalFile, len(files))
	for i, f := range files {
		out[i] = journalFile{Path: f.Path, Candidate: strp(shaHex([]byte(f.Content)))}
	}
	return out
}

// Recovery outcomes.
const (
	RecoveryRestored     = "restored"               // files restored, nginx tested + reloaded (or no reload needed)
	RecoveryReloadFailed = "restored_reload_failed" // files restored and verified; nginx -t or reload failed
	RecoveryManual       = "manual_required"        // nothing (more) touched; operator must check
)

// Recovery reports what RecoverInterrupted did.
type Recovery struct {
	BackupID   string           `json:"backupId"`
	Kind       string           `json:"kind"`
	RevisionID string           `json:"revisionId,omitempty"`
	JobID      string           `json:"jobId,omitempty"`
	Outcome    string           `json:"outcome"`
	Reason     string           `json:"reason,omitempty"`
	Problems   []RestoreProblem `json:"problems,omitempty"`
	Info       map[string]any   `json:"info,omitempty"`
}

// RecoverInterrupted rolls back a mutating nginx job the agent did not finish
// (killed after writing candidate files and possibly after the reload). It
// restores the job's backup, then runs nginx -t and reload (except for a dry
// run validate, which never reloads), so the host matches "not applied".
//
// Safety: it only acts when every file is still either the original or the
// candidate the job wrote; anything else means someone changed the file since,
// and nothing is touched (outcome manual_required). Returns nil when there is
// nothing to recover. Call it once at start, before jobs are accepted.
func (m *Manager) RecoverInterrupted(ctx context.Context) (*Recovery, error) {
	unlock, err := lock(ctx)
	defer unlock()
	if err != nil {
		return nil, err
	}
	j, err := m.readJournal()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		_ = m.clearJournal()
		return &Recovery{Outcome: RecoveryManual, Reason: err.Error()}, nil
	}
	rec := &Recovery{BackupID: j.BackupID, Kind: j.Kind, RevisionID: j.RevisionID, JobID: j.JobID}
	defer func() { _ = m.clearJournal() }()
	if j.BackupID == "" || filepath.Base(j.BackupID) != j.BackupID || j.BackupID == "." || j.BackupID == ".." {
		rec.Outcome, rec.Reason = RecoveryManual, "journal names an invalid backup id"
		return rec, nil
	}
	man, err := m.loadManifest(j.BackupID)
	if err != nil {
		rec.Outcome, rec.Reason = RecoveryManual, "backup manifest unreadable: "+err.Error()
		return rec, nil
	}
	if man.Kind != j.Kind {
		rec.Outcome, rec.Reason = RecoveryManual, fmt.Sprintf("journal kind %q does not match backup kind %q", j.Kind, man.Kind)
		return rec, nil
	}
	cand := map[string]*string{}
	for _, f := range j.Files {
		cand[f.Path] = f.Candidate
	}
	changed := false
	for _, e := range man.Files {
		t, err := m.resolve(e.Path, true)
		if err != nil {
			rec.Outcome, rec.Reason = RecoveryManual, fmt.Sprintf("%s: %v", e.Path, err)
			m.markStatus(man, statusInterruptedManual)
			return rec, nil
		}
		orig := e.Sha256
		if !e.Existed {
			orig = nil
		}
		c, known := cand[e.Path]
		switch {
		case eqSha(t.Sha, orig):
		case known && eqSha(t.Sha, c):
			changed = true
		default:
			rec.Outcome = RecoveryManual
			rec.Reason = fmt.Sprintf("%s is neither the original nor the interrupted job's candidate (changed since); nothing restored", e.Path)
			m.markStatus(man, statusInterruptedManual)
			return rec, nil
		}
	}
	if probs := m.restore(man); len(probs) > 0 {
		rec.Outcome, rec.Reason, rec.Problems = RecoveryManual, "restoring the backup failed", probs
		m.markStatus(man, statusInterruptedManual)
		return rec, nil
	}
	rec.Info = map[string]any{"filesChanged": changed, "restoredFiles": restoredFiles(man)}
	rec.Outcome = RecoveryRestored
	if man.Kind != kindValidate {
		// The job may have reloaded the candidate already: always reload the
		// restored config (after nginx -t) so the running nginx matches the files.
		rctx, cancel := recoveryCtx(ctx)
		defer cancel()
		if _, err := m.nginxBin(); err != nil {
			rec.Info["reloadSkipped"] = "nginx binary not found"
		} else if ok, out := m.nginxTest(rctx); !ok {
			rec.Outcome = RecoveryReloadFailed
			rec.Info["nginxTestOutput"] = out
		} else if method, err := m.reload(rctx); err != nil {
			rec.Outcome = RecoveryReloadFailed
			rec.Info["reloadMethod"], rec.Info["reloadError"] = method, err.Error()
		} else {
			rec.Info["reloadMethod"] = method
		}
	}
	switch man.Kind {
	case kindApply:
		m.markStatus(man, statusAutoReverted)
	default: // validate dry run / pre-revert snapshot: no longer needed
		_ = os.RemoveAll(m.backupDir(man.ID))
	}
	return rec, nil
}

// restoredFiles lists the verified post-restore sha256 of every file of man
// (nil = file absent), as checked by restore.
func restoredFiles(man *manifest) []map[string]any {
	out := make([]map[string]any, 0, len(man.Files))
	for _, e := range man.Files {
		var sha *string
		if e.Existed {
			sha = e.Sha256
		}
		out = append(out, map[string]any{"path": e.Path, "sha256": sha})
	}
	return out
}
