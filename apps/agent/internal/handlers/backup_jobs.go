package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/backupops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// P6 backup/restore jobs (docs/AGENT_PROTOCOL.md "Backups and restores (P6)").
// Always registered; they run only when the LOCAL config enabled backups and a
// host restic >= 0.17 was verified (otherwise RESTIC_UNAVAILABLE before ack).

func backupManager(d *Deps) (*backupops.Manager, error) {
	if d.Backups == nil {
		return nil, jobs.Errorf(backupops.CodeResticUnavailable, "backups are not enabled on this agent (backup.enabled is false or restic >= 0.17 is missing)")
	}
	return d.Backups, nil
}

// BackupRun implements backup.run.
type BackupRun struct{ d *Deps }

func (*BackupRun) Type() string   { return "backup.run" }
func (*BackupRun) Mutating() bool { return true }

// Timeout exceeds the maximum limits.timeoutSec (86400 s) plus manifest/cleanup.
func (*BackupRun) Timeout() time.Duration { return 25 * time.Hour }
func (*BackupRun) Decode(raw json.RawMessage) (any, error) {
	return backupops.DecodeBackup(raw)
}
func (h *BackupRun) Preflight(params any) error {
	m, err := backupManager(h.d)
	if err != nil {
		return err
	}
	return m.PreflightBackup(params.(backupops.BackupParams))
}
func (h *BackupRun) Run(ctx context.Context, params any) (any, error) {
	m, err := backupManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Backup(ctx, params.(backupops.BackupParams))
}

// BackupSnapshots implements backup.snapshots (read-only).
type BackupSnapshots struct{ d *Deps }

func (*BackupSnapshots) Type() string           { return "backup.snapshots" }
func (*BackupSnapshots) Mutating() bool         { return false }
func (*BackupSnapshots) Timeout() time.Duration { return 11 * time.Minute }
func (*BackupSnapshots) Decode(raw json.RawMessage) (any, error) {
	return backupops.DecodeSnapshots(raw)
}
func (h *BackupSnapshots) Preflight(any) error {
	m, err := backupManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckRestic()
}
func (h *BackupSnapshots) Run(ctx context.Context, params any) (any, error) {
	m, err := backupManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Snapshots(ctx, params.(backupops.SnapshotsParams))
}

// BackupVerify implements backup.verify (read-only on the source).
type BackupVerify struct{ d *Deps }

func (*BackupVerify) Type() string           { return "backup.verify" }
func (*BackupVerify) Mutating() bool         { return false }
func (*BackupVerify) Timeout() time.Duration { return 6*time.Hour + 5*time.Minute }
func (*BackupVerify) Decode(raw json.RawMessage) (any, error) {
	return backupops.DecodeVerify(raw)
}
func (h *BackupVerify) Preflight(any) error {
	m, err := backupManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckRestic()
}
func (h *BackupVerify) Run(ctx context.Context, params any) (any, error) {
	m, err := backupManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Verify(ctx, params.(backupops.VerifyParams))
}

// RestoreRun implements restore.run.
type RestoreRun struct{ d *Deps }

func (*RestoreRun) Type() string           { return "restore.run" }
func (*RestoreRun) Mutating() bool         { return true }
func (*RestoreRun) Timeout() time.Duration { return 25 * time.Hour }
func (*RestoreRun) Decode(raw json.RawMessage) (any, error) {
	return backupops.DecodeRestore(raw)
}
func (h *RestoreRun) Preflight(params any) error {
	m, err := backupManager(h.d)
	if err != nil {
		return err
	}
	return m.PreflightRestore(params.(backupops.RestoreParams))
}
func (h *RestoreRun) Run(ctx context.Context, params any) (any, error) {
	m, err := backupManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Restore(ctx, params.(backupops.RestoreParams))
}
