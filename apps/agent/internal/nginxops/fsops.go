package nginxops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BackupRetention is how many apply backups (revisions) are kept.
const BackupRetention = 20

// Manifest kinds / statuses.
const (
	kindValidate  = "validate"
	kindApply     = "apply"
	kindPreRevert = "pre-revert"

	statusPending      = "pending"
	statusApplied      = "applied"
	statusAutoReverted = "auto-reverted"
	statusReverted     = "reverted"
)

type manifestEntry struct {
	Path        string  `json:"path"`
	Sha256      *string `json:"sha256"`
	Mode        uint32  `json:"mode"`
	UID         int     `json:"uid"`
	GID         int     `json:"gid"`
	Existed     bool    `json:"existed"`
	Blob        string  `json:"blob,omitempty"`
	AfterSha256 *string `json:"afterSha256,omitempty"`
}

type manifest struct {
	Version     int             `json:"version"`
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	RevisionID  string          `json:"revisionId,omitempty"`
	JobID       string          `json:"jobId,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
	Status      string          `json:"status"`
	Files       []manifestEntry `json:"files"`
	CreatedDirs []string        `json:"createdDirs,omitempty"` // logical paths
}

func (m *Manager) backupsDir() string { return filepath.Join(m.o.StateDir, "nginx-backups") }

func (m *Manager) backupDir(id string) string { return filepath.Join(m.backupsDir(), id) }

// syncDir fsyncs a directory so a rename/create in it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// atomicWrite writes data to path via a temp file in the same directory
// (fsync file, rename, fsync dir). chown is applied when requested.
func atomicWrite(path string, data []byte, mode os.FileMode, uid, gid int, chown bool) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".ppanel-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if chown {
		if err = f.Chown(uid, gid); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b, 0o600, 0, 0, false)
}

func (m *Manager) saveManifest(man *manifest) error {
	man.UpdatedAt = m.now().UTC()
	return writeJSONAtomic(filepath.Join(m.backupDir(man.ID), "manifest.json"), man)
}

func (m *Manager) loadManifest(id string) (*manifest, error) {
	b, err := os.ReadFile(filepath.Join(m.backupDir(id), "manifest.json"))
	if err != nil {
		return nil, err
	}
	var man manifest
	if err := json.Unmarshal(b, &man); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", id, err)
	}
	return &man, nil
}

// writeBackup stores the originals of targets (as read during preflight) and
// a manifest under <stateDir>/nginx-backups/<id>/.
func (m *Manager) writeBackup(id, kind, revisionID, jobID string, ts []*target) (*manifest, error) {
	if err := os.MkdirAll(m.backupsDir(), 0o700); err != nil {
		return nil, err
	}
	dir := m.backupDir(id)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	man := &manifest{Version: 1, ID: id, Kind: kind, RevisionID: revisionID, JobID: jobID, CreatedAt: m.now().UTC(), Status: statusPending}
	createdDirs := map[string]bool{}
	for i, t := range ts {
		e := manifestEntry{Path: t.Logical, Existed: t.Exists}
		if t.Exists {
			e.Sha256, e.Mode, e.UID, e.GID = t.Sha, uint32(t.Mode), t.UID, t.GID
			e.Blob = fmt.Sprintf("%02d.orig", i)
			if err := atomicWrite(filepath.Join(dir, e.Blob), t.Content, 0o600, 0, 0, false); err != nil {
				return nil, fmt.Errorf("backup %s: %w", t.Logical, err)
			}
		}
		if t.CreateParent {
			createdDirs[ManagedDir] = true
		}
		man.Files = append(man.Files, e)
	}
	for d := range createdDirs {
		man.CreatedDirs = append(man.CreatedDirs, d)
	}
	if err := m.saveManifest(man); err != nil {
		return nil, err
	}
	if err := syncDir(m.backupsDir()); err != nil {
		return nil, err
	}
	return man, nil
}

// writeCandidates writes new content for every target. New files get 0644
// owned by the agent; existing files keep mode/uid/gid.
func (m *Manager) writeCandidates(ts []*target, files []FileChange) error {
	for i, t := range ts {
		if t.CreateParent {
			if err := os.Mkdir(filepath.Dir(t.Phys), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("mkdir %s: %w", ManagedDir, err)
			}
			_ = syncDir(filepath.Dir(filepath.Dir(t.Phys)))
		}
		data := []byte(files[i].Content)
		var err error
		if t.Exists {
			err = atomicWrite(t.Phys, data, t.Mode, t.UID, t.GID, true)
		} else {
			err = atomicWrite(t.Phys, data, 0o644, 0, 0, false)
		}
		if err != nil {
			return fmt.Errorf("write %s: %w", t.Logical, err)
		}
	}
	return nil
}

// RestoreProblem describes one file that could not be restored/verified.
type RestoreProblem struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// restore puts every manifest entry back (rewrite originals with their
// mode/owner, delete files that did not exist) and verifies the result.
func (m *Manager) restore(man *manifest) []RestoreProblem {
	var probs []RestoreProblem
	dir := m.backupDir(man.ID)
	for _, e := range man.Files {
		phys := m.toPhys(e.Path)
		if !e.Existed {
			if err := os.Remove(phys); err != nil && !errors.Is(err, fs.ErrNotExist) {
				probs = append(probs, RestoreProblem{e.Path, "remove created file: " + err.Error()})
				continue
			}
			if _, err := os.Lstat(phys); !errors.Is(err, fs.ErrNotExist) {
				probs = append(probs, RestoreProblem{e.Path, "created file still present after removal"})
			}
			_ = syncDir(filepath.Dir(phys))
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Blob))
		if err != nil {
			probs = append(probs, RestoreProblem{e.Path, "read backup blob: " + err.Error()})
			continue
		}
		if e.Sha256 == nil || shaHex(data) != *e.Sha256 {
			probs = append(probs, RestoreProblem{e.Path, "backup blob checksum mismatch"})
			continue
		}
		if filepath.Dir(e.Path) == ManagedDir {
			// ppanel-managed may have been removed when emptied (revert undo path)
			if err := os.Mkdir(filepath.Dir(phys), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				probs = append(probs, RestoreProblem{e.Path, "recreate " + ManagedDir + ": " + err.Error()})
				continue
			}
		}
		if err := atomicWrite(phys, data, os.FileMode(e.Mode), e.UID, e.GID, true); err != nil {
			probs = append(probs, RestoreProblem{e.Path, "rewrite original: " + err.Error()})
			continue
		}
		got, err := os.ReadFile(phys)
		if err != nil || shaHex(got) != *e.Sha256 {
			probs = append(probs, RestoreProblem{e.Path, "restored checksum does not match original"})
		}
	}
	for _, d := range man.CreatedDirs {
		// only removed when empty (os.Remove fails on a non-empty dir)
		_ = os.Remove(m.toPhys(d))
	}
	return probs
}

// pruneBackups keeps the newest BackupRetention apply backups.
func (m *Manager) pruneBackups() {
	ents, err := os.ReadDir(m.backupsDir())
	if err != nil {
		return
	}
	type item struct {
		id string
		at time.Time
	}
	var applies []item
	for _, e := range ents {
		if !e.IsDir() || strings.Contains(e.Name(), ".") {
			continue
		}
		man, err := m.loadManifest(e.Name())
		if err != nil || man.Kind != kindApply {
			continue
		}
		applies = append(applies, item{e.Name(), man.CreatedAt})
	}
	if len(applies) <= BackupRetention {
		return
	}
	sort.Slice(applies, func(i, j int) bool { return applies[i].at.After(applies[j].at) })
	for _, it := range applies[BackupRetention:] {
		_ = os.RemoveAll(m.backupDir(it.id))
	}
}
