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

	"github.com/ppanel/ppanel/apps/agent/internal/safefs"
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
		for _, d := range t.CreateDirs {
			createdDirs[d] = true
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
//
// TOCTOU: every write happens through a directory fd opened along the
// resolved parent recorded by the policy check, with no symlink followed
// (internal/safefs). A directory swapped for a symlink after the check makes
// the write fail instead of landing outside /etc/nginx.
func (m *Manager) writeCandidates(ts []*target, files []FileChange) error {
	for i, t := range ts {
		rparent := filepath.Dir(t.ResolvedPhys)
		if err := m.createDirs(t, rparent); err != nil {
			return err
		}
		d, err := safefs.OpenDir(rparent)
		if err != nil {
			return fmt.Errorf("write %s: parent changed since the policy check: %w", t.Logical, err)
		}
		data := []byte(files[i].Content)
		name := filepath.Base(t.ResolvedPhys)
		if t.Exists {
			err = d.WriteFileAtomic(name, data, t.Mode, t.UID, t.GID, true)
		} else {
			if _, lerr := d.Lstat(name); lerr == nil {
				err = fmt.Errorf("%s appeared since the policy check", t.Logical)
			} else {
				err = d.WriteFileAtomic(name, data, 0o644, 0, 0, false)
			}
		}
		d.Close()
		if err != nil {
			return fmt.Errorf("write %s: %w", t.Logical, err)
		}
	}
	return nil
}

// createDirs creates the missing ppanel-managed[/<app>] directories of t
// (outermost first) under the resolved parent recorded at check time, each
// through a no-follow directory fd.
func (m *Manager) createDirs(t *target, rparent string) error {
	logicalParent := filepath.Dir(t.Logical)
	for _, d := range t.CreateDirs {
		rel, err := filepath.Rel(d, logicalParent)
		if err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
		rd := rparent
		if rel != "." {
			for range strings.Split(rel, "/") {
				rd = filepath.Dir(rd)
			}
		}
		pd, err := safefs.OpenDir(filepath.Dir(rd))
		if err != nil {
			return fmt.Errorf("mkdir %s: parent changed since the policy check: %w", d, err)
		}
		err = pd.Mkdir(filepath.Base(rd), 0o755)
		if err != nil && errors.Is(err, fs.ErrExist) {
			// must be a real directory now (not a symlink planted meanwhile)
			if info, lerr := pd.Lstat(filepath.Base(rd)); lerr == nil && info.Mode.IsDir() {
				err = nil
			}
		}
		_ = pd.Sync()
		pd.Close()
		if err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

// RestoreProblem describes one file that could not be restored/verified.
type RestoreProblem struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// restoreDir re-resolves the parent directory of a logical path at restore
// time, checks it is still under the real root and opens it without
// following symlinks. mkdir=true recreates missing ppanel-managed[/<app>].
func (m *Manager) restoreDir(logical string, mkdir bool) (*safefs.Dir, error) {
	rroot, err := filepath.EvalSymlinks(m.root)
	if err != nil {
		return nil, fmt.Errorf("nginx root not accessible: %w", err)
	}
	parent := filepath.Dir(m.toPhys(logical))
	rparent, err := filepath.EvalSymlinks(parent)
	if errors.Is(err, fs.ErrNotExist) && mkdir {
		// walk from the real root creating missing components (no symlinks)
		rel, rerr := filepath.Rel(LogicalRoot, filepath.Dir(logical))
		if rerr != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("parent outside %s", LogicalRoot)
		}
		d, oerr := safefs.OpenDir(rroot)
		if oerr != nil {
			return nil, oerr
		}
		for _, c := range strings.Split(rel, "/") {
			if c == "." || c == "" {
				continue
			}
			if merr := d.Mkdir(c, 0o755); merr != nil && !errors.Is(merr, fs.ErrExist) {
				d.Close()
				return nil, merr
			}
			nd, serr := d.Sub(c)
			d.Close()
			if serr != nil {
				return nil, serr
			}
			d = nd
		}
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	if !under(rparent, rroot) {
		return nil, fmt.Errorf("parent directory now resolves outside %s", LogicalRoot)
	}
	return safefs.OpenDir(rparent)
}

// restore puts every manifest entry back (rewrite originals with their
// mode/owner, delete files that did not exist) and verifies the result. All
// target-side operations go through restoreDir (re-checked, no-follow).
func (m *Manager) restore(man *manifest) []RestoreProblem {
	var probs []RestoreProblem
	dir := m.backupDir(man.ID)
	for _, e := range man.Files {
		name := filepath.Base(m.toPhys(e.Path))
		if !e.Existed {
			d, err := m.restoreDir(e.Path, false)
			if errors.Is(err, fs.ErrNotExist) {
				continue // parent gone: the created file is gone too
			}
			if err != nil {
				probs = append(probs, RestoreProblem{e.Path, "remove created file: " + err.Error()})
				continue
			}
			if err := d.Remove(name); err != nil {
				probs = append(probs, RestoreProblem{e.Path, "remove created file: " + err.Error()})
			} else if _, err := d.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
				probs = append(probs, RestoreProblem{e.Path, "created file still present after removal"})
			}
			_ = d.Sync()
			d.Close()
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
		// ppanel-managed[/<app>] may have been removed when emptied (revert undo path)
		d, err := m.restoreDir(e.Path, strings.HasPrefix(e.Path, ManagedDir+"/"))
		if err != nil {
			probs = append(probs, RestoreProblem{e.Path, "rewrite original: " + err.Error()})
			continue
		}
		if err := d.WriteFileAtomic(name, data, os.FileMode(e.Mode), e.UID, e.GID, true); err != nil {
			d.Close()
			probs = append(probs, RestoreProblem{e.Path, "rewrite original: " + err.Error()})
			continue
		}
		got, _, err := d.ReadFile(name, maxReadBytes)
		d.Close()
		if err != nil || shaHex(got) != *e.Sha256 {
			probs = append(probs, RestoreProblem{e.Path, "restored checksum does not match original"})
		}
	}
	// innermost first; only removed when empty, never through a symlink
	dirs := append([]string(nil), man.CreatedDirs...)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		if pd, err := m.restoreDir(d, false); err == nil {
			_ = pd.RemoveDir(filepath.Base(d))
			pd.Close()
		}
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
