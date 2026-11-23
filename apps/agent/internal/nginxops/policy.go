package nginxops

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// maxReadBytes caps how much of an existing file the agent reads for hashing /
// backup. Files above this are refused (PATH_NOT_ALLOWED) rather than truncated.
const maxReadBytes = 8 << 20

// target is a policy-checked file.
type target struct {
	Logical         string
	Phys            string
	Exists          bool
	IsSymlink       bool
	ResolvedLogical string
	ResolvedPhys    string
	Content         []byte
	Sha             *string
	Mode            os.FileMode
	UID, GID        int
	CreateParent    bool // parent is ppanel-managed and does not exist yet
	// ResolvedInManaged: the resolved parent is under <root>/ppanel-managed.
	ResolvedInManaged bool
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func strp(s string) *string { return &s }

// toPhys maps a logical /etc/nginx/... path into the configured root.
func (m *Manager) toPhys(logical string) string {
	if logical == LogicalRoot {
		return m.root
	}
	return filepath.Join(m.root, strings.TrimPrefix(logical, LogicalRoot+"/"))
}

// resolvedRoot returns EvalSymlinks(root); a missing root means nginx is not present.
func (m *Manager) resolvedRoot() (string, error) {
	r, err := filepath.EvalSymlinks(m.root)
	if err != nil {
		return "", jobs.Errorf(CodeNginxNotPresent, "nginx config root %s not accessible", LogicalRoot)
	}
	return r, nil
}

func under(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }

// toLogical maps a resolved physical path under resolvedRoot back to /etc/nginx/...
func toLogical(resolved, rroot string) string {
	if resolved == rroot {
		return LogicalRoot
	}
	return LogicalRoot + "/" + strings.TrimPrefix(resolved, rroot+"/")
}

func (m *Manager) allowedByRoots(logical string) bool {
	if len(m.o.AllowedRoots) == 0 {
		return true
	}
	for _, r := range m.o.AllowedRoots {
		if under(logical, r) {
			return true
		}
	}
	return false
}

// resolve applies the path policy. write=true is used by validate/apply/revert
// (target must not be a symlink; creation only under ppanel-managed);
// write=false by read_files (a symlink is followed only if it stays under root).
func (m *Manager) resolve(logical string, write bool) (*target, error) {
	if err := ValidPath(logical); err != nil {
		return nil, err
	}
	if !m.allowedByRoots(logical) {
		return nil, pathErr("%s is outside the agent's nginx.allowedRoots", logical)
	}
	rroot, err := m.resolvedRoot()
	if err != nil {
		return nil, err
	}
	t := &target{Logical: logical, Phys: m.toPhys(logical)}
	parent := filepath.Dir(t.Phys)
	rparent, err := filepath.EvalSymlinks(parent)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist) && write && filepath.Dir(logical) == ManagedDir:
		// ppanel-managed itself will be created (0755) directly under root.
		if _, lerr := os.Lstat(parent); !errors.Is(lerr, fs.ErrNotExist) {
			return nil, pathErr("%s: parent directory is a dangling link", logical)
		}
		t.CreateParent = true
		rparent = filepath.Join(rroot, filepath.Base(ManagedDir))
	default:
		return nil, pathErr("%s: parent directory does not exist or is not accessible", logical)
	}
	if !under(rparent, rroot) {
		return nil, pathErr("%s: parent directory resolves outside %s", logical, LogicalRoot)
	}
	if st, err := os.Stat(rparent); err == nil && !st.IsDir() {
		return nil, pathErr("%s: parent is not a directory", logical)
	}
	resolvedPhys := filepath.Join(rparent, filepath.Base(t.Phys))
	t.ResolvedPhys = resolvedPhys
	t.ResolvedLogical = toLogical(resolvedPhys, rroot)
	if !m.allowedByRoots(t.ResolvedLogical) {
		return nil, pathErr("%s resolves outside the agent's nginx.allowedRoots", logical)
	}

	// Creation is only allowed when the parent really resolves under ppanel-managed
	// (catches a ppanel-managed symlinked to another directory).
	t.ResolvedInManaged = under(rparent, filepath.Join(rroot, filepath.Base(ManagedDir)))
	li, err := os.Lstat(t.Phys)
	if errors.Is(err, fs.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, pathErr("%s: %v", logical, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		t.IsSymlink = true
		if write {
			return nil, pathErr("%s is a symlink; edit the real file instead", logical)
		}
		real, err := filepath.EvalSymlinks(t.Phys)
		if err != nil {
			// dangling link: report as non-existent
			return t, nil
		}
		if !under(real, rroot) {
			return nil, pathErr("%s is a symlink resolving outside %s", logical, LogicalRoot)
		}
		t.ResolvedPhys = real
		t.ResolvedLogical = toLogical(real, rroot)
		if !m.allowedByRoots(t.ResolvedLogical) {
			return nil, pathErr("%s resolves outside the agent's nginx.allowedRoots", logical)
		}
	}
	if err := t.load(write); err != nil {
		return nil, err
	}
	return t, nil
}

// load reads an existing regular file (no symlink following for writes).
func (t *target) load(write bool) error {
	flags := os.O_RDONLY
	open := t.Phys
	if write {
		flags |= syscall.O_NOFOLLOW
	} else {
		open = t.ResolvedPhys
	}
	f, err := os.OpenFile(open, flags|syscall.O_NONBLOCK, 0)
	if err != nil {
		return pathErr("%s: cannot open: %v", t.Logical, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return pathErr("%s: %v", t.Logical, err)
	}
	if !st.Mode().IsRegular() {
		return pathErr("%s is not a regular file", t.Logical)
	}
	if st.Size() > maxReadBytes {
		return pathErr("%s is larger than %d bytes", t.Logical, maxReadBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		return pathErr("%s: read: %v", t.Logical, err)
	}
	if len(b) > maxReadBytes {
		return pathErr("%s is larger than %d bytes", t.Logical, maxReadBytes)
	}
	t.Exists = true
	t.Content = b
	t.Sha = strp(shaHex(b))
	t.Mode = st.Mode().Perm()
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		t.UID, t.GID = int(sys.Uid), int(sys.Gid)
	}
	return nil
}
