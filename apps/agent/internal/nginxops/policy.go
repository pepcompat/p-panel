package nginxops

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/safefs"
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
	// CreateDirs are missing logical directories (outermost first) that will be
	// created: only ppanel-managed itself and ppanel-managed/<app>.
	CreateDirs []string
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
	case errors.Is(err, fs.ErrNotExist) && write && managedDepthOK(logical):
		// ppanel-managed and/or ppanel-managed/<app> will be created (0755).
		base := filepath.Dir(logical)
		var missing []string
		for {
			if _, lerr := os.Lstat(m.toPhys(base)); !errors.Is(lerr, fs.ErrNotExist) {
				break
			}
			missing = append([]string{base}, missing...)
			if base == ManagedDir || base == GatewayDir {
				base = LogicalRoot
				break
			}
			base = filepath.Dir(base)
		}
		rbase, berr := filepath.EvalSymlinks(m.toPhys(base))
		if berr != nil || len(missing) == 0 {
			return nil, pathErr("%s: parent directory is a dangling link", logical)
		}
		if st, serr := os.Stat(rbase); serr != nil || !st.IsDir() {
			return nil, pathErr("%s: parent is not a directory", logical)
		}
		t.CreateDirs = missing
		rel, _ := filepath.Rel(base, filepath.Dir(logical))
		rparent = filepath.Join(rbase, rel)
	case errors.Is(err, fs.ErrNotExist) && !write && managedDepthOK(logical):
		// read_files of a managed file whose directory does not exist yet (e.g. the
		// first gateway plan): report it as absent instead of refusing the read.
		// Nothing is read; the resolved path is the lexical one under the real root.
		return &target{Logical: logical, Phys: t.Phys, ResolvedLogical: logical,
			ResolvedPhys: filepath.Join(rroot, strings.TrimPrefix(logical, LogicalRoot+"/"))}, nil
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
	if strings.HasPrefix(logical, GatewayDir+"/") {
		// P9 gateway files: the resolved parent must be exactly the real ppanel-gateway dir (depth 1).
		t.ResolvedInManaged = rparent == filepath.Join(rroot, filepath.Base(GatewayDir))
	} else {
		t.ResolvedInManaged = under(rparent, filepath.Join(rroot, filepath.Base(ManagedDir)))
	}
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

// managedDepthOK: logical is ppanel-managed/<file>, ppanel-managed/<dir>/<file>
// or (P9) ppanel-gateway/<file> (depth 1 only).
func managedDepthOK(logical string) bool {
	if rest, ok := strings.CutPrefix(logical, ManagedDir+"/"); ok {
		return rest != "" && strings.Count(rest, "/") <= 1
	}
	if rest, ok := strings.CutPrefix(logical, GatewayDir+"/"); ok {
		return rest != "" && !strings.Contains(rest, "/")
	}
	return false
}

// creatable is the filesystem creation rule: the resolved parent is really
// ppanel-managed (or a direct subdirectory of it), or the target is exactly
// ManagedIncludeFile in the real conf.d directory (not reached via a symlink).
func (t *target) creatable() bool {
	if managedDepthOK(t.Logical) {
		return t.ResolvedInManaged
	}
	for _, inc := range []string{ManagedIncludeFile, GatewayIncludeFile} {
		if t.Logical == inc && t.ResolvedLogical == inc && !t.IsSymlink {
			return true
		}
	}
	return false
}

// load reads an existing regular file. It opens the RESOLVED physical path
// with no symlink in any component (internal/safefs), so a directory swapped
// for a symlink after the policy check cannot redirect the read outside root.
// For writes the target itself must not be a symlink (checked in resolve and
// again here by O_NOFOLLOW).
func (t *target) load(write bool) error {
	_ = write
	b, info, err := safefs.ReadFileNoFollow(t.ResolvedPhys, maxReadBytes)
	if err != nil {
		if info.Size > maxReadBytes {
			return pathErr("%s is larger than %d bytes", t.Logical, maxReadBytes)
		}
		if info.Mode != 0 && !info.Mode.IsRegular() {
			return pathErr("%s is not a regular file", t.Logical)
		}
		return pathErr("%s: cannot open: %v", t.Logical, err)
	}
	t.Exists = true
	t.Content = b
	t.Sha = strp(shaHex(b))
	t.Mode = info.Mode.Perm()
	t.UID, t.GID = info.UID, info.GID
	return nil
}
