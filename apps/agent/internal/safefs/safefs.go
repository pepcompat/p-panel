//go:build unix

// Package safefs performs filesystem operations that cannot be redirected by
// a concurrent directory→symlink swap (TOCTOU). A directory is opened by
// walking its RESOLVED absolute path from "/" one component at a time with
// openat(O_NOFOLLOW|O_DIRECTORY); every later operation is relative to that
// directory fd (openat/renameat/unlinkat/mkdirat/fstatat with
// AT_SYMLINK_NOFOLLOW). If any component is (or becomes) a symlink the walk
// fails with ELOOP/ENOTDIR instead of following it.
//
// Callers resolve and policy-check a path first (filepath.EvalSymlinks +
// "under root"), then use safefs with that resolved path: the policy decision
// and the operation are bound to the same directory inode.
package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Dir is an open directory handle obtained without following symlinks.
type Dir struct {
	fd   int
	path string
}

// ErrNotCanonical is returned for relative or unclean paths / names.
var ErrNotCanonical = errors.New("safefs: path must be clean and absolute")

func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("safefs: invalid name %q", name)
	}
	return nil
}

// OpenDir opens the directory at the resolved absolute path p, refusing any
// symlink component.
func OpenDir(p string) (*Dir, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.IndexByte(p, 0) >= 0 {
		return nil, ErrNotCanonical
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: "/", Err: err}
	}
	if p == "/" {
		return &Dir{fd: fd, path: p}, nil
	}
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		nfd, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, &os.PathError{Op: "openat", Path: p, Err: err}
		}
		fd = nfd
	}
	return &Dir{fd: fd, path: p}, nil
}

// Path returns the path the directory was opened by.
func (d *Dir) Path() string { return d.path }

// Close releases the directory fd.
func (d *Dir) Close() error { return unix.Close(d.fd) }

// Sub opens child directory name (no symlink following).
func (d *Dir) Sub(name string) (*Dir, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: filepath.Join(d.path, name), Err: err}
	}
	return &Dir{fd: fd, path: filepath.Join(d.path, name)}, nil
}

// Mkdir creates child directory name (EEXIST is returned as fs.ErrExist).
func (d *Dir) Mkdir(name string, mode os.FileMode) error {
	if err := validName(name); err != nil {
		return err
	}
	if err := unix.Mkdirat(d.fd, name, uint32(mode.Perm())); err != nil {
		return &os.PathError{Op: "mkdirat", Path: filepath.Join(d.path, name), Err: err}
	}
	return nil
}

// Info is the lstat result of a directory entry.
type Info struct {
	Mode     os.FileMode
	Size     int64
	UID, GID int
	// Nlink is the hard-link count (a regular file with Nlink > 1 may be a
	// hard link to a file elsewhere on the same filesystem).
	Nlink uint64
}

func infoOf(st *unix.Stat_t) Info {
	return Info{Mode: fileMode(st), Size: st.Size, UID: int(st.Uid), GID: int(st.Gid), Nlink: uint64(st.Nlink)}
}

func fileMode(st *unix.Stat_t) os.FileMode {
	m := os.FileMode(st.Mode & 0o777)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		m |= os.ModeDir
	case unix.S_IFLNK:
		m |= os.ModeSymlink
	case unix.S_IFREG:
	default:
		m |= os.ModeIrregular
	}
	return m
}

// Lstat stats child name without following a symlink.
func (d *Dir) Lstat(name string) (Info, error) {
	if err := validName(name); err != nil {
		return Info{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return Info{}, &os.PathError{Op: "fstatat", Path: filepath.Join(d.path, name), Err: err}
	}
	return infoOf(&st), nil
}

// ReadFile reads regular file name (no symlink following) up to max bytes;
// larger files fail. Non-regular files (fifo, device) are refused without
// blocking (O_NONBLOCK).
func (d *Dir) ReadFile(name string, max int64) ([]byte, Info, error) {
	if err := validName(name); err != nil {
		return nil, Info{}, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, Info{}, &os.PathError{Op: "openat", Path: filepath.Join(d.path, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, Info{}, err
	}
	info := infoOf(&st)
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, info, fmt.Errorf("safefs: %s is not a regular file", f.Name())
	}
	if st.Size > max {
		return nil, info, fmt.Errorf("safefs: %s is larger than %d bytes", f.Name(), max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, info, err
	}
	if int64(len(b)) > max {
		return nil, info, fmt.Errorf("safefs: %s is larger than %d bytes", f.Name(), max)
	}
	return b, info, nil
}

// Remove unlinks child name (a symlink is removed itself, never followed).
// A missing entry is not an error.
func (d *Dir) Remove(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	if err := unix.Unlinkat(d.fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "unlinkat", Path: filepath.Join(d.path, name), Err: err}
	}
	return nil
}

// RemoveDir removes empty child directory name (missing = ok).
func (d *Dir) RemoveDir(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	if err := unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "unlinkat", Path: filepath.Join(d.path, name), Err: err}
	}
	return nil
}

// Stat returns the attributes of the open directory itself (fstat).
func (d *Dir) Stat() (Info, error) {
	var st unix.Stat_t
	if err := unix.Fstat(d.fd, &st); err != nil {
		return Info{}, &os.PathError{Op: "fstat", Path: d.path, Err: err}
	}
	return infoOf(&st), nil
}

// Chmod sets the permission bits of the open directory itself (fchmod).
func (d *Dir) Chmod(mode os.FileMode) error {
	if err := unix.Fchmod(d.fd, uint32(mode.Perm())); err != nil {
		return &os.PathError{Op: "fchmod", Path: d.path, Err: err}
	}
	return nil
}

// Chown sets the owner of the open directory itself (fchown).
func (d *Dir) Chown(uid, gid int) error {
	if err := unix.Fchown(d.fd, uid, gid); err != nil {
		return &os.PathError{Op: "fchown", Path: d.path, Err: err}
	}
	return nil
}

// Sync fsyncs the directory.
func (d *Dir) Sync() error {
	if err := unix.Fsync(d.fd); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return nil
}

// WriteFileAtomic writes data to child name through a fresh temp file in the
// same directory (O_EXCL|O_NOFOLLOW), fsync, renameat, fsync(dir). chown
// applies uid/gid. The temp file is removed on failure.
func (d *Dir) WriteFileAtomic(name string, data []byte, mode os.FileMode, uid, gid int, chown bool) (err error) {
	if err := validName(name); err != nil {
		return err
	}
	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return err
	}
	tmp := ".ppanel-tmp-" + hex.EncodeToString(rb[:])
	fd, err := unix.Openat(d.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "openat", Path: filepath.Join(d.path, tmp), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(d.path, tmp))
	defer func() {
		if err != nil {
			_ = unix.Unlinkat(d.fd, tmp, 0)
		}
	}()
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(mode.Perm()); err != nil {
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
	if err = unix.Renameat(d.fd, tmp, d.fd, name); err != nil {
		return &os.PathError{Op: "renameat", Path: filepath.Join(d.path, name), Err: err}
	}
	return d.Sync()
}

// ReadFileNoFollow reads the regular file at resolved absolute path p
// (no symlink in any component), up to max bytes.
func ReadFileNoFollow(p string, max int64) ([]byte, Info, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return nil, Info{}, ErrNotCanonical
	}
	d, err := OpenDir(filepath.Dir(p))
	if err != nil {
		return nil, Info{}, err
	}
	defer d.Close()
	return d.ReadFile(filepath.Base(p), max)
}

// CopyNoFollow streams the regular file at p (no symlink in any component)
// into w and returns the byte count.
func CopyNoFollow(p string, w io.Writer) (int64, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return 0, ErrNotCanonical
	}
	d, err := OpenDir(filepath.Dir(p))
	if err != nil {
		return 0, err
	}
	defer d.Close()
	name := filepath.Base(p)
	if err := validName(name); err != nil {
		return 0, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, &os.PathError{Op: "openat", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, fmt.Errorf("safefs: %s is not a regular file", p)
	}
	return io.Copy(w, f)
}
