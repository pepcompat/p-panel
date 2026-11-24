package sshkeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/safefs"
)

// Error codes of ssh.keys.sync (contract §2 + agent-side path/file checks).
const (
	// CodeUserInvalid: bad name, unknown in /etc/passwd, uid < 1000 and not
	// in ssh.allowedUsers, or uid 0 without ssh.allowRoot.
	CodeUserInvalid = "SSH_USER_INVALID"
	// CodeKeyInvalid: a key is not an allowed one-line public key, or its
	// recomputed fingerprint differs from the one sent.
	CodeKeyInvalid = "SSH_KEY_INVALID"
	// CodePathUnsafe: home/.ssh/authorized_keys is a symlink, not a
	// directory/regular file, owned by another user, or a hard link.
	CodePathUnsafe = "SSH_PATH_UNSAFE"
	// CodeFileMalformed: the managed block markers are unbalanced/duplicated
	// (the file is left untouched; an operator must repair it).
	CodeFileMalformed = "SSH_KEYS_FILE_MALFORMED"
)

// Contract constants.
const (
	MaxKeys        = 20
	ManagedBlockID = "ppanel"
	BeginMarker    = "# >>> ppanel managed keys (do not edit) >>>"
	EndMarker      = "# <<< ppanel managed keys <<<"
	// ManagedOptions prefixes every managed line: `restrict` disables port,
	// agent and X11 forwarding, user rc and PTY; `pty` re-enables only the PTY
	// needed by the terminal.
	ManagedOptions = "restrict,pty"
	// MaxAuthorizedKeysBytes bounds the file the agent will read and rewrite.
	MaxAuthorizedKeysBytes = 1 << 20
	DefaultPasswdPath      = "/etc/passwd"
	DefaultMinUID          = 1000
)

// UserRe is the contract's ssh user pattern.
var UserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// Key is one validated desired key.
type Key struct {
	Fingerprint string
	Key         *PublicKey
}

// SyncParams are the decoded, validated ssh.keys.sync params.
type SyncParams struct {
	User string
	Keys []Key
}

type rawKey struct {
	Fingerprint *string `json:"fingerprint"`
	PublicKey   *string `json:"publicKey"`
}

type rawParams struct {
	User           *string   `json:"user"`
	Keys           *[]rawKey `json:"keys"`
	ManagedBlockID *string   `json:"managedBlockId"`
}

func userErr(format string, a ...any) error { return jobs.Errorf(CodeUserInvalid, format, a...) }
func keyErr(format string, a ...any) error  { return jobs.Errorf(CodeKeyInvalid, format, a...) }

// DecodeSyncParams strictly decodes and validates ssh.keys.sync params:
// unknown fields and JSON null are refused; every key is re-parsed and its
// fingerprint recomputed. Pure (no filesystem access).
func DecodeSyncParams(raw json.RawMessage) (SyncParams, error) {
	var r rawParams
	if err := jobs.DecodeStrict(raw, &r); err != nil {
		return SyncParams{}, jobs.Errorf(jobs.RejectedInvalidParams, "%v", err)
	}
	if r.User == nil || r.Keys == nil || r.ManagedBlockID == nil {
		return SyncParams{}, jobs.Errorf(jobs.RejectedInvalidParams, "user, keys and managedBlockId are required (null refused)")
	}
	if *r.ManagedBlockID != ManagedBlockID {
		return SyncParams{}, jobs.Errorf(jobs.RejectedInvalidParams, "managedBlockId must be %q", ManagedBlockID)
	}
	if !UserRe.MatchString(*r.User) {
		return SyncParams{}, userErr("user must match %s", UserRe.String())
	}
	if len(*r.Keys) > MaxKeys {
		return SyncParams{}, jobs.Errorf(jobs.RejectedInvalidParams, "at most %d keys", MaxKeys)
	}
	p := SyncParams{User: *r.User, Keys: make([]Key, 0, len(*r.Keys))}
	seen := map[string]bool{}
	for i, rk := range *r.Keys {
		if rk.Fingerprint == nil || rk.PublicKey == nil {
			return SyncParams{}, keyErr("keys[%d]: fingerprint and publicKey are required", i)
		}
		if !fingerprintRe.MatchString(*rk.Fingerprint) {
			return SyncParams{}, keyErr("keys[%d]: fingerprint must be SHA256:<43 base64 chars>", i)
		}
		k, err := ParsePublicKey(*rk.PublicKey, syncKeyTypes)
		if err != nil {
			return SyncParams{}, keyErr("keys[%d]: %v", i, err)
		}
		if fp := k.Fingerprint(); fp != *rk.Fingerprint {
			return SyncParams{}, keyErr("keys[%d]: fingerprint mismatch (computed %s)", i, fp)
		}
		if seen[*rk.Fingerprint] {
			return SyncParams{}, keyErr("keys[%d]: duplicate key %s", i, *rk.Fingerprint)
		}
		seen[*rk.Fingerprint] = true
		p.Keys = append(p.Keys, Key{Fingerprint: *rk.Fingerprint, Key: k})
	}
	sort.Slice(p.Keys, func(i, j int) bool { return p.Keys[i].Fingerprint < p.Keys[j].Fingerprint })
	return p, nil
}

// Account is a /etc/passwd entry.
type Account struct {
	Name     string
	UID, GID int
	Home     string
}

// Syncer installs managed keys. The zero value uses the production defaults.
type Syncer struct {
	// PasswdPath defaults to /etc/passwd (tests override).
	PasswdPath string
	// AllowedUsers (agent config ssh.allowedUsers) may be targeted even when
	// their uid is below MinUID.
	AllowedUsers []string
	// AllowRoot (agent config ssh.allowRoot, default false) permits uid 0.
	AllowRoot bool
	// MinUID defaults to 1000 (tests override).
	MinUID int

	mu sync.Mutex
}

// LookupUser applies the user policy (contract §2) and returns the account.
func (s *Syncer) LookupUser(name string) (*Account, error) {
	if !UserRe.MatchString(name) {
		return nil, userErr("user must match %s", UserRe.String())
	}
	path := s.PasswdPath
	if path == "" {
		path = DefaultPasswdPath
	}
	// the passwd file itself must not be a symlink; its (root-owned) parent may be
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		path = filepath.Join(dir, filepath.Base(path))
	}
	b, _, err := safefs.ReadFileNoFollow(path, 8<<20)
	if err != nil {
		return nil, userErr("cannot read %s: %v", path, err)
	}
	acct, err := findPasswd(b, name)
	if err != nil {
		return nil, err
	}
	minUID := s.MinUID
	if minUID == 0 {
		minUID = DefaultMinUID
	}
	allowed := false
	for _, u := range s.AllowedUsers {
		if u == name {
			allowed = true
		}
	}
	switch {
	case acct.UID == 0 || name == "root":
		if !s.AllowRoot {
			return nil, userErr("user %s has uid 0: refused (agent config ssh.allowRoot is false)", name)
		}
	case acct.UID == 65534:
		if !allowed {
			return nil, userErr("user %s is the overflow (nobody) user", name)
		}
	case acct.UID < minUID && !allowed:
		return nil, userErr("user %s has uid %d < %d and is not in agent config ssh.allowedUsers", name, acct.UID, minUID)
	}
	if !filepath.IsAbs(acct.Home) || filepath.Clean(acct.Home) != acct.Home || acct.Home == "/" {
		return nil, userErr("user %s has no usable home directory", name)
	}
	return acct, nil
}

func findPasswd(b []byte, name string) (*Account, error) {
	var found *Account
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) != 7 || f[0] != name {
			continue
		}
		if found != nil {
			return nil, userErr("user %s appears more than once in /etc/passwd", name)
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
			return nil, userErr("user %s has a malformed passwd entry", name)
		}
		found = &Account{Name: name, UID: uid, GID: gid, Home: f[5]}
	}
	if found == nil {
		return nil, userErr("user %s does not exist in /etc/passwd", name)
	}
	return found, nil
}

// Result is the ssh.keys.sync output (contract §2; `changed` is additive).
type Result struct {
	User                string   `json:"user"`
	ManagedFingerprints []string `json:"managedFingerprints"`
	PreservedLines      int      `json:"preservedLines"`
	FileSha256          string   `json:"fileSha256"`
	Changed             bool     `json:"changed"`
}

func unsafePath(format string, a ...any) error { return jobs.Errorf(CodePathUnsafe, format, a...) }

// Sync rewrites the managed block of ~user/.ssh/authorized_keys.
func (s *Syncer) Sync(ctx context.Context, p SyncParams) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, err := s.LookupUser(p.User)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	home, err := filepath.EvalSymlinks(acct.Home)
	if err != nil {
		return nil, unsafePath("home directory of %s is not usable: %v", acct.Name, err)
	}
	hd, err := safefs.OpenDir(home)
	if err != nil {
		return nil, unsafePath("open home directory: %v", err)
	}
	defer hd.Close()
	if st, err := hd.Stat(); err != nil || !st.Mode.IsDir() || (st.UID != acct.UID && st.UID != 0) {
		return nil, unsafePath("home directory %s must be a directory owned by %s or root", home, acct.Name)
	}

	// ~/.ssh: never follow a symlink; create 0700 owned by the user.
	if err := hd.Mkdir(".ssh", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, unsafePath("create .ssh: %v", err)
	}
	sd, err := hd.Sub(".ssh")
	if err != nil {
		return nil, unsafePath(".ssh must be a real directory (symlinks refused): %v", err)
	}
	defer sd.Close()
	st, err := sd.Stat()
	if err != nil || !st.Mode.IsDir() {
		return nil, unsafePath(".ssh is not a directory")
	}
	// root-owned (e.g. just created by the agent) is taken over by the user
	if st.UID != acct.UID && st.UID != 0 {
		return nil, unsafePath(".ssh is owned by uid %d, not %s", st.UID, acct.Name)
	}
	if st.UID != acct.UID || st.GID != acct.GID {
		if err := sd.Chown(acct.UID, acct.GID); err != nil {
			return nil, unsafePath("chown .ssh: %v", err)
		}
	}
	if st.Mode.Perm() != 0o700 {
		if err := sd.Chmod(0o700); err != nil {
			return nil, unsafePath("chmod .ssh: %v", err)
		}
	}

	// authorized_keys: O_NOFOLLOW read; the fstat of the opened file decides.
	const name = "authorized_keys"
	old, info, err := sd.ReadFile(name, MaxAuthorizedKeysBytes)
	exists := true
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			exists, old = false, nil
		} else if errors.Is(err, unix.ELOOP) {
			return nil, unsafePath("authorized_keys is a symlink: refused")
		} else {
			return nil, unsafePath("authorized_keys: %v", err)
		}
	}
	if exists {
		if info.UID != acct.UID && info.UID != 0 {
			return nil, unsafePath("authorized_keys is owned by uid %d, not %s", info.UID, acct.Name)
		}
		if info.Nlink > 1 {
			return nil, unsafePath("authorized_keys has %d hard links: refused", info.Nlink)
		}
	}

	newContent, preserved, err := Render(old, p.Keys)
	if err != nil {
		return nil, err
	}
	res := &Result{User: acct.Name, ManagedFingerprints: make([]string, 0, len(p.Keys)), PreservedLines: preserved}
	for _, k := range p.Keys {
		res.ManagedFingerprints = append(res.ManagedFingerprints, k.Fingerprint)
	}
	sum := sha256.Sum256(newContent)
	res.FileSha256 = hex.EncodeToString(sum[:])

	upToDate := exists && bytes.Equal(old, newContent) && info.Mode.Perm() == 0o600 &&
		info.UID == acct.UID && info.GID == acct.GID
	if upToDate || (!exists && len(newContent) == 0) {
		return res, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := sd.WriteFileAtomic(name, newContent, 0o600, acct.UID, acct.GID, true); err != nil {
		return nil, jobs.Errorf(jobs.HandlerFailed, "write authorized_keys: %v", err)
	}
	res.Changed = true
	return res, nil
}

// ManagedLine renders one managed authorized_keys line. The key comment from
// the Center is replaced by a fixed one.
func ManagedLine(k Key) string {
	return ManagedOptions + " " + k.Key.Type + " " + k.Key.Base64 + " ppanel:" + k.Fingerprint
}

// splitLines splits b into lines that keep their "\n" terminator (the last
// one may be unterminated).
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

func lineIs(l []byte, marker string) bool {
	l = bytes.TrimSuffix(l, []byte("\n"))
	l = bytes.TrimSuffix(l, []byte("\r"))
	return string(l) == marker
}

// Render returns the new file content: every line outside the managed block
// byte-for-byte, the block replaced by the desired keys (at the same place,
// or appended when absent; removed when there are no keys). A missing final
// newline before an appended block is the only byte added to foreign lines.
func Render(old []byte, keys []Key) ([]byte, int, error) {
	lines := splitLines(old)
	begin, end := -1, -1
	for i, l := range lines {
		switch {
		case lineIs(l, BeginMarker):
			if begin >= 0 {
				return nil, 0, jobs.Errorf(CodeFileMalformed, "more than one managed block begin marker")
			}
			begin = i
		case lineIs(l, EndMarker):
			if end >= 0 {
				return nil, 0, jobs.Errorf(CodeFileMalformed, "more than one managed block end marker")
			}
			end = i
		}
	}
	if (begin < 0) != (end < 0) || (begin >= 0 && end < begin) {
		return nil, 0, jobs.Errorf(CodeFileMalformed, "unbalanced managed block markers")
	}
	var before, after [][]byte
	if begin < 0 {
		before = lines
	} else {
		before, after = lines[:begin], lines[end+1:]
	}
	var block bytes.Buffer
	if len(keys) > 0 {
		block.WriteString(BeginMarker + "\n")
		for _, k := range keys {
			block.WriteString(ManagedLine(k) + "\n")
		}
		block.WriteString(EndMarker + "\n")
	}
	var out bytes.Buffer
	for _, l := range before {
		out.Write(l)
	}
	if block.Len() > 0 && out.Len() > 0 && out.Bytes()[out.Len()-1] != '\n' {
		out.WriteByte('\n')
	}
	out.Write(block.Bytes())
	for _, l := range after {
		out.Write(l)
	}
	return out.Bytes(), len(before) + len(after), nil
}

// String implements fmt.Stringer for logs (fingerprints only, never keys).
func (p SyncParams) String() string {
	fps := make([]string, len(p.Keys))
	for i, k := range p.Keys {
		fps[i] = k.Fingerprint
	}
	return fmt.Sprintf("user=%s keys=%v", p.User, fps)
}
