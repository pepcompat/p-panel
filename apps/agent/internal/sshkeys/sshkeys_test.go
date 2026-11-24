package sshkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

func mkfifo(p string) error { return unix.Mkfifo(p, 0o600) }

// Vectors generated with OpenSSH ssh-keygen (fingerprints from `ssh-keygen -lf`).
const (
	vecEd25519   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbIlEAqqM0ypCUxbhGVxnF3qPc8PCXMdCYEqLjrl9q1 vec"
	vecEd25519FP = "SHA256:R4iRQRZj8Jlz6b8IoSGQneNlAqkeMxvZNuxVwjVcHZg"
	vecECDSA     = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOSRzbayyrgqLbfYVmLMogk+WkotJv/2pxWvaPPc3AUHGPAoQHuC3TVgqw/Ug5eY8LaG5UkXd3Lp1lJcknpe6Aw= vec"
	vecECDSAFP   = "SHA256:w3V8zTBQtDRcwMp1crD2386l74CC46ED83/VA1mrfYw"
)

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func edKey(t testing.TB) (line, fp string) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " test", Fingerprint(blob)
}

// rsaKey builds a structurally valid ssh-rsa blob with an n of the given size
// (validation only checks structure and size, never primality).
func rsaKey(bits int) (line, fp string) {
	n := make([]byte, bits/8)
	n[0] = 0x80                 // exactly `bits` bits
	n = append([]byte{0}, n...) // mpint: positive with leading 0
	n[len(n)-1] = 1
	blob := append(sshString([]byte("ssh-rsa")), sshString([]byte{1, 0, 1})...)
	blob = append(blob, sshString(n)...)
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob), Fingerprint(blob)
}

func TestFingerprintVectors(t *testing.T) {
	for line, want := range map[string]string{vecEd25519: vecEd25519FP, vecECDSA: vecECDSAFP} {
		k, err := ParsePublicKey(line, syncKeyTypes)
		if err != nil {
			t.Fatal(err)
		}
		if k.Fingerprint() != want {
			t.Fatalf("fingerprint %s want %s", k.Fingerprint(), want)
		}
	}
}

func params(user string, keys ...[2]string) json.RawMessage {
	ks := []map[string]string{}
	for _, k := range keys {
		ks = append(ks, map[string]string{"publicKey": k[0], "fingerprint": k[1]})
	}
	b, _ := json.Marshal(map[string]any{"user": user, "keys": ks, "managedBlockId": "ppanel"})
	return b
}

func code(err error) string {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je.Code
	}
	if err == nil {
		return ""
	}
	return "OTHER:" + err.Error()
}

func TestDecodeMaliciousInputs(t *testing.T) {
	ed, edFP := edKey(t)
	ed2, ed2FP := edKey(t)
	rsa3072, rsa3072FP := rsaKey(3072)
	rsa2048, rsa2048FP := rsaKey(2048)
	edB64 := strings.Fields(ed)[1]
	blobED, _ := base64.StdEncoding.DecodeString(edB64)
	// ed25519 blob relabelled as ssh-rsa
	wrongType := "ssh-rsa " + edB64
	trailing := append(append([]byte{}, blobED...), 0)
	trailingLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(trailing)
	many := make([][2]string, 21)
	for i := range many {
		many[i][0], many[i][1] = edKey(t)
	}
	cases := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"valid ed25519", params("ops", [2]string{ed, edFP}), ""},
		{"valid ecdsa vector", params("ops", [2]string{vecECDSA, vecECDSAFP}), ""},
		{"valid rsa 3072", params("ops", [2]string{rsa3072, rsa3072FP}), ""},
		{"empty key set (remove all)", params("ops"), ""},
		{"newline injection", params("ops", [2]string{ed + "\nssh-ed25519 " + strings.Fields(ed2)[1], edFP}), CodeKeyInvalid},
		{"CR injection", params("ops", [2]string{ed + "\rx", edFP}), CodeKeyInvalid},
		{"NUL in key", params("ops", [2]string{ed + "\x00", edFP}), CodeKeyInvalid},
		{"tab in comment", params("ops", [2]string{strings.Replace(ed, " test", " a\tb", 1), edFP}), CodeKeyInvalid},
		{"options: command", params("ops", [2]string{`command="/bin/sh" ` + ed, edFP}), CodeKeyInvalid},
		{"options: restrict only", params("ops", [2]string{"restrict " + ed, edFP}), CodeKeyInvalid},
		{"options: no-pty,permitopen", params("ops", [2]string{`permitopen="10.0.0.1:22",no-pty ` + ed, edFP}), CodeKeyInvalid},
		{"options: environment", params("ops", [2]string{`environment="LD_PRELOAD=/tmp/x" ` + ed, edFP}), CodeKeyInvalid},
		{"leading space", params("ops", [2]string{" " + ed, edFP}), CodeKeyInvalid},
		{"double space before comment", params("ops", [2]string{strings.Replace(ed, " test", "  test", 1), edFP}), CodeKeyInvalid},
		{"unsupported type ssh-dss", params("ops", [2]string{"ssh-dss " + edB64, edFP}), CodeKeyInvalid},
		{"cert type", params("ops", [2]string{"ssh-ed25519-cert-v01@openssh.com " + edB64, edFP}), CodeKeyInvalid},
		{"private key PEM", params("ops", [2]string{"-----BEGIN OPENSSH PRIVATE KEY-----", edFP}), CodeKeyInvalid},
		{"private key multi-line", params("ops", [2]string{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", edFP}), CodeKeyInvalid},
		{"blob type mismatch", params("ops", [2]string{wrongType, edFP}), CodeKeyInvalid},
		{"trailing blob data", params("ops", [2]string{trailingLine, Fingerprint(trailing)}), CodeKeyInvalid},
		{"unpadded base64", params("ops", [2]string{strings.TrimSuffix(vecECDSA, "= vec"), vecECDSAFP}), CodeKeyInvalid},
		{"non-canonical padding bits", params("ops", [2]string{strings.Replace(vecECDSA, "6Aw= vec", "6Ax=", 1), vecECDSAFP}), CodeKeyInvalid},
		{"base64 garbage", params("ops", [2]string{"ssh-ed25519 !!!!", edFP}), CodeKeyInvalid},
		{"rsa 2048 too small", params("ops", [2]string{rsa2048, rsa2048FP}), CodeKeyInvalid},
		{"fingerprint mismatch", params("ops", [2]string{ed, ed2FP}), CodeKeyInvalid},
		{"fingerprint malformed", params("ops", [2]string{ed, "MD5:aa:bb"}), CodeKeyInvalid},
		{"fingerprint padded", params("ops", [2]string{ed, edFP + "="}), CodeKeyInvalid},
		{"duplicate key", params("ops", [2]string{ed, edFP}, [2]string{ed, edFP}), CodeKeyInvalid},
		{"21 keys", params("ops", many...), jobs.RejectedInvalidParams},
		{"user uppercase", params("Ops", [2]string{ed, edFP}), CodeUserInvalid},
		{"user path", params("../root", [2]string{ed, edFP}), CodeUserInvalid},
		{"user option", params("-oProxyCommand", [2]string{ed, edFP}), CodeUserInvalid},
		{"user newline", params("ops\nroot", [2]string{ed, edFP}), CodeUserInvalid},
		{"user too long", params(strings.Repeat("a", 33), [2]string{ed, edFP}), CodeUserInvalid},
		{"user empty", params("", [2]string{ed, edFP}), CodeUserInvalid},
		{"unknown field", json.RawMessage(`{"user":"ops","keys":[],"managedBlockId":"ppanel","path":"/root/.ssh/authorized_keys"}`), jobs.RejectedInvalidParams},
		{"unknown key field", json.RawMessage(`{"user":"ops","keys":[{"publicKey":"x","fingerprint":"y","options":"no-pty"}],"managedBlockId":"ppanel"}`), jobs.RejectedInvalidParams},
		{"privateKey field refused", json.RawMessage(`{"user":"ops","keys":[],"managedBlockId":"ppanel","privateKey":"x"}`), jobs.RejectedInvalidParams},
		{"null user", json.RawMessage(`{"user":null,"keys":[],"managedBlockId":"ppanel"}`), jobs.RejectedInvalidParams},
		{"null keys", json.RawMessage(`{"user":"ops","keys":null,"managedBlockId":"ppanel"}`), jobs.RejectedInvalidParams},
		{"null key entry", json.RawMessage(`{"user":"ops","keys":[null],"managedBlockId":"ppanel"}`), CodeKeyInvalid},
		{"missing block id", json.RawMessage(`{"user":"ops","keys":[]}`), jobs.RejectedInvalidParams},
		{"other block id", json.RawMessage(`{"user":"ops","keys":[],"managedBlockId":"other"}`), jobs.RejectedInvalidParams},
	}
	_ = ed2FP
	for _, c := range cases {
		_, err := DecodeSyncParams(c.raw)
		if got := code(err); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// ---------------- Sync ----------------

type env struct {
	t      *testing.T
	s      *Syncer
	home   string
	passwd string
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", "ops")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	passwd := filepath.Join(dir, "passwd")
	content := fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\n"+
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"svc:x:%d:%d::%s:/bin/sh\n"+
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"+
		"ops:x:%d:%d::%s:/bin/bash\n"+
		"nohome:x:%d:%d::relative:/bin/sh\n", 50, gid, home, uid, gid, home, uid, gid)
	if err := os.WriteFile(passwd, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	minUID := uid
	if minUID > 100 {
		minUID = 100
	}
	if minUID == 0 { // running as root (CI container)
		minUID = 1
	}
	return &env{t: t, s: &Syncer{PasswdPath: passwd, MinUID: minUID}, home: home, passwd: passwd}
}

func (e *env) sync(user string, keys ...[2]string) (*Result, error) {
	p, err := DecodeSyncParams(params(user, keys...))
	if err != nil {
		e.t.Fatalf("decode: %v", err)
	}
	return e.s.Sync(context.Background(), p)
}

func (e *env) ak() string { return filepath.Join(e.home, ".ssh", "authorized_keys") }

func (e *env) read() string {
	b, err := os.ReadFile(e.ak())
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func TestSyncInstallsManagedBlock(t *testing.T) {
	e := newEnv(t)
	ed, edFP := edKey(t)
	res, err := e.sync("ops", [2]string{ed, edFP}, [2]string{vecECDSA, vecECDSAFP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.User != "ops" || len(res.ManagedFingerprints) != 2 || res.PreservedLines != 0 {
		t.Fatalf("result %+v", res)
	}
	st, _ := os.Stat(filepath.Join(e.home, ".ssh"))
	if st.Mode().Perm() != 0o700 || !st.IsDir() {
		t.Fatalf(".ssh mode %v", st.Mode())
	}
	fst, _ := os.Stat(e.ak())
	if fst.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys mode %v", fst.Mode())
	}
	got := e.read()
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if lines[0] != BeginMarker || lines[len(lines)-1] != EndMarker || len(lines) != 4 {
		t.Fatalf("content:\n%s", got)
	}
	for _, l := range lines[1:3] {
		if !strings.HasPrefix(l, "restrict,pty ") {
			t.Fatalf("managed line without restrict,pty: %q", l)
		}
		if strings.Contains(l, "PRIVATE") {
			t.Fatal("private material")
		}
	}
	sum := sha256.Sum256([]byte(got))
	if res.FileSha256 != hex.EncodeToString(sum[:]) {
		t.Fatal("fileSha256 mismatch")
	}
	// the Center's comment is not copied; the line carries the fingerprint
	if strings.Contains(got, " vec") || !strings.Contains(got, "ppanel:"+vecECDSAFP) {
		t.Fatalf("comment handling:\n%s", got)
	}
}

func TestSyncPreservesForeignLinesByteForByte(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	ed, edFP := edKey(t)
	ed2, ed2FP := edKey(t)
	head := "# my own keys\r\nssh-ed25519 AAAAforeign1 alice@laptop\r\n\n  # indented comment\n" +
		`command="/usr/bin/backup",no-pty ssh-rsa AAAAforeign2 backup` + "\n"
	tail := "ssh-ed25519 AAAAforeign3 after-block" // no final newline
	old := head + BeginMarker + "\nrestrict,pty " + ed2 + "\n" + EndMarker + "\n" + tail
	if err := os.WriteFile(e.ak(), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := e.sync("ops", [2]string{ed, edFP})
	if err != nil {
		t.Fatal(err)
	}
	got := e.read()
	want := head + BeginMarker + "\n" + ManagedLine(mustKey(t, ed, edFP)) + "\n" + EndMarker + "\n" + tail
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
	if res.PreservedLines != 6 || !res.Changed {
		t.Fatalf("result %+v", res)
	}
	if strings.Contains(got, strings.Fields(ed2)[1]) {
		t.Fatal("old managed key still present")
	}
	_ = ed2FP
	// .ssh mode tightened, file mode 0600
	if st, _ := os.Stat(filepath.Join(e.home, ".ssh")); st.Mode().Perm() != 0o700 {
		t.Fatalf(".ssh mode %v", st.Mode())
	}
	if st, _ := os.Stat(e.ak()); st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode())
	}
	// removing all keys removes the block and keeps every foreign byte
	if _, err := e.sync("ops"); err != nil {
		t.Fatal(err)
	}
	if got := e.read(); got != head+tail {
		t.Fatalf("after removal:\n%q", got)
	}
}

func TestSyncAppendsAfterUnterminatedLine(t *testing.T) {
	e := newEnv(t)
	os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700)
	os.WriteFile(e.ak(), []byte("ssh-ed25519 AAAAforeign x"), 0o600)
	ed, edFP := edKey(t)
	if _, err := e.sync("ops", [2]string{ed, edFP}); err != nil {
		t.Fatal(err)
	}
	if got := e.read(); !strings.HasPrefix(got, "ssh-ed25519 AAAAforeign x\n"+BeginMarker+"\n") {
		t.Fatalf("got %q", got)
	}
}

func mustKey(t *testing.T, line, fp string) Key {
	k, err := ParsePublicKey(line, syncKeyTypes)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Fingerprint: fp, Key: k}
}

func TestSyncIdempotent(t *testing.T) {
	e := newEnv(t)
	a, aFP := edKey(t)
	b, bFP := edKey(t)
	r1, err := e.sync("ops", [2]string{a, aFP}, [2]string{b, bFP})
	if err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(e.ak())
	r2, err := e.sync("ops", [2]string{b, bFP}, [2]string{a, aFP}) // order does not matter
	if err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(e.ak())
	if r2.Changed || r1.FileSha256 != r2.FileSha256 || !os.SameFile(st1, st2) {
		t.Fatalf("second sync rewrote the file: %+v %+v", r1, r2)
	}
	// no file and no keys: nothing is created
	e2 := newEnv(t)
	r, err := e2.sync("ops")
	if err != nil || r.Changed {
		t.Fatalf("%v %+v", err, r)
	}
	if _, err := os.Stat(e2.ak()); !os.IsNotExist(err) {
		t.Fatal("authorized_keys created for an empty key set")
	}
}

func TestSyncRefusesSymlinksAndHardlinks(t *testing.T) {
	ed, edFP := edKey(t)
	t.Run("symlinked .ssh", func(t *testing.T) {
		e := newEnv(t)
		victim := filepath.Join(t.TempDir(), "rootssh")
		os.MkdirAll(victim, 0o700)
		os.WriteFile(filepath.Join(victim, "authorized_keys"), []byte("root-key\n"), 0o600)
		if err := os.Symlink(victim, filepath.Join(e.home, ".ssh")); err != nil {
			t.Fatal(err)
		}
		_, err := e.sync("ops", [2]string{ed, edFP})
		if code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
		if b, _ := os.ReadFile(filepath.Join(victim, "authorized_keys")); string(b) != "root-key\n" {
			t.Fatal("symlink target modified")
		}
		if ents, _ := os.ReadDir(victim); len(ents) != 1 {
			t.Fatal("temp file left in symlink target")
		}
	})
	t.Run("symlinked authorized_keys", func(t *testing.T) {
		e := newEnv(t)
		os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700)
		victim := filepath.Join(t.TempDir(), "shadow")
		os.WriteFile(victim, []byte("secret\n"), 0o600)
		os.Symlink(victim, e.ak())
		_, err := e.sync("ops", [2]string{ed, edFP})
		if code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "secret\n" {
			t.Fatal("symlink target modified")
		}
		if fi, _ := os.Lstat(e.ak()); fi.Mode()&os.ModeSymlink == 0 {
			t.Fatal("symlink replaced")
		}
	})
	t.Run("hardlinked authorized_keys", func(t *testing.T) {
		e := newEnv(t)
		os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700)
		victim := filepath.Join(e.home, "shadow-copy") // same filesystem
		os.WriteFile(victim, []byte("secret\n"), 0o600)
		if err := os.Link(victim, e.ak()); err != nil {
			t.Skip("hard links unsupported:", err)
		}
		_, err := e.sync("ops", [2]string{ed, edFP})
		if code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "secret\n" {
			t.Fatal("hard link target modified")
		}
	})
	t.Run(".ssh is a file", func(t *testing.T) {
		e := newEnv(t)
		os.WriteFile(filepath.Join(e.home, ".ssh"), []byte("x"), 0o600)
		if _, err := e.sync("ops", [2]string{ed, edFP}); code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("authorized_keys is a directory", func(t *testing.T) {
		e := newEnv(t)
		os.MkdirAll(e.ak(), 0o700)
		if _, err := e.sync("ops", [2]string{ed, edFP}); code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("authorized_keys is a fifo", func(t *testing.T) {
		e := newEnv(t)
		os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700)
		if err := mkfifo(e.ak()); err != nil {
			t.Skip(err)
		}
		if _, err := e.sync("ops", [2]string{ed, edFP}); code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversized authorized_keys", func(t *testing.T) {
		e := newEnv(t)
		os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700)
		os.WriteFile(e.ak(), bytes.Repeat([]byte("#\n"), MaxAuthorizedKeysBytes), 0o600)
		if _, err := e.sync("ops", [2]string{ed, edFP}); code(err) != CodePathUnsafe {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSyncMalformedBlockLeavesFileUntouched(t *testing.T) {
	ed, edFP := edKey(t)
	for name, content := range map[string]string{
		"begin only":   "a\n" + BeginMarker + "\nrestrict,pty x\n",
		"end only":     EndMarker + "\n",
		"end before":   EndMarker + "\n" + BeginMarker + "\n",
		"two blocks":   BeginMarker + "\n" + EndMarker + "\n" + BeginMarker + "\n" + EndMarker + "\n",
		"double begin": BeginMarker + "\n" + BeginMarker + "\n" + EndMarker + "\n",
	} {
		e := newEnv(t)
		os.MkdirAll(filepath.Join(e.home, ".ssh"), 0o700)
		os.WriteFile(e.ak(), []byte(content), 0o600)
		if _, err := e.sync("ops", [2]string{ed, edFP}); code(err) != CodeFileMalformed {
			t.Fatalf("%s: got %v", name, err)
		}
		if e.read() != content {
			t.Fatalf("%s: file modified", name)
		}
	}
}

func TestUserPolicy(t *testing.T) {
	e := newEnv(t)
	for user, want := range map[string]string{
		"ops":     "",
		"root":    CodeUserInvalid, // uid 0, allowRoot false
		"daemon":  CodeUserInvalid, // uid 1 < min, not allowed
		"svc":     CodeUserInvalid, // uid 50 < min
		"nobody":  CodeUserInvalid,
		"ghost":   CodeUserInvalid, // not in passwd
		"nohome":  CodeUserInvalid, // relative home
		"Bad":     CodeUserInvalid,
		"a:b":     CodeUserInvalid,
		"ops\n":   CodeUserInvalid,
		"-ops":    CodeUserInvalid,
		"o/../ps": CodeUserInvalid,
	} {
		if _, err := e.s.LookupUser(user); code(err) != want {
			t.Errorf("%q: got %v want %q", user, err, want)
		}
	}
	allowed := &Syncer{PasswdPath: e.passwd, MinUID: e.s.MinUID, AllowedUsers: []string{"svc", "nobody"}}
	for _, u := range []string{"svc", "nobody"} {
		if _, err := allowed.LookupUser(u); err != nil {
			t.Errorf("%s in allowedUsers refused: %v", u, err)
		}
	}
	// allowedUsers never unlocks root
	ar := &Syncer{PasswdPath: e.passwd, AllowedUsers: []string{"root"}}
	if _, err := ar.LookupUser("root"); code(err) != CodeUserInvalid {
		t.Fatalf("root via allowedUsers: %v", err)
	}
	r := &Syncer{PasswdPath: e.passwd, AllowRoot: true}
	if a, err := r.LookupUser("root"); err != nil || a.UID != 0 || a.Home != "/root" {
		t.Fatalf("allowRoot: %v %+v", err, a)
	}
	// a second uid-0 account is root too
	p2 := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(p2, []byte("toor:x:0:0::/root:/bin/sh\ndup:x:1000:1000::/home/dup:/bin/sh\ndup:x:1001:1001::/home/dup2:/bin/sh\n"), 0o644)
	s2 := &Syncer{PasswdPath: p2}
	if _, err := s2.LookupUser("toor"); code(err) != CodeUserInvalid {
		t.Fatalf("uid-0 alias accepted: %v", err)
	}
	if _, err := s2.LookupUser("dup"); code(err) != CodeUserInvalid {
		t.Fatalf("duplicate passwd entry accepted: %v", err)
	}
	// sync for a refused user writes nothing
	ed, edFP := edKey(t)
	if _, err := e.sync("svc", [2]string{ed, edFP}); code(err) != CodeUserInvalid {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.home, ".ssh")); !os.IsNotExist(err) {
		t.Fatal(".ssh created for a refused user")
	}
}

func TestRenderNeverEmitsUnrestrictedManagedLines(t *testing.T) {
	ed, edFP := edKey(t)
	out, _, err := Render(nil, []Key{mustKey(t, ed, edFP), mustKey(t, vecEd25519, vecEd25519FP)})
	if err != nil {
		t.Fatal(err)
	}
	in := false
	for _, l := range strings.Split(string(out), "\n") {
		switch {
		case l == BeginMarker:
			in = true
		case l == EndMarker:
			in = false
		case in && !strings.HasPrefix(l, "restrict,pty ssh-"):
			t.Fatalf("bad managed line %q", l)
		}
	}
}

// ---------------- facts ----------------

func TestCollectFacts(t *testing.T) {
	dir := t.TempDir()
	if CollectFacts(dir) != nil {
		t.Fatal("facts without host keys must be nil")
	}
	os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), []byte(vecEd25519+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ssh_host_ecdsa_key.pub"), []byte(vecECDSA+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ssh_host_rsa_key.pub"), []byte("garbage\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600)
	// a symlinked .pub is ignored (never followed)
	other := filepath.Join(t.TempDir(), "x.pub")
	os.WriteFile(other, []byte(vecECDSA+"\n"), 0o644)
	os.Symlink(other, filepath.Join(dir, "ssh_host_dsa_key.pub"))

	f := CollectFacts(dir)
	if f == nil || len(f.HostKeys) != 2 || f.Port != nil {
		t.Fatalf("facts %+v", f)
	}
	if f.HostKeys[0] != (HostKey{"ecdsa-sha2-nistp256", vecECDSAFP}) || f.HostKeys[1] != (HostKey{"ssh-ed25519", vecEd25519FP}) {
		t.Fatalf("host keys %+v", f.HostKeys)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), `"port"`) {
		t.Fatalf("json %s", b)
	}

	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("# Port 1\nPasswordAuthentication no\n"), 0o644)
	if p := CollectFacts(dir).Port; p == nil || *p != 22 {
		t.Fatalf("default port %v", p)
	}
	os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755)
	os.WriteFile(filepath.Join(dir, "sshd_config.d", "10-port.conf"), []byte("port=2222\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Include sshd_config.d/*.conf\nPort 22\nMatch User x\n  Port 9\n"), 0o644)
	if p := CollectFacts(dir).Port; p == nil || *p != 2222 {
		t.Fatalf("include port %v", p)
	}
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Match User x\nPort 9\n"), 0o644)
	if p := CollectFacts(dir).Port; p == nil || *p != 22 {
		t.Fatalf("port inside Match must be ignored: %v", p)
	}
	// include loop is bounded
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Include sshd_config\n"), 0o644)
	if p := CollectFacts(dir).Port; p == nil || *p != 22 {
		t.Fatalf("include loop %v", p)
	}
}

func FuzzDecodeSyncParams(f *testing.F) {
	f.Add([]byte(params("ops", [2]string{vecEd25519, vecEd25519FP})))
	f.Add([]byte(`{"user":"ops","keys":[{"publicKey":"command=\"x\" ssh-ed25519 AAAA","fingerprint":"SHA256:x"}],"managedBlockId":"ppanel"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeSyncParams(raw)
		if err != nil {
			return
		}
		if !UserRe.MatchString(p.User) || len(p.Keys) > MaxKeys {
			t.Fatalf("accepted %+v", p)
		}
		out, _, err := Render(nil, p.Keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Keys) == 0 {
			if len(out) != 0 {
				t.Fatalf("empty key set rendered %q", out)
			}
			return
		}
		for _, l := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			if l != BeginMarker && l != EndMarker && !strings.HasPrefix(l, "restrict,pty ") {
				t.Fatalf("unrestricted line %q", l)
			}
		}
		if n := strings.Count(string(out), "\n"); len(p.Keys) > 0 && n != len(p.Keys)+2 {
			t.Fatalf("line injection: %d lines for %d keys", n, len(p.Keys))
		}
	})
}
