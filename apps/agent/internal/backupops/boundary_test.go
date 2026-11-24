package backupops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSnap = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func manifestJSON(path string) string {
	return `{"target":0,"type":"paths","snapshotId":"` + testSnap + `","files":[{"path":"` + path + `","size":1,"sha256":"` +
		strings.Repeat("a", 64) + `"}],"fileCount":1,"truncated":false}`
}

// TestManifestPathTraversalRejected: "/backup/" used to exempt a manifest
// path from the canonical-path check, so "/backup/../etc/shadow" was accepted
// and verifyFiles hashed (and reported the sha256 of) a file outside the restore.
func TestManifestPathTraversalRejected(t *testing.T) {
	for _, p := range []string{"/backup/../etc/shadow", "/backup/../../root/.ssh/id_rsa", "/backup/./x", "/backup//x", "/backup/x/", "/proc/self/environ", "relative"} {
		raw := `{"repo":{"url":"https://repo.example:8000/srv1/","repositoryId":"0190f4c2-0000-7000-8000-000000000001"},"snapshotId":"` + testSnap[:8] + `","manifest":` + manifestJSON(p) + `}`
		if _, err := DecodeVerify(json.RawMessage(raw)); err == nil {
			t.Errorf("manifest path %q accepted by backup.verify", p)
		}
	}
	if _, err := DecodeVerify(json.RawMessage(`{"repo":{"url":"https://repo.example:8000/srv1/","repositoryId":"0190f4c2-0000-7000-8000-000000000001"},"snapshotId":"` + testSnap[:8] + `","manifest":` + manifestJSON("/backup/data/a.txt") + `}`)); err != nil {
		t.Fatalf("legit /backup/ path refused: %v", err)
	}
}

// TestVerifyFilesNeverFollowsOutOfRoot: a restored symlink (or an intermediate
// symlinked dir) pointing outside the staging root is reported missing, and the
// sha256 of the outside file never appears in the result.
func TestVerifyFilesNeverFollowsOutOfRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "staging")
	outside := filepath.Join(base, "outside")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "srv"), 0o700))
	must(os.MkdirAll(outside, 0o700))
	secret := []byte("root:$6$hash:19000:0:99999:7:::\n")
	must(os.WriteFile(filepath.Join(outside, "shadow"), secret, 0o600))
	sum := sha256.Sum256(secret)
	secretSha := hex.EncodeToString(sum[:])
	must(os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(root, "srv", "link")))
	must(os.Symlink(outside, filepath.Join(root, "dirlink")))
	must(os.WriteFile(filepath.Join(root, "srv", "ok.txt"), []byte("ok"), 0o600))
	okSum := sha256.Sum256([]byte("ok"))
	exp := []ManifestFile{
		{Path: "/srv/link", Size: 1, Sha256: strings.Repeat("b", 64)},
		{Path: "/dirlink/shadow", Size: 1, Sha256: strings.Repeat("b", 64)},
		{Path: "/srv/../../outside/shadow", Size: 1, Sha256: strings.Repeat("b", 64)},
		{Path: "/srv/ok.txt", Size: 2, Sha256: hex.EncodeToString(okSum[:])},
	}
	v := verifyFiles(exp, root, nil)
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), secretSha) {
		t.Fatalf("outside file hash leaked: %s", b)
	}
	if v.OK || len(v.Mismatches) != 3 {
		t.Fatalf("want 3 mismatches (missing), got %s", b)
	}
	for _, m := range v.Mismatches {
		if m.Reason != "missing" || m.Actual != "" {
			t.Fatalf("unexpected mismatch %+v", m)
		}
	}
}

// TestStagingDirRefusesSymlinkedRestoresDir: <stateDir>/restores planted as a
// symlink (to "/" or anywhere) must not redirect a staging restore.
func TestStagingDirRefusesSymlinkedRestoresDir(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(state, 0o700)
	os.MkdirAll(outside, 0o700)
	if err := os.Symlink(outside, filepath.Join(state, "restores")); err != nil {
		t.Fatal(err)
	}
	m := New(Options{StateDir: state})
	target := m.StagingDir("0190f4c2-0000-7000-8000-000000000001")
	if err := m.makeStagingDir(target); err == nil {
		t.Fatal("staging dir created through a symlinked restores dir")
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("created %v outside the state dir", ents)
	}
	// a pre-planted symlink as the staging dir itself is refused as existing
	os.Remove(filepath.Join(state, "restores"))
	os.MkdirAll(filepath.Join(state, "restores"), 0o700)
	target2 := m.StagingDir("0190f4c2-0000-7000-8000-000000000002")
	if err := os.Symlink("/", target2); err != nil {
		t.Fatal(err)
	}
	if err := m.makeStagingDir(target2); err == nil || !os.IsExist(err) {
		t.Fatalf("pre-planted staging symlink: %v", err)
	}
	// the legitimate case works and yields a real 0700 directory
	target3 := m.StagingDir("0190f4c2-0000-7000-8000-000000000003")
	if err := m.makeStagingDir(target3); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(target3)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", st, err)
	}
}

// TestHashFileNeverFollowsSymlink: the backup-time manifest hasher refuses a
// file that was swapped for a symlink (or a fifo) after the walk saw it.
func TestHashFileNeverFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "real"), []byte("x"), 0o600)
	os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link"))
	if _, _, err := hashFile(filepath.Join(dir, "link")); err == nil {
		t.Fatal("hashFile followed a symlink")
	}
	if _, _, err := hashFile(filepath.Join(dir, "real")); err != nil {
		t.Fatal(err)
	}
}

// TestArgvNoOptionInjection: every value a Center can put into restic argv
// either follows "--" or a flag that takes it as a value, and validators refuse
// leading '-' everywhere a value stands alone.
func TestArgvNoOptionInjection(t *testing.T) {
	if CheckHostPath("-x") == nil || CheckHostPath("--password-command=id") == nil {
		t.Fatal("leading '-' host path accepted")
	}
	for _, e := range []string{"-x", "--exclude-file=/etc/shadow"} {
		raw := `{"type":"paths","paths":["/srv"],"excludes":["` + e + `"]}`
		if _, err := decodeTarget(json.RawMessage(raw)); err == nil {
			t.Errorf("exclude %q accepted", e)
		}
	}
	for _, v := range []string{"-h", "--file=/etc/passwd", "-U"} {
		if checkDBFields("db", v, "u", "PW", 0) == nil || checkDBFields("db", "d", v, "PW", 0) == nil {
			t.Errorf("db value %q accepted", v)
		}
		if tagRe.MatchString(v) || snapshotRe.MatchString(v) {
			t.Errorf("tag/snapshot %q accepted", v)
		}
	}
	for _, u := range []string{"-o", "--option=x", "rest:-x", "rest:http://-host/x"} {
		if (RepoRef{URL: u, RepositoryID: "0190f4c2-0000-7000-8000-000000000001"}).validate() == nil && strings.HasPrefix(u, "-") {
			t.Errorf("repo url %q accepted", u)
		}
	}
	// restoreArgs: every element starting with '-' is one of the fixed flags;
	// Center-supplied values (snapshot, target, includes) never do.
	flags := map[string]bool{"--no-cache": true, "-r": true, "--target": true, "--json": true, "--include": true,
		"--dry-run": true, "-vv": true, "--verify": true, "--delete": true}
	a := restoreArgs(RepoRef{URL: "https://r.example/x", RepositoryID: "0190f4c2-0000-7000-8000-000000000001"}, testSnap[:8], true, "/tmp/s", []string{"/srv/a", "/srv/b"}, true, true, true)
	for _, x := range a {
		if strings.HasPrefix(x, "-") && !flags[x] {
			t.Errorf("unexpected option %q in %v", x, a)
		}
	}
}
