package nginxops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests simulate the check→use race deterministically: the policy check
// (resolve/preflight) runs, then an attacker with write access somewhere under
// /etc/nginx swaps a checked directory for a symlink to a directory outside the
// root, then the agent performs the write/read/restore. Nothing outside the
// root may be written, removed or disclosed.

func swapDirForSymlink(t *testing.T, dir, target string) {
	t.Helper()
	must(t, os.Rename(dir, dir+".orig"))
	must(t, os.Symlink(target, dir))
}

func TestTOCTOUWriteThroughSwappedParent(t *testing.T) {
	e := newEnv(t)
	must(t, os.MkdirAll(e.root+"/ppanel-managed/web", 0o755))
	ts, err := e.m.resolveAll([]string{"/etc/nginx/ppanel-managed/web/route.conf"}, true)
	must(t, err)
	swapDirForSymlink(t, e.root+"/ppanel-managed/web", e.out)
	err = e.m.writeCandidates(ts, []FileChange{{Path: "/etc/nginx/ppanel-managed/web/route.conf", Content: "evil\n"}})
	if _, serr := os.Stat(filepath.Join(e.out, "route.conf")); serr == nil {
		t.Fatal("file written outside the nginx root through a swapped directory")
	}
	if err == nil {
		t.Fatal("write through a swapped directory must fail")
	}
	assertNoTempFiles(t, e.out)
}

func TestTOCTOUWriteExistingThroughSwappedParent(t *testing.T) {
	e := newEnv(t)
	must(t, os.WriteFile(e.out+"/x.conf", []byte("outside\n"), 0o644))
	ts, err := e.m.resolveAll([]string{"/etc/nginx/conf.d/x.conf"}, true)
	must(t, err)
	swapDirForSymlink(t, e.root+"/conf.d", e.out)
	err = e.m.writeCandidates(ts, []FileChange{{Path: "/etc/nginx/conf.d/x.conf", Content: "evil\n"}})
	b, _ := os.ReadFile(e.out + "/x.conf")
	if string(b) != "outside\n" {
		t.Fatalf("outside file overwritten: %q", b)
	}
	if err == nil {
		t.Fatal("write must fail")
	}
	assertNoTempFiles(t, e.out)
}

func TestTOCTOUCreateDirsThroughSwappedRootChild(t *testing.T) {
	e := newEnv(t)
	// ppanel-managed does not exist yet: it and <app> will be created.
	ts, err := e.m.resolveAll([]string{"/etc/nginx/ppanel-managed/web/route.conf"}, true)
	must(t, err)
	if len(ts[0].CreateDirs) != 2 {
		t.Fatalf("CreateDirs=%v", ts[0].CreateDirs)
	}
	// attacker plants ppanel-managed as a symlink to outside after the check
	must(t, os.Symlink(e.out, e.root+"/ppanel-managed"))
	_ = e.m.writeCandidates(ts, []FileChange{{Path: "/etc/nginx/ppanel-managed/web/route.conf", Content: "evil\n"}})
	if _, err := os.Stat(filepath.Join(e.out, "web")); err == nil {
		t.Fatal("directory created outside the root")
	}
}

func TestTOCTOUReadThroughSwappedParent(t *testing.T) {
	e := newEnv(t)
	must(t, os.WriteFile(e.out+"/a.conf", []byte("TOP SECRET\n"), 0o644))
	tg, err := e.m.resolve("/etc/nginx/sites-available/a.conf", false)
	must(t, err)
	swapDirForSymlink(t, e.root+"/sites-available", e.out)
	// re-load as read_files would (after the policy check)
	tg.Content, tg.Exists = nil, false
	if err := tg.load(false); err == nil && strings.Contains(string(tg.Content), "TOP SECRET") {
		t.Fatal("read_files disclosed a file outside the root")
	}
}

func TestTOCTOURestoreThroughSwappedParent(t *testing.T) {
	e := newEnv(t)
	ts, err := e.m.resolveAll([]string{"/etc/nginx/conf.d/x.conf"}, true)
	must(t, err)
	man, err := e.m.writeBackup("0190f4c2-0000-7000-8000-00000000b001", kindApply, "", "", ts)
	must(t, err)
	must(t, os.WriteFile(e.out+"/x.conf", []byte("outside\n"), 0o644))
	swapDirForSymlink(t, e.root+"/conf.d", e.out)
	probs := e.m.restore(man)
	b, _ := os.ReadFile(e.out + "/x.conf")
	if string(b) != "outside\n" {
		t.Fatalf("restore overwrote a file outside the root: %q", b)
	}
	if len(probs) == 0 {
		t.Fatal("restore through a swapped directory must report a problem")
	}
	assertNoTempFiles(t, e.out)
}

func TestTOCTOURestoreRemoveThroughSwappedParent(t *testing.T) {
	e := newEnv(t)
	must(t, os.MkdirAll(e.root+"/ppanel-managed/web", 0o755))
	ts, err := e.m.resolveAll([]string{"/etc/nginx/ppanel-managed/web/route.conf"}, true)
	must(t, err)
	man, err := e.m.writeBackup("0190f4c2-0000-7000-8000-00000000b002", kindApply, "", "", ts)
	must(t, err)
	// the created file "did not exist": restore deletes it. Swap the dir first.
	must(t, os.WriteFile(e.out+"/route.conf", []byte("keep me\n"), 0o644))
	swapDirForSymlink(t, e.root+"/ppanel-managed/web", e.out)
	e.m.restore(man)
	if _, err := os.Stat(e.out + "/route.conf"); err != nil {
		t.Fatal("restore deleted a file outside the root")
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), ".ppanel-tmp-") {
			t.Fatalf("temp file left outside the root: %s", en.Name())
		}
	}
}
