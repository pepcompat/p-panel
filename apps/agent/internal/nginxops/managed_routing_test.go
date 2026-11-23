package nginxops

import (
	"encoding/json"
	"os"
	"testing"
)

const (
	revR1 = "aaaaaaaa-1111-4111-8111-111111111111"
	revR2 = "aaaaaaaa-2222-4222-8222-222222222222"
)

// P4: exactly one extra creatable path outside ppanel-managed.
func TestManagedIncludeFileCreatableOnlyThatPath(t *testing.T) {
	mk := func(p string) json.RawMessage {
		return json.RawMessage(`{"revisionId":"` + revR1 + `","files":[{"path":"` + p + `","expectedSha256Before":null,"content":"include /etc/nginx/ppanel-managed/*/*.conf;\n"}]}`)
	}
	if _, err := DecodeApply(mk(ManagedIncludeFile)); err != nil {
		t.Fatalf("include file refused at decode: %v", err)
	}
	for _, p := range []string{"/etc/nginx/conf.d/other.conf", "/etc/nginx/conf.d/ppanel-managed.conf.bak", "/etc/nginx/ppanel-managed.conf",
		"/etc/nginx/sites-enabled/ppanel-managed.conf", "/etc/nginx/conf.d/xppanel-managed.conf"} {
		_, err := DecodeApply(mk(p))
		if code(t, err) != CodePathNotAllowed {
			t.Fatalf("%s: %v", p, err)
		}
	}

	e := newEnv(t)
	before := tree(e.root)
	// filesystem policy: conf.d/other.conf still refused, nothing written
	_, err := e.m.Apply(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{{Path: "/etc/nginx/conf.d/other.conf", Content: "x"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("conf.d/other.conf: %v", err)
	}
	sameTree(t, before, tree(e.root))

	inc := "include /etc/nginx/ppanel-managed/*/*.conf;\n"
	out, err := e.m.Apply(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{{Path: ManagedIncludeFile, Content: inc}}})
	must(t, err)
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}
	if b, _ := os.ReadFile(e.root + "/conf.d/ppanel-managed.conf"); string(b) != inc {
		t.Fatalf("include content %q", b)
	}
	sha := shaHex([]byte(inc))
	_, err = e.m.Revert(ctxJob(revR2), RevertParams{RevisionID: revR1, ExpectedCurrent: []ExpectedFile{{Path: ManagedIncludeFile, Sha256: &sha}}})
	must(t, err)
	sameTree(t, before, tree(e.root))
}

func TestManagedIncludeFileRefusedThroughSymlinkedConfD(t *testing.T) {
	e := newEnv(t)
	must(t, os.Rename(e.root+"/conf.d", e.root+"/conf-real"))
	must(t, os.Symlink("conf-real", e.root+"/conf.d"))
	_, err := e.m.Validate(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{{Path: ManagedIncludeFile, Content: "x"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("symlinked conf.d: %v", err)
	}
	if _, err := os.Stat(e.root + "/conf-real/ppanel-managed.conf"); err == nil {
		t.Fatal("created through symlinked conf.d")
	}
}

// Routes live in ppanel-managed/<app>/route.conf: the app dir (and ppanel-managed)
// are created on apply and removed again on revert; deeper nesting is refused.
func TestManagedAppRouteDirCreatedAndReverted(t *testing.T) {
	e := newEnv(t)
	before := tree(e.root)
	route := "upstream ppanel_shop { server 127.0.0.1:20001; }\n"
	_, err := e.m.Apply(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{
		{Path: ManagedIncludeFile, Content: "include /etc/nginx/ppanel-managed/*/*.conf;\n"},
		{Path: "/etc/nginx/ppanel-managed/shop/route.conf", Content: route},
	}})
	must(t, err)
	if b, _ := os.ReadFile(e.root + "/ppanel-managed/shop/route.conf"); string(b) != route {
		t.Fatalf("route %q", b)
	}
	st, _ := os.Stat(e.root + "/ppanel-managed/shop")
	if st == nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("app dir mode %v", st)
	}
	shaI, shaR := shaHex([]byte("include /etc/nginx/ppanel-managed/*/*.conf;\n")), shaHex([]byte(route))
	_, err = e.m.Revert(ctxJob(revR2), RevertParams{RevisionID: revR1, ExpectedCurrent: []ExpectedFile{
		{Path: ManagedIncludeFile, Sha256: &shaI}, {Path: "/etc/nginx/ppanel-managed/shop/route.conf", Sha256: &shaR}}})
	must(t, err)
	sameTree(t, before, tree(e.root)) // app dir + ppanel-managed removed

	_, err = e.m.Validate(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/a/b/c.conf", Content: "x"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("deep nesting: %v", err)
	}
	// app dir symlinked elsewhere inside root → creation refused
	must(t, os.MkdirAll(e.root+"/ppanel-managed", 0o755))
	must(t, os.Symlink("../sites-available", e.root+"/ppanel-managed/evil"))
	_, err = e.m.Validate(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{{Path: "/etc/nginx/ppanel-managed/evil/route.conf", Content: "x"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("symlinked app dir: %v", err)
	}
}
