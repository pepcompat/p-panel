package nginxops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
)

const fuzzRID = "11111111-2222-4333-8444-555555555555"

func assertValidPath(t *testing.T, p string) {
	t.Helper()
	if ValidPath(p) != nil || !strings.HasPrefix(p, LogicalRoot+"/") || hasDotDotSeg(p) || strings.Contains(p, "//") ||
		strings.ContainsAny(p, "\x00\\ ") || filepath.Clean(p) != p || len(p) > len(LogicalRoot)+1+200 {
		t.Fatalf("policy-violating path accepted: %q", p)
	}
}

func hasDotDotSeg(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == ".." || s == "." {
			return true
		}
	}
	return false
}

// FuzzValidPath: an accepted path is canonical, under /etc/nginx/, no "..",
// no "//", no NUL, bounded length.
func FuzzValidPath(f *testing.F) {
	for _, s := range []string{"/etc/nginx/nginx.conf", "/etc/nginx/../passwd", "/etc/nginx//a", "/etc/nginx/a/", "/etc/nginx/./a",
		"/etc/nginx/a\x00b", "/etc/nginxx/a", "/etc/nginx/ppanel-managed/web/route.conf", "/etc/nginx/...", "/etc/nginx/a/..b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if ValidPath(p) == nil {
			assertValidPath(t, p)
		}
	})
}

// FuzzDecodeNginxParams drives all four strict decoders with arbitrary JSON.
func FuzzDecodeNginxParams(f *testing.F) {
	seeds := []string{
		`{"paths":["/etc/nginx/nginx.conf"]}`,
		`{"revisionId":"` + fuzzRID + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"x"}]}`,
		`{"revisionId":"` + fuzzRID + `","files":[{"path":"/etc/nginx/conf.d/x.conf","expectedSha256Before":"` + strings.Repeat("a", 64) + `","content":"y"}],"postchecks":[{"hostHeader":"a.example","path":"/","scheme":"https","port":443,"expectStatus":[200]}]}`,
		`{"revisionId":"` + fuzzRID + `","expectedCurrent":[{"path":"/etc/nginx/a.conf","sha256":null}]}`,
		`{"revisionId":"` + fuzzRID + `","files":[{"path":"/etc/nginx/sites-available/new.conf","expectedSha256Before":null,"content":"x"}]}`,
		`{"revisionId":"` + fuzzRID + `","files":[{"path":"/etc/nginx/ppanel-managed/a.conf","expectedSha256Before":null,"content":"a\u0000"}]}`,
		`{"paths":["/etc/nginx/../etc/shadow"],"extra":1}`, `[]`, `null`, `{"paths":null}`,
	}
	for i, s := range seeds {
		f.Add(uint8(i), []byte(s))
	}
	f.Fuzz(func(t *testing.T, which uint8, raw []byte) {
		check := func(files []FileChange) {
			if len(files) < 1 || len(files) > MaxFiles {
				t.Fatalf("file count %d accepted", len(files))
			}
			seen := map[string]bool{}
			for _, fc := range files {
				assertValidPath(t, fc.Path)
				if seen[fc.Path] {
					t.Fatalf("duplicate path accepted: %s", fc.Path)
				}
				seen[fc.Path] = true
				if len(fc.Content) > MaxFileBytes || !utf8.ValidString(fc.Content) || strings.IndexByte(fc.Content, 0) >= 0 {
					t.Fatalf("bad content accepted for %s", fc.Path)
				}
				if fc.ExpectedSha256Before == nil && !CreatableLogical(fc.Path) {
					t.Fatalf("creation outside ppanel-managed accepted: %s", fc.Path)
				}
				if fc.ExpectedSha256Before != nil && !shaRe.MatchString(*fc.ExpectedSha256Before) {
					t.Fatalf("bad sha accepted")
				}
			}
		}
		switch which % 4 {
		case 0:
			p, err := DecodeRead(raw)
			if err == nil {
				if len(p.Paths) == 0 || len(p.Paths) > MaxFiles {
					t.Fatalf("read path count %d accepted", len(p.Paths))
				}
				for _, x := range p.Paths {
					assertValidPath(t, x)
				}
			}
		case 1:
			if p, err := DecodeValidate(raw); err == nil {
				check(p.Files)
				if !uuidRe.MatchString(p.RevisionID) || p.RevisionID != strings.ToLower(p.RevisionID) {
					t.Fatalf("revisionId %q", p.RevisionID)
				}
			}
		case 2:
			if p, err := DecodeApply(raw); err == nil {
				check(p.Files)
				if len(p.Postchecks) > MaxPostchecks {
					t.Fatalf("%d postchecks accepted", len(p.Postchecks))
				}
				for _, pc := range p.Postchecks {
					if !hostHeaderRe.MatchString(pc.HostHeader) || !probePathRe.MatchString(pc.Path) || (pc.Scheme != "http" && pc.Scheme != "https") ||
						pc.Port < 1 || pc.Port > 65535 || strings.ContainsAny(pc.HostHeader+pc.Path, "\r\n @") {
						t.Fatalf("bad postcheck accepted: %+v", pc)
					}
				}
			}
		case 3:
			if p, err := DecodeRevert(raw); err == nil {
				for _, e := range p.ExpectedCurrent {
					assertValidPath(t, e.Path)
				}
			}
		}
	})
}

// FuzzResolve applies the filesystem path policy to arbitrary logical paths
// against a fixture tree full of hostile symlinks. Whatever resolves must stay
// under the real root; writes never target a symlink; creation is only
// possible under ppanel-managed or the one include file.
func FuzzResolve(f *testing.F) {
	base := f.TempDir()
	root := filepath.Join(base, "nginx")
	out := filepath.Join(base, "outside")
	for _, d := range []string{root + "/sites-available", root + "/sites-enabled", root + "/conf.d", root + "/ppanel-managed/web", out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			f.Fatal(err)
		}
	}
	os.WriteFile(root+"/nginx.conf", []byte("events {}\n"), 0o644)
	os.WriteFile(root+"/sites-available/a.conf", []byte("server {}\n"), 0o644)
	os.WriteFile(out+"/secret", []byte("s\n"), 0o600)
	os.Symlink("../sites-available/a.conf", root+"/sites-enabled/a.conf")
	os.Symlink(out, root+"/escape-dir")
	os.Symlink(out+"/secret", root+"/conf.d/escape.conf")
	os.Symlink("/", root+"/rootlink")
	os.Symlink(out, root+"/ppanel-managed/evil")
	os.Symlink("loop2", root+"/loop1")
	os.Symlink("loop1", root+"/loop2")
	os.Symlink("../../..", root+"/conf.d/up")
	rroot, _ := filepath.EvalSymlinks(root)
	f.Setenv("PPANEL_AGENT_TEST_NGINX_ROOT", "1")
	m, err := New(Options{Root: root, StateDir: filepath.Join(base, "state"), Exec: execx.System{}})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/a.conf", "/etc/nginx/escape-dir/secret",
		"/etc/nginx/conf.d/escape.conf", "/etc/nginx/rootlink/etc/passwd", "/etc/nginx/ppanel-managed/evil/x.conf",
		"/etc/nginx/ppanel-managed/new/route.conf", "/etc/nginx/loop1/x", "/etc/nginx/conf.d/up/etc/passwd",
		"/etc/nginx/conf.d/ppanel-managed.conf", "/etc/nginx/ppanel-managed/a/b/c.conf"} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, logical string, write bool) {
		tg, err := m.resolve(logical, write)
		if err != nil {
			return
		}
		assertValidPath(t, logical)
		if !under(tg.ResolvedPhys, rroot) {
			t.Fatalf("%q resolved outside root: %s", logical, tg.ResolvedPhys)
		}
		if write && tg.IsSymlink {
			t.Fatalf("write target is a symlink: %q", logical)
		}
		if tg.Exists {
			if real, err := filepath.EvalSymlinks(tg.ResolvedPhys); err != nil || !under(real, rroot) {
				t.Fatalf("%q content read from outside root (%s)", logical, real)
			}
		}
		if write && !tg.Exists && tg.creatable() {
			if !CreatableLogical(logical) || !(tg.ResolvedInManaged || tg.ResolvedLogical == ManagedIncludeFile || tg.ResolvedLogical == GatewayIncludeFile) {
				t.Fatalf("creatable outside the creation rule: %q -> %s", logical, tg.ResolvedLogical)
			}
			if strings.HasPrefix(tg.ResolvedPhys, out) {
				t.Fatalf("creation would land outside: %s", tg.ResolvedPhys)
			}
		}
	})
}
