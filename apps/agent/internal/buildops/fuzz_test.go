package buildops

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
)

const fzBuildID = "0190f4c2-0000-7000-8000-00000000b11d"
const fzSha = "0123456789abcdef0123456789abcdef01234567"

func assertRel(t *testing.T, what, p string) {
	t.Helper()
	if strings.HasPrefix(p, "/") {
		t.Fatalf("%s absolute: %q", what, p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == ".git" {
			t.Fatalf("%s escapes: %q", what, p)
		}
	}
	if strings.Contains(p, "//") || strings.ContainsAny(p, "\x00\\") {
		t.Fatalf("%s not canonical: %q", what, p)
	}
}

func assertSource(t *testing.T, s GitSource) {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "git") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		t.Fatalf("git url accepted: %q", s.URL)
	}
	if strings.HasPrefix(s.URL, "-") || strings.ContainsAny(s.URL, "@ \t\n\r\x00\\%?#") || strings.Contains(s.URL, "::") {
		t.Fatalf("git url with option/transport smuggling accepted: %q", s.URL)
	}
	if s.HostPort() != strings.ToLower(u.Host) {
		t.Fatalf("host %q vs %q", s.HostPort(), u.Host)
	}
	if !CommitShaRe.MatchString(s.CommitSha) {
		t.Fatalf("sha %q", s.CommitSha)
	}
	assertRel(t, "subdir", s.Subdir)
}

// FuzzDecodeBuild: image.build decode never panics; accepted params have an
// https/git URL without credentials/options, a pinned commit, a relative
// subdir/dockerfile without .. or .git, an allowlisted network, bounded limits,
// a push repo without tag/digest and env-key build args.
func FuzzDecodeBuild(f *testing.F) {
	base := `{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"https://github.com/acme/web.git","commitSha":"` + fzSha + `","subdir":"apps/web"},"dockerfile":"Dockerfile","pushRepo":"ghcr.io/acme/web"}`
	for _, s := range []string{base,
		`{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"https://github.com/acme/web.git","commitSha":"` + fzSha + `"},"template":"nextjs","pushRepo":"lab-registry:5000/ppanel/web","network":"none","limits":{"memoryMb":256,"cpus":0.5,"timeoutSec":60},"buildArgs":{"NODE_ENV":"production"},"target":"runner","registryAuth":true}`,
		`{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"https://user:pw@github.com/acme/web.git","commitSha":"` + fzSha + `"},"dockerfile":"Dockerfile","pushRepo":"ghcr.io/acme/web"}`,
		`{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"ext::sh -c id","commitSha":"` + fzSha + `"},"dockerfile":"Dockerfile","pushRepo":"ghcr.io/acme/web"}`,
		`{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"https://github.com/acme/web.git","commitSha":"` + fzSha + `","subdir":"../../etc"},"dockerfile":"../Dockerfile","pushRepo":"ghcr.io/acme/web:latest"}`,
		`{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"https://github.com/acme/web.git","commitSha":"` + fzSha + `","subdir":".git/hooks"},"dockerfile":"Dockerfile","pushRepo":"ghcr.io/acme/web","network":"host"}`,
		`{"buildId":"` + fzBuildID + `","app":"web","source":{"url":"https://github.com/acme/web.git","commitSha":"` + fzSha + `"},"dockerfile":"Dockerfile","pushRepo":"ghcr.io/acme/web","limits":{"cpus":NaN}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeBuild(raw)
		if err != nil {
			return
		}
		assertSource(t, p.Source)
		if (p.Dockerfile == "") == (p.Template == "") {
			t.Fatal("dockerfile xor template")
		}
		if p.Dockerfile != "" {
			assertRel(t, "dockerfile", p.Dockerfile)
			if strings.HasSuffix(p.Dockerfile, "/") {
				t.Fatalf("dockerfile dir %q", p.Dockerfile)
			}
		}
		if p.Network != "default" && p.Network != "none" {
			t.Fatalf("network %q", p.Network)
		}
		if !ImageRepoRe.MatchString(p.PushRepo) || strings.ContainsAny(p.PushRepo, "@") || strings.Count(p.PushRepo, ":") > 1 {
			t.Fatalf("pushRepo %q", p.PushRepo)
		}
		if !strings.HasPrefix(p.Tag(), "build-") || len(p.Tag()) != 18 {
			t.Fatalf("tag %q", p.Tag())
		}
		l := p.Limits
		if l.MemoryMb < 256 || l.MemoryMb > 32768 || !(l.Cpus >= 0.5 && l.Cpus <= 32) || l.TimeoutSec < 60 || l.TimeoutSec > 3600 {
			t.Fatalf("limits %+v", l)
		}
		for k, v := range p.BuildArgs {
			if !containerops.EnvKeyRe.MatchString(k) || strings.IndexByte(v, 0) >= 0 || len(v) > 1024 {
				t.Fatalf("buildArg %q", k)
			}
		}
		if p.Target != "" && !targetRe.MatchString(p.Target) {
			t.Fatalf("target %q", p.Target)
		}
	})
}

func FuzzDecodeInspect(f *testing.F) {
	f.Add([]byte(`{"source":{"url":"https://github.com/acme/web.git","commitSha":"` + fzSha + `"}}`))
	f.Add([]byte(`{"source":{"url":"git://h/x","commitSha":"` + fzSha + `","subdir":"a/../b","auth":true}}`))
	f.Add([]byte(`{"source":{"url":"https://-oProxyCommand=id/x","commitSha":"` + fzSha + `"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if p, err := DecodeInspect(raw); err == nil {
			assertSource(t, p.Source)
		}
	})
}

// FuzzResolveInside: resolving a subdir/dockerfile inside a checkout full of
// hostile symlinks never yields a path outside the checkout.
func FuzzResolveInside(f *testing.F) {
	base := f.TempDir()
	root := filepath.Join(base, "src")
	out := filepath.Join(base, "outside")
	os.MkdirAll(filepath.Join(root, "app", "sub"), 0o755)
	os.MkdirAll(out, 0o755)
	os.WriteFile(filepath.Join(root, "app", "Dockerfile"), []byte("FROM x\n"), 0o644)
	os.WriteFile(filepath.Join(out, "secret"), []byte("s"), 0o600)
	os.Symlink(out, filepath.Join(root, "esc"))
	os.Symlink("../..", filepath.Join(root, "app", "up"))
	os.Symlink("/etc/passwd", filepath.Join(root, "app", "pw"))
	os.Symlink("sub", filepath.Join(root, "app", "ok"))
	rroot, _ := filepath.EvalSymlinks(root)
	for _, s := range []string{"app", "esc", "app/up", "app/pw", "app/ok", "app/up/outside/secret", "", "app/sub/../../esc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		if !relPathOK(rel) || !subdirRe.MatchString(rel) {
			return
		}
		got, err := resolveInside(root, rel)
		if err != nil {
			return
		}
		if !within(rroot, got) {
			t.Fatalf("%q resolved outside the checkout: %s", rel, got)
		}
	})
}
