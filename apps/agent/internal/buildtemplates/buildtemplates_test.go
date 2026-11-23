package buildtemplates

import (
	"regexp"
	"strings"
	"testing"
)

func TestTemplatesEmbeddedAndHardened(t *testing.T) {
	want := map[string]struct{ port, user, cmd string }{
		"nextjs":  {"EXPOSE 3000", "USER 1001:1001", `CMD ["node", "server.js"]`},
		"nestjs":  {"EXPOSE 3000", "USER node", `CMD ["node", "dist/main"]`},
		"laravel": {"EXPOSE 80", "USER www-data", `CMD ["apache2-foreground"]`},
	}
	if len(Names) != len(want) {
		t.Fatalf("Names %v", Names)
	}
	pinned := regexp.MustCompile(`(?m)^ARG [A-Z_]+_IMAGE=[a-z0-9./-]+:[A-Za-z0-9.-]+@sha256:[a-f0-9]{64}$`)
	for _, n := range Names {
		b, err := Get(n)
		if err != nil || len(b) < 200 {
			t.Fatalf("%s: %v (%d bytes)", n, err, len(b))
		}
		s := string(b)
		w := want[n]
		for _, must := range []string{w.port, w.user, w.cmd, " AS runtime"} {
			if !strings.Contains(s, must) {
				t.Errorf("%s: missing %q", n, must)
			}
		}
		// the LAST USER must be non-root and come after the last FROM
		if strings.LastIndex(s, "\nUSER ") < strings.LastIndex(s, "\nFROM ") {
			t.Errorf("%s: final stage has no USER", n)
		}
		if regexp.MustCompile(`(?m)^USER (root|0)\b`).MatchString(s) {
			t.Errorf("%s: runs as root", n)
		}
		if strings.Count(s, "\nFROM ") < 2 {
			t.Errorf("%s: expected a multi-stage build", n)
		}
		if !pinned.MatchString(s) {
			t.Errorf("%s: base image not pinned by tag+digest", n)
		}
		// classic builder (Engine API /build version=1): no BuildKit-only syntax
		for _, bk := range []string{"# syntax", "--mount", "<<EOF", "--link", "--chmod"} {
			if strings.Contains(s, bk) {
				t.Errorf("%s: BuildKit-only syntax %q", n, bk)
			}
		}
	}
	if _, err := Get("rails"); err == nil || Valid("../nextjs") || !Valid("laravel") {
		t.Fatal("unknown template accepted")
	}
	if FileName != "Dockerfile.ppanel" {
		t.Fatal(FileName)
	}
}
