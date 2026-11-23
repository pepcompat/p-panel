package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden file is the cross-language contract (TS and Go must both pass it).
const goldenRel = "../../../../packages/shared-contracts/testdata/redaction-golden.json"

func TestGoldenFile(t *testing.T) {
	b, err := os.ReadFile(filepath.FromSlash(goldenRel))
	if err != nil {
		t.Fatalf("golden file must exist in the monorepo: %v", err)
	}
	var g struct {
		Cases []struct {
			In  string `json:"in"`
			Out string `json:"out"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Cases) == 0 {
		t.Fatal("no golden cases")
	}
	for i, c := range g.Cases {
		if got := Line(c.In); got != c.Out {
			t.Errorf("case %d:\n in:   %q\n got:  %q\n want: %q", i, c.In, got, c.Out)
		}
		// the Redactor with no known secrets must behave identically
		if got := New().Redact(c.In); got != c.Out {
			t.Errorf("case %d (Redactor): got %q want %q", i, got, c.Out)
		}
	}
	t.Logf("%d golden cases passed", len(g.Cases))
}

func TestPatternNamesMirrorTS(t *testing.T) {
	src, err := os.ReadFile(filepath.FromSlash("../../../../packages/shared-contracts/src/redaction.ts"))
	if err != nil {
		t.Skip("shared-contracts source not present")
	}
	for _, p := range Patterns {
		if !strings.Contains(string(src), "name: '"+p.Name+"'") {
			t.Errorf("pattern %s not in redaction.ts", p.Name)
		}
	}
	if n := strings.Count(string(src), "    name: '"); n != len(Patterns) {
		t.Errorf("TS has %d patterns, Go %d", n, len(Patterns))
	}
}

func TestKnownSecretValues(t *testing.T) {
	r := New()
	r.Linger = 0
	release := r.Register("s3cr3t-value-XYZ", "short", "s3cr3t-value-XYZ-longer")
	if r.Known() != 2 {
		t.Fatalf("known=%d (short value must be ignored)", r.Known())
	}
	in := "env APP_DB=s3cr3t-value-XYZ-longer and s3cr3t-value-XYZ; short stays"
	got := r.Redact(in)
	want := "env APP_DB=[REDACTED] and [REDACTED]; short stays"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	release()
	release() // idempotent
	if r.Known() != 0 {
		t.Fatalf("known after release=%d", r.Known())
	}
	if got := r.Redact("plain s3cr3t-value-XYZ"); got != "plain s3cr3t-value-XYZ" {
		t.Fatalf("released secret still redacted: %q", got)
	}
}

func TestRegisterRefCounted(t *testing.T) {
	r := New()
	r.Linger = 0
	a := r.Register("shared-secret-1")
	b := r.Register("shared-secret-1")
	a()
	if r.Redact("x shared-secret-1") != "x [REDACTED]" {
		t.Fatal("value released while still registered by another job")
	}
	b()
	if r.Known() != 0 {
		t.Fatal("not released")
	}
}

func TestLingerKeepsValue(t *testing.T) {
	r := New()
	rel := r.Register("linger-secret-value")
	rel()
	if r.Redact("linger-secret-value") != Replacement {
		t.Fatal("value must linger after release")
	}
}

func TestExtraCases(t *testing.T) {
	cases := map[string]string{
		"GET /?api_key=sk_live_abc123456 HTTP/1.1":               "GET /?api_key=[REDACTED] HTTP/1.1",
		`{"level":"info","token":"abcdef"}`:                      `{"level":"info","token":"[REDACTED]"}`,
		"proxy-authorization: Basic dXNlcjpwYXNz":                "proxy-authorization: [REDACTED]",
		"https://user:pw@example.com/x and ASIAABCDEFGHIJKLMNOP": "https://user:[REDACTED]@example.com/x and [REDACTED]",
	}
	for in, want := range cases {
		if got := Line(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}
