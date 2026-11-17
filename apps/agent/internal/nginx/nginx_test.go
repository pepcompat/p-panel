package nginx

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/nginx/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLexerQuotesCommentsBracesMarkers(t *testing.T) {
	src := "# configuration file /a.conf:\nfoo \"x;{y}\" 'it\\'s' bar#notcomment; # c { ;\nbaz ${var}x {\n}\n"
	toks, err := Lex(src, "stdin")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range toks {
		got = append(got, tk.Value)
	}
	want := []string{"/a.conf", "foo", "x;{y}", "it's", "bar#notcomment", ";", "baz", "${var}x", "{", "}"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tokens\n got %q\nwant %q", got, want)
	}
	if toks[1].File != "/a.conf" || toks[1].Line != 1 || toks[6].Line != 2 {
		t.Fatalf("positions wrong: %+v %+v", toks[1], toks[6])
	}
}

func byName(r *Report, name string) *ServerBlock {
	for _, s := range r.Servers {
		for _, n := range s.ServerNames {
			if n.Name == name {
				return s
			}
		}
	}
	return nil
}

func TestNginxTDumpFixture(t *testing.T) {
	r, err := ParseAndAnalyze(load(t, "nginx-T.txt"), "nginx-T")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 12 {
		t.Errorf("files=%d want 12", len(r.Files))
	}
	if len(r.Servers) != 8 {
		t.Fatalf("servers=%d want 8", len(r.Servers))
	}

	// multiple server_name + provenance through include
	ex := byName(r, "www.example.com")
	if ex == nil || len(ex.ServerNames) != 2 || ex.Root != "/var/www/example" {
		t.Fatalf("example: %+v", ex)
	}
	if ex.Provenance.File != "/etc/nginx/sites-enabled/example.com" || ex.Provenance.Line != 1 ||
		len(ex.Provenance.IncludedFrom) != 1 || ex.Provenance.IncludedFrom[0] != "/etc/nginx/nginx.conf:20" {
		t.Errorf("provenance %+v", ex.Provenance)
	}
	if len(ex.Listen) != 2 || ex.Listen[1].Address != "[::]" || ex.Listen[1].Port != 80 {
		t.Errorf("listen %+v", ex.Listen)
	}

	// wildcard + regex names
	w := byName(r, "*.example.org")
	if w == nil {
		t.Fatal("wildcard server missing")
	}
	kinds := map[string]string{}
	for _, n := range w.ServerNames {
		kinds[n.Name] = n.Kind
	}
	if kinds["*.example.org"] != "wildcard" || kinds[".example.net"] != "wildcard" || kinds[`~^(?<sub>[a-z]+)\.example\.io$`] != "regex" {
		t.Errorf("kinds %v", kinds)
	}
	if w.ConfidenceLevel == "high" {
		t.Errorf("wildcard/regex-only server should not be high confidence: %v", w.Confidence)
	}

	// fastcgi via nested include (relative path resolved against /etc/nginx)
	php := byName(r, "php.example.com")
	if php == nil || len(php.FastCGIPass) != 1 || php.FastCGIPass[0] != "unix:/run/php/php8.3-fpm.sock" {
		t.Fatalf("php %+v", php)
	}
	if len(php.Locations) != 1 || php.Locations[0].Match != `~ \.php$` {
		t.Errorf("php locations %+v", php.Locations)
	}
	if len(php.Unsupported) != 0 {
		t.Errorf("php should have no unsupported directives (snippet included): %+v", php.Unsupported)
	}

	// TLS
	tls := byName(r, "secure.example.com")
	if tls == nil || !tls.TLS || !tls.Listen[0].SSL || !tls.Listen[0].HTTP2 || !tls.Listen[1].DefaultServer {
		t.Fatalf("tls %+v", tls)
	}
	if tls.SSLCertificates[0] != "/etc/letsencrypt/live/secure.example.com/fullchain.pem" || len(tls.SSLCertificateKeys) != 1 {
		t.Errorf("certs %+v", tls.SSLCertificates)
	}
	if tls.ConfidenceLevel != "high" || tls.ManualReviewRequired {
		t.Errorf("tls confidence %v %v %v", tls.Confidence, tls.ManualReviewRequired, tls.Reasons)
	}

	// reverse proxy + upstream linkage
	px := byName(r, "api.example.com")
	if px == nil || len(px.ProxyPass) != 2 || len(px.Upstreams) != 1 || px.Upstreams[0] != "app_backend" {
		t.Fatalf("proxy %+v", px)
	}
	if px.Listen[0].Port != 8080 || !px.Listen[0].DefaultServer {
		t.Errorf("proxy listen %+v", px.Listen)
	}
	if len(r.Upstreams) != 1 || len(r.Upstreams[0].Servers) != 2 || r.Upstreams[0].Provenance.File != "/etc/nginx/conf.d/upstreams.conf" {
		t.Errorf("upstreams %+v", r.Upstreams)
	}

	// duplicate domains
	if len(r.Duplicates) != 1 || r.Duplicates[0].Name != "example.com" || r.Duplicates[0].Port != 80 || len(r.Duplicates[0].ServerIDs) != 2 {
		t.Fatalf("duplicates %+v", r.Duplicates)
	}
	if !ex.ManualReviewRequired {
		t.Error("duplicate server must require manual review")
	}

	// unsupported directives
	u := byName(r, "weird.example.com")
	if u == nil {
		t.Fatal("unsupported server missing")
	}
	names := map[string]bool{}
	for _, d := range u.Unsupported {
		names[d.Name] = true
	}
	for _, want := range []string{"set", "if", "sub_filter", "content_by_lua_block"} {
		if !names[want] {
			t.Errorf("missing unsupported %q in %+v", want, u.Unsupported)
		}
	}
	if !u.ManualReviewRequired || u.ConfidenceLevel == "high" {
		t.Errorf("unsupported server confidence %v review=%v", u.Confidence, u.ManualReviewRequired)
	}
	topNames := map[string]bool{}
	for _, d := range r.Unsupported {
		topNames[d.Name] = true
	}
	if !topNames["map"] {
		t.Errorf("http-level map should be reported: %+v", r.Unsupported)
	}

	// unresolved include + catch-all default
	def := byName(r, "_")
	if def == nil || def.ServerNames[0].Kind != "catch_all" || !def.ManualReviewRequired {
		t.Fatalf("default %+v", def)
	}
	foundIssue := false
	for _, is := range r.Includes {
		if is.Pattern == "/etc/nginx/missing-snippet.conf" {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Errorf("missing include issue: %+v", r.Includes)
	}

	// JSON shape: arrays never null
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), ":null") {
		t.Errorf("report JSON contains null: %s", b)
	}
}

func TestSingleFileFixture(t *testing.T) {
	r, err := ParseAndAnalyze(load(t, "single-server.conf"), "/etc/nginx/single.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 0 {
		// a bare server{} outside http is not in http context -> not a site
		t.Fatalf("bare server outside http must not be reported, got %d", len(r.Servers))
	}
	wrapped := "http {\n" + load(t, "single-server.conf") + "}\n"
	r, err = ParseAndAnalyze(wrapped, "/etc/nginx/single.conf")
	if err != nil || len(r.Servers) != 1 {
		t.Fatalf("err=%v servers=%d", err, len(r.Servers))
	}
	s := r.Servers[0]
	if s.ServerNames[0].Name != "single.example.com" || s.Root != "/srv/with space" || s.Listen[0].Address != "127.0.0.1" || s.Listen[0].Port != 8081 {
		t.Fatalf("%+v", s)
	}
	if s.Locations[0].Alias != "/srv/static/" || s.Provenance.Line != 3 {
		t.Fatalf("loc %+v prov %+v", s.Locations, s.Provenance)
	}
}

func TestImplicitListen(t *testing.T) {
	r, err := ParseAndAnalyze("http { server { server_name a.test; root /x; } }", "f")
	if err != nil || len(r.Servers) != 1 || !r.Servers[0].Listen[0].Implicit || r.Servers[0].Listen[0].Port != 80 {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestBrokenFixtures(t *testing.T) {
	for _, f := range []string{"broken-unbalanced.conf", "broken-quote.conf"} {
		_, err := ParseAndAnalyze(load(t, f), f)
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("%s: expected SyntaxError, got %v", f, err)
		}
	}
	for _, src := range []string{"}", "a b;;", "a {", "{", "server { listen 80 }"} {
		if _, err := ParseDump(src, "x"); err == nil {
			t.Errorf("%q: expected error", src)
		}
	}
}

func TestRecursiveIncludeGuard(t *testing.T) {
	src := "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/a.conf; }\n# configuration file /etc/nginx/a.conf:\ninclude /etc/nginx/a.conf;\n"
	r, err := ParseAndAnalyze(src, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Includes) == 0 || r.Includes[0].Reason != "recursive include" {
		t.Fatalf("%+v", r.Includes)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("http { server { listen 80; server_name a; } }")
	f.Add("a \"b\" 'c' ${d} # e\n{ }")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseAndAnalyze(s, "fuzz")
	})
}
