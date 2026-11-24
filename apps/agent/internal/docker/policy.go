package docker

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
)

// Request-shape policy shared by the read-only Client and the write-capable
// Engine (docs: apps/agent/SECURITY_BOUNDARIES.md "Docker Engine API").
//
// The (method, path) allowlists only mean something if the path the daemon
// routes is the path we checked. Every request must therefore be in a single
// canonical form before any allowlist is consulted:
//
//   - scheme http, host "docker" (the transport always dials the configured
//     unix socket; the host is only a placeholder), no userinfo/opaque/fragment;
//   - no percent-encoded path (URL.RawPath set): %2e%2e, %2f, ... are refused
//     instead of being decoded differently by us and by the daemon;
//   - path is clean (path.Clean), absolute, no "//", no "..", no backslash, no
//     control/space/non-ASCII characters;
//   - no API version prefix (/v1.47/...): the agent never sends one, so a
//     versioned path can only be an attempt to dodge the anchored regexes;
//   - no HTTP method-override headers;
//   - redirects are never followed (noRedirects).

var versionPrefixRe = regexp.MustCompile(`^/v[0-9]`)

var idOrNameRe = regexp.MustCompile(`^` + idOrName + `$`)

// imageRefPathRe is an image reference usable in /images/{ref}/json
// (repo[:port]/path[:tag][@sha256:hex] or an image id).
var imageRefPathRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/@-]{0,400}$`)

// readAllow is the complete list of GET/HEAD paths either client may use.
var readAllow = []*regexp.Regexp{
	regexp.MustCompile(`^/_ping$`),
	regexp.MustCompile(`^/version$`),
	regexp.MustCompile(`^/containers/json$`),
	regexp.MustCompile(`^/containers/` + idOrName + `/(json|logs|stats|archive)$`),
	regexp.MustCompile(`^/images/[a-z0-9][a-z0-9._:/@-]{0,400}/json$`),
	regexp.MustCompile(`^/networks/` + idOrName + `$`),
	regexp.MustCompile(`^/volumes/` + idOrName + `$`),
}

func allowedRead(p string) bool {
	if !CanonicalPath(p) {
		return false
	}
	for _, re := range readAllow {
		if re.MatchString(p) {
			// /images/<ref>/json must not smuggle another endpoint in <ref>
			if strings.HasPrefix(p, "/images/") && strings.Count(p, "/json") != 1 {
				return false
			}
			return true
		}
	}
	return false
}

// CanonicalPath reports whether p is in the single canonical form the
// allowlists are written against (see package policy comment).
func CanonicalPath(p string) bool {
	if p == "" || p[0] != '/' || len(p) > 1024 {
		return false
	}
	if path.Clean(p) != p || strings.Contains(p, "//") || strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c <= ' ' || c >= 0x7f || c == '%' || c == '\\' || c == '?' || c == '#' || c == ';' {
			return false
		}
	}
	return !versionPrefixRe.MatchString(p)
}

var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

// checkRequestShape enforces the canonical request form before allowlisting.
func checkRequestShape(r *http.Request) error {
	u := r.URL
	refuse := func(why string) error {
		p := ""
		if u != nil {
			p = u.Path
		}
		return fmt.Errorf("docker: %s %s refused (not in the container-ops allowlist: %s)", r.Method, p, why)
	}
	if u == nil {
		return refuse("no URL")
	}
	if u.Scheme != "http" || u.Host != "docker" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return refuse("non-canonical URL")
	}
	if r.Host != "" && r.Host != "docker" {
		return refuse("Host header override")
	}
	if u.RawPath != "" {
		return refuse("percent-encoded path")
	}
	if !CanonicalPath(u.Path) {
		return refuse("non-canonical path")
	}
	if r.Method != strings.ToUpper(r.Method) {
		return refuse("non-canonical method")
	}
	for _, h := range methodOverrideHeaders {
		if _, ok := r.Header[http.CanonicalHeaderKey(h)]; ok {
			return refuse("method override header")
		}
	}
	return nil
}

// errRedirect is returned when the daemon (or anything on the socket) answers
// with a redirect: the agent never follows one, so a 30x cannot turn an
// allowed request into a request for another path.
var errRedirect = errors.New("docker: redirects are not followed")

func noRedirects(*http.Request, []*http.Request) error { return errRedirect }
