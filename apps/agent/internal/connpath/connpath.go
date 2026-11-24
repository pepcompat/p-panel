// Package connpath manages the agent's management paths (P9,
// docs/P9_NETWORK_CONTRACT.md §1): the Center gateway endpoints advertised at
// enrollment and in heartbeat responses (`public` / `private`), the Center's
// connection policy, the dial order it implies, periodic endpoint probing and
// the "path forbidden" state after a 403 CONNECTION_PATH_NOT_ALLOWED.
//
// Safety rule: under `private_only` the agent never dials (or probes) a public
// endpoint, even when every private endpoint is down (fail closed).
package connpath

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Management paths.
const (
	PathPublic  = "public"
	PathPrivate = "private"
)

// Connection policies (ConnectionPolicy in the contract).
const (
	PolicyAuto             = "auto"
	PolicyPrivateOnly      = "private_only"
	PolicyPublicOnly       = "public_only"
	PolicyPrivatePreferred = "private_preferred"
	PolicyPublicPreferred  = "public_preferred"
	// PolicyUnknown: no policy received yet (fresh enrollment, older Center).
	// Dialled like public_preferred: the backwards-compatible public path
	// first, a private endpoint (if advertised) as fallback.
	PolicyUnknown = ""
)

// CodePathNotAllowed is the Center's 403 error code for a request that arrived
// on a listener whose path the server's policy does not allow.
const CodePathNotAllowed = "CONNECTION_PATH_NOT_ALLOWED"

// Limits on Center-supplied endpoint lists.
const (
	MaxEndpoints  = 8
	MaxURLBytes   = 512
	PingPath      = "/agent/v1/ping"
	FileName      = "connection.json"
	maxFileBytes  = 64 << 10
	stateVersion1 = 1
)

// Endpoint is one advertised gateway endpoint.
type Endpoint struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

// Block is the heartbeat response `connection` block.
type Block struct {
	Policy    string     `json:"policy"`
	Endpoints []Endpoint `json:"endpoints"`
}

// ValidPolicy reports whether p is a known connection policy.
func ValidPolicy(p string) bool {
	switch p {
	case PolicyAuto, PolicyPrivateOnly, PolicyPublicOnly, PolicyPrivatePreferred, PolicyPublicPreferred:
		return true
	}
	return false
}

// ValidPath reports whether p is a known management path.
func ValidPath(p string) bool { return p == PathPublic || p == PathPrivate }

// NormalizeURL validates a Center-advertised gateway URL: https, a host, no
// userinfo/query/fragment, no path other than "/". It returns the URL without
// a trailing slash.
func NormalizeURL(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > MaxURLBytes {
		return "", errors.New("gateway url empty or too long")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] >= 0x7f {
			return "", errors.New("gateway url contains control, space or non-ASCII characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("gateway url: %v", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("gateway url must be https://host[:port], got %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", errors.New("gateway url must not contain userinfo, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("gateway url must not contain a path")
	}
	if p := u.Port(); p != "" {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
			if n > 65535 {
				break
			}
		}
		if n < 1 || n > 65535 {
			return "", errors.New("gateway url port out of range")
		}
	}
	return "https://" + u.Host, nil
}

// ValidateEndpoints validates and normalises a Center-supplied endpoint list:
// 1..MaxEndpoints entries, known paths, valid https URLs, no duplicate URL.
func ValidateEndpoints(eps []Endpoint) ([]Endpoint, error) {
	if len(eps) == 0 {
		return nil, errors.New("no endpoints")
	}
	if len(eps) > MaxEndpoints {
		return nil, fmt.Errorf("more than %d endpoints", MaxEndpoints)
	}
	out := make([]Endpoint, 0, len(eps))
	seen := map[string]bool{}
	for i, e := range eps {
		if !ValidPath(e.Path) {
			return nil, fmt.Errorf("endpoints[%d]: unknown path %q", i, e.Path)
		}
		u, err := NormalizeURL(e.URL)
		if err != nil {
			return nil, fmt.Errorf("endpoints[%d]: %v", i, err)
		}
		if seen[u] {
			return nil, fmt.Errorf("endpoints[%d]: duplicate url", i)
		}
		seen[u] = true
		out = append(out, Endpoint{Path: e.Path, URL: u})
	}
	return out, nil
}

// pathOrder is the path preference of a policy (paths not listed are never dialled).
func pathOrder(policy string, eps []Endpoint) []string {
	switch policy {
	case PolicyPrivateOnly:
		return []string{PathPrivate}
	case PolicyPublicOnly:
		return []string{PathPublic}
	case PolicyPrivatePreferred:
		return []string{PathPrivate, PathPublic}
	case PolicyAuto:
		for _, e := range eps {
			if e.Path == PathPrivate {
				return []string{PathPrivate, PathPublic}
			}
		}
		return []string{PathPublic}
	default: // public_preferred and unknown
		return []string{PathPublic, PathPrivate}
	}
}

// Order returns the endpoints in dial order for policy. Endpoints of a path
// the policy does not allow are left out (private_only never yields public).
// Within a path the advertised order is kept.
func Order(policy string, eps []Endpoint) []Endpoint {
	var out []Endpoint
	for _, p := range pathOrder(policy, eps) {
		for _, e := range eps {
			if e.Path == p {
				out = append(out, e)
			}
		}
	}
	return out
}

// Allows reports whether policy permits dialling path.
func Allows(policy, path string) bool {
	if !ValidPath(path) {
		return false
	}
	switch policy {
	case PolicyPrivateOnly:
		return path == PathPrivate
	case PolicyPublicOnly:
		return path == PathPublic
	}
	return true
}

// Probeable reports whether the agent may probe an endpoint of path under
// policy. Only private_only restricts probing (no public dial at all); other
// policies probe every advertised endpoint so the Center can verify a path
// before switching to it.
func Probeable(policy, path string) bool {
	if policy == PolicyPrivateOnly {
		return path == PathPrivate
	}
	return ValidPath(path)
}
