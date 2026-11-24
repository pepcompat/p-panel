// Package redact removes secrets from log lines before they are buffered or
// shipped (P5, docs/AGENT_PROTOCOL.md "Telemetry"). The pattern list mirrors
// packages/shared-contracts/src/redaction.ts EXACTLY (JS flag `i` → RE2 `(?i)`,
// `$1` → `${1}`); both sides must pass packages/shared-contracts/testdata/redaction-golden.json.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Replacement is the text substituted for a secret.
const Replacement = "[REDACTED]"

// MinSecretLen is the shortest known secret value that is redacted verbatim
// (shorter values would destroy ordinary text).
const MinSecretLen = 6

// MaxKnownSecrets bounds the in-memory secret value registry.
const MaxKnownSecrets = 1024

// Pattern is one compiled redaction rule.
type Pattern struct {
	Name        string
	Re          *regexp.Regexp
	Replacement string
}

// Patterns is the shared list, in order (more specific first).
var Patterns = []Pattern{
	{"private_key_block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), Replacement},
	{"url_userinfo", regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@`), "${1}" + Replacement + "@"},
	{"authorization_header", regexp.MustCompile(`(?i)((?:^|[\s"'{,])(?:proxy-)?authorization["']?\s*[:=]\s*["']?)(?:bearer |basic |token )?[^\s"',}]+`), "${1}" + Replacement},
	{"bearer_token", regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9\-._~+/]+=*`), "${1}" + Replacement},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`), Replacement},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`), Replacement},
	{"slack_token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), Replacement},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), Replacement},
	{"ppanel_enrollment_token", regexp.MustCompile(`\bppe_[A-Za-z0-9_-]{16,}`), Replacement},
	{"key_value_secret", regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|passw(?:or)?d|pwd)["']?\s*[:=]\s*["']?)[^\s"'&,;}]+`), "${1}" + Replacement},
}

// Line applies the shared patterns only.
func Line(s string) string {
	for _, p := range Patterns {
		s = p.Re.ReplaceAllString(s, p.Replacement)
	}
	return s
}

// Redactor applies the shared patterns plus exact known secret values (job
// secrets held in memory by the agent). Safe for concurrent use.
type Redactor struct {
	mu      sync.RWMutex
	refs    map[string]int // value -> registrations
	ordered []string       // longest first
	// Linger keeps a released value redacted for a while (a container started
	// by a job may log its env shortly after the job ends). Default 15 min.
	Linger time.Duration
}

// New returns an empty Redactor.
func New() *Redactor { return &Redactor{refs: map[string]int{}, Linger: 15 * time.Minute} }

// Register adds secret values; release removes them (after Linger). Values
// shorter than MinSecretLen are ignored. Never logs or persists values.
func (r *Redactor) Register(values ...string) (release func()) {
	var added []string
	r.mu.Lock()
	for _, v := range values {
		if len(v) < MinSecretLen || strings.Contains(Replacement, v) {
			// too short to redact verbatim, or a fragment of the marker itself
			// (it could never be removed from a redacted line)
			continue
		}
		if _, ok := r.refs[v]; !ok && len(r.refs) >= MaxKnownSecrets {
			continue
		}
		r.refs[v]++
		added = append(added, v)
	}
	r.rebuildLocked()
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			drop := func() {
				r.mu.Lock()
				for _, v := range added {
					if r.refs[v]--; r.refs[v] <= 0 {
						delete(r.refs, v)
					}
				}
				r.rebuildLocked()
				r.mu.Unlock()
			}
			if r.Linger > 0 {
				time.AfterFunc(r.Linger, drop)
			} else {
				drop()
			}
		})
	}
}

func (r *Redactor) rebuildLocked() {
	r.ordered = r.ordered[:0]
	for v := range r.refs {
		r.ordered = append(r.ordered, v)
	}
	sort.Slice(r.ordered, func(i, j int) bool {
		if len(r.ordered[i]) != len(r.ordered[j]) {
			return len(r.ordered[i]) > len(r.ordered[j])
		}
		return r.ordered[i] < r.ordered[j]
	})
}

// MaxKnownLen returns the length of the longest registered value (0 if none).
func (r *Redactor) MaxKnownLen() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.ordered) == 0 {
		return 0
	}
	return len(r.ordered[0])
}

// Known returns the number of registered secret values.
func (r *Redactor) Known() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.refs)
}

// maxSecretPasses bounds the known-value fixpoint loop in Redact.
const maxSecretPasses = 8

// Redact applies the shared patterns, then known secret values.
//
// Known values are replaced by marking EVERY occurrence (overlapping ones
// included) of every value in the current text, merging the marked ranges and
// replacing each merged range once. Because a replacement could create a new
// occurrence of another value that shares characters with the marker (for
// example "ED]tail"), this is repeated until no value occurs. If that does not
// converge within maxSecretPasses the whole line is replaced (fail closed).
// The result therefore never contains a registered value, and Redact is
// idempotent on its own output.
func (r *Redactor) Redact(s string) string {
	s = Line(s)
	if r == nil {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.ordered) == 0 {
		return s // identical to the shared (TS-mirrored) pattern pass
	}
	// Fixpoint of (known values ∘ patterns): a replacement can create a new
	// word boundary for a pattern ("pa[REDACTED]ghp_…") or a new occurrence
	// of another value, so both are re-applied until nothing changes.
	for pass := 0; pass < maxSecretPasses; pass++ {
		out, changed := r.replaceOnce(s)
		if changed {
			out = Line(out)
		}
		if !changed || out == s {
			return s
		}
		s = out
	}
	if out, changed := r.replaceOnce(s); changed || Line(out) != out {
		return Replacement
	}
	return s
}

// replaceOnce marks all occurrences of all known values and replaces each
// merged marked range with Replacement.
func (r *Redactor) replaceOnce(s string) (string, bool) {
	type span struct{ a, b int }
	var spans []span
	for _, v := range r.ordered {
		if !strings.Contains(s, v) {
			continue
		}
		for i := 0; i <= len(s)-len(v); {
			j := strings.Index(s[i:], v)
			if j < 0 {
				break
			}
			spans = append(spans, span{i + j, i + j + len(v)})
			i += j + 1
		}
	}
	if len(spans) == 0 {
		return s, false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].a < spans[j].a })
	var b strings.Builder
	b.Grow(len(s))
	cur := spans[0]
	last := 0
	flush := func(sp span) {
		b.WriteString(s[last:sp.a])
		b.WriteString(Replacement)
		last = sp.b
	}
	for _, sp := range spans[1:] {
		if sp.a <= cur.b { // overlapping or adjacent: merge
			if sp.b > cur.b {
				cur.b = sp.b
			}
			continue
		}
		flush(cur)
		cur = sp
	}
	flush(cur)
	b.WriteString(s[last:])
	return b.String(), true
}
