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
		if len(v) < MinSecretLen {
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

// Known returns the number of registered secret values.
func (r *Redactor) Known() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.refs)
}

// Redact applies the shared patterns, then known secret values (longest first).
func (r *Redactor) Redact(s string) string {
	s = Line(s)
	if r == nil {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, v := range r.ordered {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, Replacement)
		}
	}
	return s
}
