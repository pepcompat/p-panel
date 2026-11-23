// Package logship is the agent side of P5 log shipping (ADR-0008,
// docs/AGENT_PROTOCOL.md "Telemetry: metrics and logs"): sources (nginx file
// tailers, managed-container log followers, the agent's own log) → redaction →
// bounded on-disk segment buffer (drop-oldest, counted) → gzip batches POSTed
// to /agent/v1/logs over the existing mTLS channel.
//
// Invariants: a line is redacted before it touches disk; disk usage is bounded
// by logs.bufferCapBytes (+ at most one entry); memory holds at most one batch
// in flight; nothing here can block or affect workloads.
package logship

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

// Source names.
const (
	SourceNginxAccess = "nginx_access"
	SourceNginxError  = "nginx_error"
	SourceContainer   = "container"
	SourceAgent       = "agent"
)

// Limits from the protocol.
const (
	MaxLineBytes     = 16 << 10
	TruncSuffix      = " …[truncated]"
	MaxRawLine       = 64 << 10 // bytes read for one line before redaction
	MaxBatchEntries  = 5000
	MaxBatchGzip     = 1 << 20
	MaxBatchRaw      = 6 << 20 // stays well under the Center's 8 MiB decompressed limit
	defaultSegMin    = 64 << 10
	defaultSegMax    = 4 << 20
	agentChanEntries = 1024
)

// Entry is one log entry as shipped (keys always present; null when unknown).
type Entry struct {
	TS        string  `json:"ts"`
	Source    string  `json:"source"`
	App       *string `json:"app"`
	Service   *string `json:"service"`
	Container *string `json:"container"`
	File      *string `json:"file"`
	Stream    *string `json:"stream"`
	Level     *string `json:"level"`
	Line      string  `json:"line"`
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// FormatTS formats an entry timestamp (UTC, nanosecond precision).
func FormatTS(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Sanitize makes raw text a shippable line: valid UTF-8, redacted (patterns +
// known secret values), then capped at MaxLineBytes including TruncSuffix.
// Redaction happens on (up to MaxRawLine bytes of) the original text BEFORE
// truncation so a cut can never expose part of a secret.
func Sanitize(r *redact.Redactor, raw []byte) string {
	if len(raw) > MaxRawLine {
		raw = raw[:MaxRawLine]
	}
	s := strings.TrimRight(string(raw), "\r\n")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = r.Redact(s)
	if len(s) > MaxLineBytes {
		cut := MaxLineBytes - len(TruncSuffix)
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + TruncSuffix
	}
	return s
}

var nginxErrRe = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[([a-z]+)\]`)

func normLevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "trace", "debug", "dbg", "10", "20":
		return "debug"
	case "info", "information", "notice", "inf", "30":
		return "info"
	case "warn", "warning", "wrn", "40":
		return "warn"
	case "error", "err", "eror", "50":
		return "error"
	case "fatal", "crit", "critical", "alert", "emerg", "emergency", "panic", "60":
		return "fatal"
	}
	return ""
}

// DetectLevel: nginx error-log severity; JSON `level`/`severity` fields;
// stderr → error only when there is no better signal; else nil.
func DetectLevel(source, stream, line string) *string {
	if source == SourceNginxError {
		if m := nginxErrRe.FindStringSubmatch(line); m != nil {
			if l := normLevel(m[1]); l != "" {
				return &l
			}
		}
	}
	if t := strings.TrimSpace(line); len(t) > 1 && t[0] == '{' {
		var j struct {
			Level    any `json:"level"`
			Severity any `json:"severity"`
		}
		if json.Unmarshal([]byte(t), &j) == nil {
			for _, v := range []any{j.Level, j.Severity} {
				var s string
				switch x := v.(type) {
				case string:
					s = x
				case float64:
					s = strconv.FormatFloat(x, 'f', -1, 64)
				}
				if l := normLevel(s); l != "" {
					return &l
				}
			}
		}
	}
	if stream == "stderr" {
		l := "error"
		return &l
	}
	return nil
}
