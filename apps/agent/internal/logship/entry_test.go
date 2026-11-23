package logship

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

func TestSanitizeTruncatesAndRedacts(t *testing.T) {
	r := redact.New()
	long := strings.Repeat("é", 20000) // 40000 bytes
	got := Sanitize(r, []byte(long))
	if len(got) > MaxLineBytes || !strings.HasSuffix(got, TruncSuffix) || !utf8.ValidString(got) {
		t.Fatalf("len=%d suffix=%v valid=%v", len(got), strings.HasSuffix(got, TruncSuffix), utf8.ValidString(got))
	}
	// a secret straddling the 16 KiB boundary must be redacted, never partially kept
	in := strings.Repeat("a", MaxLineBytes-20) + " password=hunter2hunter2hunter2 tail"
	got = Sanitize(r, []byte(in))
	if strings.Contains(got, "hunter") {
		t.Fatalf("partial secret leaked: %q", got[len(got)-60:])
	}
	if Sanitize(r, []byte("bad \xff utf8\r\n")) != "bad � utf8" {
		t.Fatal("invalid utf8 / CRLF not normalised")
	}
	rel := r.Register("job-secret-value-123")
	defer rel()
	if got := Sanitize(r, []byte("echo job-secret-value-123")); got != "echo [REDACTED]" {
		t.Fatalf("known secret: %q", got)
	}
}

func TestDetectLevel(t *testing.T) {
	cases := []struct{ src, stream, line, want string }{
		{SourceNginxError, "", "2026/11/23 10:00:00 [error] 12#12: *1 open() failed", "error"},
		{SourceNginxError, "", "2026/11/23 10:00:00 [crit] 12#12: boom", "fatal"},
		{SourceNginxError, "", "2026/11/23 10:00:00 [notice] 1#1: start", "info"},
		{SourceNginxError, "", "2026/11/23 10:00:00 [warn] 1#1: x", "warn"},
		{SourceContainer, "stdout", `{"level":"warn","msg":"x"}`, "warn"},
		{SourceContainer, "stderr", `{"severity":"INFO","msg":"x"}`, "info"},
		{SourceContainer, "stdout", `{"level":30,"msg":"pino"}`, "info"},
		{SourceContainer, "stdout", `{"level":50,"msg":"pino"}`, "error"},
		{SourceContainer, "stderr", "plain stderr line", "error"},
		{SourceContainer, "stdout", "plain stdout line", ""},
		{SourceNginxAccess, "", `127.0.0.1 - - [23/Nov/2026] "GET / HTTP/1.1" 500 1`, ""},
		{SourceAgent, "", `{"timestamp":"x","level":"info","message":"m"}`, "info"},
	}
	for _, c := range cases {
		got := DetectLevel(c.src, c.stream, c.line)
		g := ""
		if got != nil {
			g = *got
		}
		if g != c.want {
			t.Errorf("%s/%s %q: got %q want %q", c.src, c.stream, c.line, g, c.want)
		}
	}
}
