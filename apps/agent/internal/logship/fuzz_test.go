package logship

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

// FuzzSanitizeAndBatch: arbitrary raw log bytes + a registered secret go
// through Sanitize and the batch encoder. Properties: never panics; each line
// is valid UTF-8, <= MaxLineBytes, never contains the secret, and is stable
// under a second Sanitize; the gzip batch decodes to JSON with every entry
// carrying all keys, and fits MaxBatchGzip.
func FuzzSanitizeAndBatch(f *testing.F) {
	f.Add([]byte("GET /x?token=abc123secret HTTP/1.1\r\n"), "abc123secret", uint8(3))
	f.Add([]byte("\xff\xfe password=hunter2hunter2 \x00\x1b[31mred"), "hunter2hunter2", uint8(1))
	f.Add(bytes.Repeat([]byte("é"), MaxLineBytes), "ééééééé", uint8(2))
	f.Add(append(bytes.Repeat([]byte("a"), MaxLineBytes-5), []byte("SECRETVALUE")...), "SECRETVALUE", uint8(1))
	f.Fuzz(func(t *testing.T, raw []byte, secret string, n uint8) {
		r := redact.New()
		r.Linger = 0
		defer r.Register(secret)()
		line := Sanitize(r, raw)
		if !utf8.ValidString(line) || len(line) > MaxLineBytes {
			t.Fatalf("line invalid/too long (%d)", len(line))
		}
		if len(secret) >= redact.MinSecretLen && !strings.Contains(redact.Replacement, secret) && utf8.ValidString(secret) &&
			!strings.Contains(secret, "\r") && !strings.Contains(secret, "\n") && strings.Contains(line, secret) {
			t.Fatalf("secret %q leaked in %q", secret, line)
		}
		if again := Sanitize(r, []byte(line)); again != line && !strings.HasSuffix(line, TruncSuffix) {
			t.Fatalf("Sanitize not stable: %q -> %q", line, again)
		}
		app := "web"
		e := Entry{TS: "2026-11-23T00:00:00Z", Source: "container", App: &app, Line: line}
		e.Level = DetectLevel("container", "stderr", line)
		one, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		k := int(n%8) + 1
		lines := make([][]byte, k)
		for i := range lines {
			lines[i] = one
		}
		gz, used, err := encodeBatch(batchHead{BatchID: "b", Seq: 1, SentAt: "2026-11-23T00:00:00Z"}, lines)
		if err != nil {
			t.Fatal(err)
		}
		if len(gz) > MaxBatchGzip || used < 1 || used > k {
			t.Fatalf("batch %d bytes, used %d/%d", len(gz), used, k)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		var b struct {
			Entries []map[string]any `json:"entries"`
		}
		if err := json.Unmarshal(body, &b); err != nil || len(b.Entries) != used {
			t.Fatalf("batch json: %v (%d entries)", err, len(b.Entries))
		}
		for _, en := range b.Entries {
			for _, key := range []string{"ts", "source", "app", "service", "container", "file", "stream", "level", "line"} {
				if _, ok := en[key]; !ok {
					t.Fatalf("entry missing %s", key)
				}
			}
		}
	})
}

// TestSanitizeSecretStraddlingRawCut: a known secret cut in half by the
// MaxRawLine limit must not survive as a fragment, even when redaction of
// earlier content shrinks the line under MaxLineBytes.
func TestSanitizeSecretStraddlingRawCut(t *testing.T) {
	r := redact.New()
	r.Linger = 0
	secret := "S3CR3T-0123456789abcdef-TOKEN"
	defer r.Register(secret)()
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("A", MaxRawLine-200) + "\n-----END RSA PRIVATE KEY-----"
	pad := MaxRawLine - len(key) - 1 - len(secret)/2
	raw := key + " " + strings.Repeat("x", pad) + secret + " tail"
	line := Sanitize(r, []byte(raw))
	if strings.Contains(line, secret[:len(secret)/2]) {
		t.Fatalf("secret fragment survived: ...%q", line[max(0, len(line)-80):])
	}
	if !strings.HasSuffix(line, TruncSuffix) {
		t.Fatalf("raw cut not marked as truncated: ...%q", line[max(0, len(line)-40):])
	}
}
