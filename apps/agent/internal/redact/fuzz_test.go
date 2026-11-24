package redact

import (
	"strings"
	"testing"
)

// FuzzRedactor (values that are fragments of the marker itself are not
// registered — they cannot be removed from any redacted line): Redact never panics, is idempotent, and no registered secret
// value (>= MinSecretLen) survives in the output, whatever surrounds it.
func FuzzRedactor(f *testing.F) {
	for _, s := range [][2]string{
		{"password=hunter2hunter2 token: abc", "hunter2hunter2"},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_sig_sig", "s3cr3t-value"},
		{"https://user:pa55word@host/x ghp_abcdefghijklmnopqrstuvwxyz0123", "pa55word"},
		{"aaaa[REDACTED]bbbb", "[REDACTED]b"},
		{"xx-secret-xx-secret-xx", "secret-xx-s"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "MIIEMIIE"},
		{"value=REDACTEDREDACTED", "REDACTED"},
		{"abcabcabcabc", "bcabca"},
	} {
		f.Add(s[0], s[1], "")
	}
	f.Fuzz(func(t *testing.T, line, secret, secret2 string) {
		r := New()
		r.Linger = 0
		release := r.Register(secret, secret2)
		defer release()
		out := r.Redact(line)
		if again := r.Redact(out); again != out {
			t.Fatalf("not idempotent:\n in:  %q\n 1st: %q\n 2nd: %q", line, out, again)
		}
		for _, s := range []string{secret, secret2} {
			if len(s) >= MinSecretLen && !strings.Contains(Replacement, s) && strings.Contains(out, s) {
				t.Fatalf("known secret %q survived in %q (input %q)", s, out, line)
			}
		}
		// shared patterns alone are also idempotent
		l := Line(line)
		if Line(l) != l {
			t.Fatalf("Line not idempotent: %q -> %q -> %q", line, l, Line(l))
		}
	})
}
