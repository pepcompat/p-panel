package execx

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRejectsRelativeAndUnsafe(t *testing.T) {
	if _, err := (System{}).Run(context.Background(), "sh", []string{"-c", "true"}, time.Second, 0); err == nil {
		t.Fatal("relative binary must be rejected")
	}
	if _, err := (System{}).Run(context.Background(), "/bin/echo", []string{"a\x00b"}, time.Second, 0); err == nil {
		t.Fatal("NUL arg must be rejected")
	}
}

func TestOutputCapAndArgvNotShell(t *testing.T) {
	// argv is passed literally: shell metacharacters are inert.
	r, err := (System{}).Run(context.Background(), "/bin/echo", []string{"x; rm -rf /", "$(id)"}, time.Second, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Stdout) != "x; rm" || !r.Truncated {
		t.Fatalf("got %q trunc=%v", r.Stdout, r.Truncated)
	}
}

func TestTimeout(t *testing.T) {
	_, err := (System{}).Run(context.Background(), "/bin/sleep", []string{"5"}, 200*time.Millisecond, 0)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestFind(t *testing.T) {
	if p, ok := Find("echo", ""); !ok || !strings.HasPrefix(p, "/") {
		t.Fatalf("echo not found: %q", p)
	}
	if _, ok := Find("../bin/echo", ""); ok {
		t.Fatal("path names must not resolve")
	}
}
