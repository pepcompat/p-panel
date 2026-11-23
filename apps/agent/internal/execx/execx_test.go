package execx

import (
	"context"
	"path/filepath"
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

func TestRunCmdEnvAndDir(t *testing.T) {
	bin, ok := Find("env", "")
	if !ok {
		t.Skip("env binary not found")
	}
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	res, err := System{}.RunCmd(context.Background(), Cmd{Binary: bin, Env: []string{"HOME=" + dir, "GIT_TERMINAL_PROMPT=0"}, Dir: dir, Timeout: 5 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "HOME="+dir) || !strings.Contains(out, "GIT_TERMINAL_PROMPT=0") || !strings.Contains(out, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatalf("env: %s", out)
	}
	for _, bad := range []string{"PATH=/tmp", "LD_PRELOAD=/x.so", "GIT_X=a\nb", "NOEQUALS", "git_lower=1"} {
		if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: bin, Env: []string{bad}}); err == nil {
			t.Errorf("env %q accepted", bad)
		}
	}
	if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: bin, Dir: "relative"}); err == nil {
		t.Error("relative dir accepted")
	}
}

func TestResticEnvLongAndInterrupt(t *testing.T) {
	bin, ok := Find("env", "")
	if !ok {
		t.Skip("env binary not found")
	}
	res, err := System{}.RunCmd(context.Background(), Cmd{Binary: bin, Env: []string{"RESTIC_PASSWORD=pw", "RESTIC_REST_USERNAME=u",
		"RESTIC_REST_PASSWORD=rp", "RESTIC_CACHE_DIR=/tmp/c", "TMPDIR=/tmp"}, Timeout: 5 * time.Second})
	if err != nil || !strings.Contains(string(res.Stdout), "RESTIC_REST_PASSWORD=rp") {
		t.Fatalf("%v %s", err, res.Stdout)
	}
	for _, bad := range []string{"RESTIC_REPOSITORY=/x", "RESTIC_PASSWORD_COMMAND=/bin/sh", "AWS_SECRET_ACCESS_KEY=x"} {
		if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: bin, Env: []string{bad}}); err == nil {
			t.Errorf("env %q accepted", bad)
		}
	}
	// a Long command keeps its (>10 min) timeout; a normal one is clamped
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err = System{}.RunCmd(ctx, Cmd{Binary: "/bin/sleep", Args: []string{"30"}, Timeout: 2 * time.Hour, Long: true, Interrupt: true})
	if err == nil || !strings.Contains(err.Error(), "cancelled") || time.Since(start) > 10*time.Second {
		t.Fatalf("interrupt: %v after %s", err, time.Since(start))
	}
}
