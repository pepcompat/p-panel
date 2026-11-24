package execx

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// TestTimeoutKillsProcessGroup: a timed-out process and the children it forked
// are all killed (no orphans). /bin/sh is used here only as a test fixture that
// forks; the agent itself never runs a shell.
func TestTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := "sleep 60 & echo $! > " + pidFile + "; wait"
	start := time.Now()
	_, err := System{}.RunCmd(context.Background(), Cmd{Binary: "/bin/sh", Args: []string{"-c", script}, Timeout: 300 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took %s (pipes held by an orphan?)", time.Since(start))
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(3 * time.Second)
	for alive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if alive(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d survived the timeout (orphan)", pid)
	}
}

// TestCancelKillsProcessGroup: ctx cancellation behaves like the timeout.
func TestCancelKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	_, err := System{}.RunCmd(ctx, Cmd{Binary: "/bin/sh", Args: []string{"-c", "sleep 60 & echo $! > " + pidFile + "; wait"}, Timeout: 30 * time.Second})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid == 0 {
		t.Fatal("no child pid")
	}
	deadline := time.Now().Add(3 * time.Second)
	for alive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if alive(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d survived cancellation", pid)
	}
}

// TestBackgroundChildReapedAfterNormalExit: a child left running by a process
// that exits 0 is killed too.
func TestBackgroundChildReapedAfterNormalExit(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	res, err := System{}.RunCmd(context.Background(), Cmd{Binary: "/bin/sh", Args: []string{"-c", "sleep 60 >/dev/null 2>&1 & echo $! > " + pidFile}, Timeout: 10 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(3 * time.Second)
	for pid > 0 && alive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 || alive(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("background child %d survived", pid)
	}
}

func TestOutputCapsStdoutAndStderr(t *testing.T) {
	// 1 MiB to stdout and stderr each; caps are 1000 bytes / 64 KiB.
	res, err := System{}.RunCmd(context.Background(), Cmd{Binary: "/bin/sh",
		Args: []string{"-c", "head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2"}, Timeout: 10 * time.Second, MaxOut: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 1000 || len(res.Stderr) != 64<<10 || !res.Truncated {
		t.Fatalf("stdout=%d stderr=%d trunc=%v", len(res.Stdout), len(res.Stderr), res.Truncated)
	}
}

func TestTimeoutClamped(t *testing.T) {
	// > 10 min (not Long) falls back to 30 s; an explicit huge Long timeout is clamped too.
	start := time.Now()
	_, err := System{}.RunCmd(context.Background(), Cmd{Binary: "/bin/sleep", Args: []string{"0.1"}, Timeout: 365 * 24 * time.Hour})
	if err != nil || time.Since(start) > 5*time.Second {
		t.Fatalf("%v %s", err, time.Since(start))
	}
}

// TestEnvAllowlistBypass: command-executing or path-hijacking variables are
// refused whatever the casing or value tricks.
func TestEnvAllowlistBypass(t *testing.T) {
	bin := "/usr/bin/env"
	refused := []string{
		"GIT_SSH_COMMAND=sh -c id", "GIT_SSH=/tmp/x", "GIT_EXEC_PATH=/tmp", "GIT_PROXY_COMMAND=/tmp/x", "GIT_EXTERNAL_DIFF=/tmp/x",
		"GIT_CONFIG_PARAMETERS='core.sshCommand=id'", "GIT_TEMPLATE_DIR=/tmp", "GIT_DIR=/etc", "GIT_WORK_TREE=/", "GIT_PAGER=sh",
		"GIT_EDITOR=sh", "GIT_SEQUENCE_EDITOR=sh", "GIT_TRACE=/tmp/trace", "GIT_ASKPASS=/tmp/askpass", "GIT_CONFIG_GLOBAL=/tmp/evil",
		"GIT_ALLOW_PROTOCOL=ext", "GIT_ALLOW_PROTOCOL=ext:https", "GIT_TERMINAL_PROMPT=1", "GIT_CONFIG_NOSYSTEM=0",
		"GIT_CONFIG_KEY_0=core.sshCommand", "GIT_CONFIG_KEY_0=core.fsmonitor", "GIT_CONFIG_KEY_1=core.pager", "GIT_CONFIG_KEY_0=credential.helper",
		"GIT_CONFIG_KEY_0=protocol.ext.allow", "GIT_CONFIG_KEY_0=url.ext::sh.insteadOf", "GIT_CONFIG_KEY_0=CORE.HOOKSPATH",
		"GIT_CONFIG_KEY_100=core.hooksPath", "PATH=/tmp", "LD_PRELOAD=/x.so", "LD_LIBRARY_PATH=/tmp", "DYLD_INSERT_LIBRARIES=/x",
		"BASH_ENV=/tmp/x", "ENV=/tmp/x", "IFS= ", "home=/tmp", "Home=/tmp", "HOME=relative", "HOME=/tmp/../etc", "TMPDIR=",
		"RESTIC_PASSWORD_COMMAND=id", "RESTIC_PASSWORD_FILE=/etc/shadow", "RESTIC_REPOSITORY_FILE=/x", "RESTIC_FROM_PASSWORD_COMMAND=id",
		"PGPASSFILE=/x", " HOME=/tmp", "HOME =/tmp", "HOME=/tmp\nPATH=/x", "HOME=/tmp\x00PATH=/x", "=x", "",
	}
	for _, kv := range refused {
		if err := CheckEnv(kv); err == nil {
			t.Errorf("CheckEnv accepted %q", kv)
		}
		if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: bin, Env: []string{kv}}); err == nil {
			t.Errorf("RunCmd accepted env %q", kv)
		}
	}
	// a duplicate key could override an earlier pinned value
	if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: bin, Env: []string{"HOME=/tmp", "HOME=/root"}}); err == nil {
		t.Error("duplicate env key accepted")
	}
	for _, kv := range []string{"GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null", "GIT_ASKPASS=/bin/false",
		"GIT_ALLOW_PROTOCOL=https", "GIT_CONFIG_KEY_5=http.extraHeader", "GIT_CONFIG_VALUE_5=Authorization: Basic eA==", "RESTIC_PASSWORD=x=y"} {
		if err := CheckEnv(kv); err != nil {
			t.Errorf("CheckEnv refused legitimate %q: %v", kv, err)
		}
	}
}

func TestArgvBounds(t *testing.T) {
	big := make([]string, MaxArgs+1)
	for i := range big {
		big[i] = "x"
	}
	if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: "/bin/echo", Args: big}); err == nil {
		t.Error("giant argv accepted")
	}
	if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: "/bin/echo", Args: []string{strings.Repeat("a", MaxArgBytes+1)}}); err == nil {
		t.Error("giant arg accepted")
	}
	for _, b := range []string{"/bin/../bin/echo", "bin/echo", "/bin/echo/", "", "./echo"} {
		if _, err := (System{}).RunCmd(context.Background(), Cmd{Binary: b}); err == nil {
			t.Errorf("binary %q accepted", b)
		}
	}
	if _, ok := Find("echo", "/tmp/does-not-exist"); ok {
		t.Error("non-existent override resolved")
	}
}

// FuzzCheckEnv: anything CheckEnv accepts has an allowlisted key, no control
// characters, and never a command-executing git/restic/loader variable.
func FuzzCheckEnv(f *testing.F) {
	for _, s := range []string{"HOME=/tmp", "GIT_SSH_COMMAND=id", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_KEY_0=core.sshCommand",
		"RESTIC_PASSWORD=x", "LD_PRELOAD=x", "GIT_ASKPASS=/bin/false", "GIT_ALLOW_PROTOCOL=ext", "HOME=/a/../b", "TMPDIR=/tmp\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, kv string) {
		if CheckEnv(kv) != nil {
			return
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !ExtraEnvKeyRe.MatchString(k) || strings.ContainsAny(kv, "\x00\n\r") {
			t.Fatalf("accepted %q", kv)
		}
		for _, bad := range []string{"SSH", "EXEC_PATH", "PROXY", "EXTERNAL", "PARAMETERS", "PAGER", "EDITOR", "COMMAND", "_FILE", "LD_", "DYLD", "PATH="} {
			if strings.Contains(k+"=", bad) {
				t.Fatalf("dangerous key accepted: %q", kv)
			}
		}
		if strings.HasPrefix(k, "GIT_CONFIG_KEY_") && !gitConfigKeys[v] {
			t.Fatalf("git config key %q accepted", v)
		}
		if k == "GIT_ASKPASS" && v != "/bin/false" {
			t.Fatalf("askpass %q accepted", v)
		}
		if k == "GIT_ALLOW_PROTOCOL" && strings.Contains(v, "ext") {
			t.Fatalf("ext protocol accepted")
		}
	})
}
