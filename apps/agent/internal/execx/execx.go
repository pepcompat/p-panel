// Package execx is the ONLY place the agent spawns processes.
//
// Rules (security brief §3 / §14.1 "no generic command execution"):
//   - never a shell: exec.Command with an absolute binary and an argv slice;
//   - binaries are resolved only from fixed system directories;
//   - every invocation has a timeout and capped stdout/stderr;
//   - environment is replaced with a minimal fixed one.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultMaxOutput caps captured stdout (and separately stderr).
const DefaultMaxOutput = 8 << 20

// Result of a process run.
type Result struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
	Duration  time.Duration
}

// Executor runs a fixed binary with validated args. Implementations must not use a shell.
type Executor interface {
	Run(ctx context.Context, binary string, args []string, timeout time.Duration, maxOut int) (Result, error)
}

// System is the real Executor.
type System struct{}

var fixedEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}

// ErrUnsafeArg is returned for args that could never be legitimate.
var ErrUnsafeArg = errors.New("unsafe argument")

// Run executes binary (absolute path) with args.
func (System) Run(ctx context.Context, binary string, args []string, timeout time.Duration, maxOut int) (Result, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return Result{}, fmt.Errorf("execx: binary must be a clean absolute path: %q", binary)
	}
	for _, a := range args {
		if strings.ContainsAny(a, "\x00\n\r") {
			return Result{}, ErrUnsafeArg
		}
	}
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 30 * time.Second
	}
	if maxOut <= 0 {
		maxOut = DefaultMaxOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = fixedEnv
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	stdout := &capped{max: maxOut}
	stderr := &capped{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	start := time.Now()
	err := cmd.Run()
	res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Truncated: stdout.trunc || stderr.trunc, Duration: time.Since(start)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("execx: %s timed out after %s", filepath.Base(binary), timeout)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return res, nil // non-zero exit is reported via ExitCode
	}
	return res, err
}

type capped struct {
	buf   bytes.Buffer
	max   int
	trunc bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.trunc = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.trunc = true
	}
	return len(p), nil // swallow the rest so the child doesn't block/EPIPE
}

// SearchDirs are the only directories binaries are resolved from.
var SearchDirs = func() []string {
	d := []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}
	if runtime.GOOS == "darwin" {
		d = append(d, "/opt/homebrew/bin", "/opt/homebrew/sbin")
	}
	return d
}()

// Find resolves a bare binary name from SearchDirs; override (absolute) wins if set.
func Find(name, override string) (string, bool) {
	if override != "" {
		if isExec(override) {
			return override, true
		}
		return "", false
	}
	if strings.ContainsRune(name, '/') {
		return "", false
	}
	for _, d := range SearchDirs {
		p := filepath.Join(d, name)
		if isExec(p) {
			return p, true
		}
	}
	return "", false
}

func isExec(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}
