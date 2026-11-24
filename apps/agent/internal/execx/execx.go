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
	"regexp"
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
func (s System) Run(ctx context.Context, binary string, args []string, timeout time.Duration, maxOut int) (Result, error) {
	return s.RunCmd(ctx, Cmd{Binary: binary, Args: args, Timeout: timeout, MaxOut: maxOut})
}

// Cmd is one process invocation with optional extra environment and working
// directory (used by the P4b git source fetch). Still never a shell.
type Cmd struct {
	Binary string
	Args   []string
	// Env entries (KEY=VALUE) appended to the fixed minimal environment. Only
	// keys matching ExtraEnvKeyRe are accepted (HOME and GIT_*), so no
	// PATH/LD_PRELOAD style injection is possible.
	Env []string
	// Dir is the working directory (clean absolute path; default "/").
	Dir     string
	Timeout time.Duration
	MaxOut  int
	// Long allows a timeout up to MaxLongTimeout (P6 backups/restores);
	// otherwise timeouts are capped at 10 minutes.
	Long bool
	// Interrupt sends SIGINT (instead of SIGKILL) when ctx is cancelled or the
	// timeout fires, then kills after InterruptGrace. restic uses this to
	// remove its repository lock and never writes a snapshot for an aborted run.
	Interrupt bool
}

// MaxArgs / MaxArgBytes bound argv (giant arrays from params can never reach exec).
const (
	MaxArgs     = 512
	MaxArgBytes = 8 << 10
)

// MaxLongTimeout bounds Cmd.Long invocations (24 h job limit + margin).
const MaxLongTimeout = 25 * time.Hour

// InterruptGrace is how long an interrupted process may take to exit.
const InterruptGrace = 15 * time.Second

// CmdRunner runs a Cmd. System implements it; tests may fake it.
type CmdRunner interface {
	RunCmd(ctx context.Context, c Cmd) (Result, error)
}

// ExtraEnvKeyRe limits the environment keys a Cmd may add: HOME, the exact
// GIT_* variables the P4b source fetch uses and the restic credential/cache
// variables (P6; secrets are passed to restic ONLY via env, never argv).
// Command-executing git variables (GIT_SSH_COMMAND, GIT_EXEC_PATH,
// GIT_PROXY_COMMAND, GIT_EXTERNAL_DIFF, GIT_CONFIG_PARAMETERS, ...) are not
// accepted, and CheckEnv additionally pins the values of the dangerous ones.
var ExtraEnvKeyRe = regexp.MustCompile(`^(HOME|TMPDIR|GIT_(TERMINAL_PROMPT|CONFIG_NOSYSTEM|CONFIG_GLOBAL|ALLOW_PROTOCOL|LFS_SKIP_SMUDGE|ASKPASS|CONFIG_COUNT|CONFIG_KEY_[0-9]{1,2}|CONFIG_VALUE_[0-9]{1,2})|RESTIC_(PASSWORD|REST_USERNAME|REST_PASSWORD|CACHE_DIR))$`)

// gitConfigKeys are the only config keys that may be injected through
// GIT_CONFIG_KEY_<n> (none of them can make git run a program).
var gitConfigKeys = map[string]bool{
	"core.hooksPath": true, "http.followRedirects": true, "submodule.recurse": true,
	"fetch.recurseSubmodules": true, "core.symlinks": true, "http.extraHeader": true, "protocol.version": true,
}

// pinnedEnvValues are keys whose only acceptable value is fixed.
var pinnedEnvValues = map[string]map[string]bool{
	"GIT_ASKPASS":         {"/bin/false": true},
	"GIT_CONFIG_GLOBAL":   {"/dev/null": true},
	"GIT_TERMINAL_PROMPT": {"0": true},
	"GIT_CONFIG_NOSYSTEM": {"1": true},
	"GIT_LFS_SKIP_SMUDGE": {"1": true},
	"GIT_ALLOW_PROTOCOL":  {"https": true, "git": true, "https:git": true},
}

// CheckEnv validates one extra environment entry (KEY=VALUE) against the
// key allowlist and the per-key value rules.
func CheckEnv(kv string) error {
	k, v, ok := strings.Cut(kv, "=")
	if !ok || !ExtraEnvKeyRe.MatchString(k) || strings.ContainsAny(kv, "\x00\n\r") {
		return fmt.Errorf("execx: environment entry %q refused", k)
	}
	if allowed, pinned := pinnedEnvValues[k]; pinned && !allowed[v] {
		return fmt.Errorf("execx: environment entry %q has a refused value", k)
	}
	if strings.HasPrefix(k, "GIT_CONFIG_KEY_") && !gitConfigKeys[v] {
		return fmt.Errorf("execx: git config key %q refused", v)
	}
	if (k == "HOME" || k == "TMPDIR" || k == "RESTIC_CACHE_DIR") && (!filepath.IsAbs(v) || filepath.Clean(v) != v) {
		return fmt.Errorf("execx: %s must be a clean absolute path", k)
	}
	return nil
}

// RunCmd executes c.Binary (absolute path) with c.Args.
func (System) RunCmd(ctx context.Context, c Cmd) (Result, error) {
	binary := c.Binary
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return Result{}, fmt.Errorf("execx: binary must be a clean absolute path: %q", binary)
	}
	if len(c.Args) > MaxArgs {
		return Result{}, ErrUnsafeArg
	}
	for _, a := range c.Args {
		if len(a) > MaxArgBytes || strings.ContainsAny(a, "\x00\n\r") {
			return Result{}, ErrUnsafeArg
		}
	}
	env := append([]string(nil), fixedEnv...)
	seen := map[string]bool{}
	for _, kv := range c.Env {
		if err := CheckEnv(kv); err != nil {
			return Result{}, err
		}
		k, _, _ := strings.Cut(kv, "=")
		if seen[k] {
			return Result{}, fmt.Errorf("execx: environment entry %q given twice", k)
		}
		seen[k] = true
		env = append(env, kv)
	}
	dir := "/"
	if c.Dir != "" {
		if !filepath.IsAbs(c.Dir) || filepath.Clean(c.Dir) != c.Dir {
			return Result{}, fmt.Errorf("execx: dir must be a clean absolute path")
		}
		dir = c.Dir
	}
	timeout, maxOut := c.Timeout, c.MaxOut
	maxTimeout := 10 * time.Minute
	if c.Long {
		maxTimeout = MaxLongTimeout
	}
	if timeout <= 0 || timeout > maxTimeout {
		timeout = 30 * time.Second
	}
	if maxOut <= 0 {
		maxOut = DefaultMaxOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, c.Args...)
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	// Own process group: a timeout/cancel signals the WHOLE group, so helpers
	// a binary forks (git-remote-https, ssh, ...) never outlive the job.
	setProcessGroup(cmd)
	sig := os.Kill
	if c.Interrupt {
		sig = os.Interrupt
		cmd.WaitDelay = InterruptGrace
	}
	cmd.Cancel = func() error { return signalGroup(cmd, sig) }
	stdout := &capped{max: maxOut}
	stderr := &capped{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	start := time.Now()
	err := cmd.Run()
	// Reap anything left in the group (orphans that ignored the signal, or
	// background children of a process that exited normally).
	_ = signalGroup(cmd, os.Kill)
	res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Truncated: stdout.trunc || stderr.trunc, Duration: time.Since(start)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("execx: %s timed out after %s: %w", filepath.Base(binary), timeout, context.DeadlineExceeded)
	}
	if ctx.Err() == context.Canceled {
		return res, fmt.Errorf("execx: %s cancelled: %w", filepath.Base(binary), context.Canceled)
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
