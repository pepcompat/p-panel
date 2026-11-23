package backupops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// Options configure a Manager.
type Options struct {
	// Engine is the write-capable Docker Engine (nil = helper targets fail
	// with DOCKER_UNAVAILABLE).
	Engine *docker.Engine
	// Exec runs the host restic binary (execx.System in production).
	Exec execx.CmdRunner
	// ResticBin / ResticVersion come from the startup check ("" = RESTIC_UNAVAILABLE).
	ResticBin     string
	ResticVersion string
	// HelperImage is backup.helperImage from the LOCAL config.
	HelperImage string
	// WorkDir holds the restic cache and temporary verify restores.
	WorkDir string
	// StateDir is the agent state dir (never backed up; staging restores
	// go to <StateDir>/restores/<restoreId>).
	StateDir string
	// Hostname is recorded as the snapshot host of helper backups.
	Hostname string
	// Secrets performs the one-time secrets fetch for the job in ctx.
	Secrets func(ctx context.Context) (*transport.JobSecrets, error)
	// LockApp is the shared per-app mutex (containerops.Manager.LockApp);
	// nil = a private one.
	LockApp func(ctx context.Context, app string) (func(), error)
	// Resolve resolves the repo host for helper ExtraHosts (default net resolver).
	Resolve func(ctx context.Context, host string) ([]string, error)
	Log     *slog.Logger
	// ScratchReadyTimeout bounds waiting for a scratch DB (default 3 min).
	ScratchReadyTimeout time.Duration
	// ReadyInterval is the scratch readiness poll interval (default 2 s).
	ReadyInterval time.Duration
}

// Manager runs the P6 jobs. One mutating job per repository at a time, plus
// the per-app mutex for volume/DB targets.
type Manager struct {
	o        Options
	mu       sync.Mutex
	repo     map[string]chan struct{}
	apps     map[string]chan struct{}
	verifyMu sync.Mutex
}

// New returns a Manager.
func New(o Options) *Manager {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Exec == nil {
		o.Exec = execx.System{}
	}
	if o.Resolve == nil {
		o.Resolve = net.DefaultResolver.LookupHost
	}
	if o.ScratchReadyTimeout == 0 {
		o.ScratchReadyTimeout = 3 * time.Minute
	}
	if o.ReadyInterval == 0 {
		o.ReadyInterval = 2 * time.Second
	}
	if o.WorkDir == "" && o.StateDir != "" {
		o.WorkDir = filepath.Join(o.StateDir, "backup")
	}
	return &Manager{o: o, repo: map[string]chan struct{}{}, apps: map[string]chan struct{}{}}
}

// ResticVersion returns the verified host restic version ("" = unavailable).
func (m *Manager) ResticVersion() string { return m.o.ResticVersion }

func jerr(code, format string, a ...any) *jobs.Error { return jobs.Errorf(code, format, a...) }

func lockChan(ctx context.Context, mu *sync.Mutex, set map[string]chan struct{}, key, what string) (func(), error) {
	mu.Lock()
	ch, ok := set[key]
	if !ok {
		ch = make(chan struct{}, 1)
		set[key] = ch
	}
	mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, jerr(jobs.HandlerTimeout, "timed out waiting for another job on %s", what)
	}
}

// lock takes the per-repo mutex and then the per-app mutexes (sorted, so two
// jobs never deadlock).
func (m *Manager) lock(ctx context.Context, repoID string, apps []string) (func(), error) {
	var releases []func()
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	r, err := lockChan(ctx, &m.mu, m.repo, repoID, "repository "+repoID)
	if err != nil {
		return nil, err
	}
	releases = append(releases, r)
	for _, app := range sortedUnique(apps) {
		var u func()
		if m.o.LockApp != nil {
			u, err = m.o.LockApp(ctx, app)
		} else {
			u, err = lockChan(ctx, &m.mu, m.apps, app, "app "+app)
		}
		if err != nil {
			release()
			return nil, err
		}
		releases = append(releases, u)
	}
	return release, nil
}

// ---------------- preflight (before ack) ----------------

// CheckRestic fails with RESTIC_UNAVAILABLE when no usable host restic exists.
func (m *Manager) CheckRestic() error {
	if m.o.ResticBin == "" || m.o.ResticVersion == "" {
		return jerr(CodeResticUnavailable, "restic >= %d.%d is not available on this agent", MinResticMajor, MinResticMinor)
	}
	return nil
}

// CheckHelperImage applies the helper image rule: the job's helperImage (if
// any) must equal the LOCAL backup.helperImage.
func (m *Manager) CheckHelperImage(job string) (string, error) {
	if m.o.HelperImage == "" {
		return "", jerr(CodeHelperImageNotAllowed, "no backup.helperImage is configured on this agent")
	}
	if job != "" && job != m.o.HelperImage {
		return "", jerr(CodeHelperImageNotAllowed, "helperImage %s is not the agent's configured backup.helperImage", job)
	}
	return m.o.HelperImage, nil
}

func (m *Manager) checkPaths(paths []string) error {
	for _, p := range paths {
		if UnderDir(p, m.o.StateDir) {
			return jerr(jobs.RejectedInvalidParams, "path %s is inside the agent state directory", p)
		}
	}
	return nil
}

// PreflightBackup is the pure pre-ack check of backup.run.
func (m *Manager) PreflightBackup(p BackupParams) error {
	if err := m.CheckRestic(); err != nil {
		return err
	}
	for _, t := range p.Targets {
		if err := m.checkPaths(t.Paths); err != nil {
			return err
		}
	}
	if p.NeedsHelper() {
		if _, err := m.CheckHelperImage(p.HelperImage); err != nil {
			return err
		}
	} else if p.HelperImage != "" {
		if _, err := m.CheckHelperImage(p.HelperImage); err != nil {
			return err
		}
	}
	return nil
}

// PreflightRestore is the pure pre-ack check of restore.run.
func (m *Manager) PreflightRestore(p RestoreParams) error {
	if err := m.CheckRestic(); err != nil {
		return err
	}
	if err := m.checkPaths(p.Target.Include); err != nil {
		return err
	}
	if p.Target.NeedsHelper() || p.HelperImage != "" {
		if _, err := m.CheckHelperImage(p.HelperImage); err != nil {
			return err
		}
	}
	if p.Target.IsDB() && p.Target.Mode == "scratch" && p.Target.ScratchImage == "" && !p.DryRun {
		return jerr(jobs.RejectedInvalidParams, "target.scratchImage is required for a scratch restore")
	}
	return nil
}

// ---------------- per-job session ----------------

type session struct {
	m          *Manager
	ctx        context.Context
	repo       RepoRef
	creds      Creds
	env        map[string]string
	secrets    []string
	log        *slog.Logger
	image      string
	extraHosts []string
	pulled     bool
}

func (m *Manager) newSession(ctx context.Context, repo RepoRef, log *slog.Logger) (*session, error) {
	if m.o.Secrets == nil {
		return nil, jerr(containerops.CodeSecretsUnavailable, "secrets channel not configured")
	}
	sec, err := m.o.Secrets(ctx)
	if err != nil {
		code := transport.Code(err)
		if code == "" {
			code = "transport error"
		}
		return nil, jerr(containerops.CodeSecretsUnavailable, "secrets fetch failed (%s)", code)
	}
	creds, err := credsFrom(sec)
	if err != nil {
		return nil, jerr(containerops.CodeSecretsUnavailable, "%v", err)
	}
	s := &session{m: m, ctx: ctx, repo: repo, creds: creds, env: map[string]string{}, log: log}
	s.secrets = append(s.secrets, creds.Values()...)
	for k, v := range sec.Env {
		s.env[k] = v
		s.secrets = append(s.secrets, v)
	}
	return s, nil
}

func (s *session) addSecret(v string) { s.secrets = append(s.secrets, v) }

func (s *session) redact(text string) string {
	vals := make([]string, 0, len(s.secrets)*2)
	for _, v := range s.secrets {
		if len(v) < 4 {
			continue
		}
		vals = append(vals, v)
		if b, err := json.Marshal(v); err == nil {
			if q := strings.Trim(string(b), `"`); q != v {
				vals = append(vals, q)
			}
		}
	}
	return containerops.Redact(text, vals)
}

// redactOut serialises an output with every secret value replaced.
func (s *session) redactOut(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(s.redact(string(b))), nil
}

// redactErr redacts an error's message and details.
func (s *session) redactErr(err error) error {
	if err == nil {
		return nil
	}
	var je *jobs.Error
	if !errors.As(err, &je) {
		return jerr(jobs.HandlerFailed, "%s", s.redact(err.Error()))
	}
	out := &jobs.Error{Code: je.Code, Message: s.redact(je.Message)}
	if je.Details != nil {
		if b, e := json.Marshal(je.Details); e == nil {
			out.Details = json.RawMessage(s.redact(string(b)))
		}
	}
	return out
}

// restic runs the HOST restic binary: fixed argv, credentials via env only,
// SIGINT on cancel (restic then removes its lock; no snapshot is written).
func (s *session) restic(args []string, maxOut int) (execx.Result, error) {
	m := s.m
	timeout := 24 * time.Hour
	if dl, ok := s.ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		return execx.Result{}, context.DeadlineExceeded
	}
	cache := filepath.Join(m.o.WorkDir, "cache")
	_ = os.MkdirAll(cache, 0o700)
	env := append(s.creds.Env(), "RESTIC_CACHE_DIR="+cache, "HOME="+m.o.WorkDir)
	return m.o.Exec.RunCmd(s.ctx, execx.Cmd{Binary: m.o.ResticBin, Args: args, Env: env, Timeout: timeout,
		MaxOut: maxOut, Long: true, Interrupt: true})
}

// prepareHelper pins the helper image (pull by digest) and the repo host
// resolution used as the helper's ExtraHosts (helpers resolve the repo host
// exactly like the agent does).
func (s *session) prepareHelper(jobImage string) error {
	img, err := s.m.CheckHelperImage(jobImage)
	if err != nil {
		return err
	}
	e := s.m.o.Engine
	if e == nil {
		return jerr(containerops.CodeDockerUnavailable, "docker is not configured on this agent")
	}
	if err := e.Ping(s.ctx); err != nil {
		return jerr(containerops.CodeDockerUnavailable, "docker engine API not reachable")
	}
	s.image = img
	if !s.pulled {
		if err := e.PullImage(s.ctx, img, ""); err != nil {
			return s.dockerErr("pull helper image", err)
		}
		s.pulled = true
	}
	s.extraHosts = s.m.repoExtraHosts(s.ctx, s.repo)
	return nil
}

func (m *Manager) repoExtraHosts(ctx context.Context, repo RepoRef) []string {
	u, err := url.Parse(strings.TrimPrefix(repo.URL, "rest:"))
	if err != nil || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := m.o.Resolve(rctx, u.Hostname())
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return []string{u.Hostname() + ":" + a}
		}
	}
	return nil
}

func (s *session) dockerErr(op string, err error) *jobs.Error {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je
	}
	if docker.IsUnavailable(err) {
		return jerr(containerops.CodeDockerUnavailable, "docker engine not reachable during %s", op)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return jerr(CodeBackupFailed, "%s aborted: %v", op, err)
	}
	return jerr(jobs.HandlerFailed, "%s: %s", op, s.redact(err.Error()))
}

// helper fills the common helper fields.
func (s *session) helper(role, app, label string, cmd []string, env []string) HelperSpec {
	return HelperSpec{Role: role, App: app, RunLabel: label, Image: s.image, Cmd: cmd,
		Env: append(s.creds.Env(), env...), Network: "bridge", ExtraHosts: s.extraHosts, Hostname: s.m.o.Hostname}
}

func (s *session) runHelper(spec HelperSpec, inspect func(*helperRun, *HelperResult) error) (*HelperResult, error) {
	return runHelper(s.ctx, s.m.o.Engine, spec, s.log, inspect)
}

// ---------------- backup.snapshots ----------------

// SnapshotsOutput is the backup.snapshots output.
type SnapshotsOutput struct {
	Snapshots []Snapshot `json:"snapshots"`
}

// Snapshots implements backup.snapshots (read-only).
func (m *Manager) Snapshots(ctx context.Context, p SnapshotsParams) (any, error) {
	if err := m.CheckRestic(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	s, err := m.newSession(ctx, p.Repo, m.o.Log.With("job", "backup.snapshots"))
	if err != nil {
		return nil, err
	}
	args := []string{"-r", p.Repo.ResticURL(), "snapshots", "--json", "--no-lock"}
	if p.Tag != "" {
		args = append(args, "--tag", p.Tag)
	}
	res, err := s.restic(args, 32<<20)
	if err != nil {
		return nil, s.redactErr(jerr(CodeRepoUnreachable, "restic snapshots: %v", err))
	}
	if res.ExitCode != 0 {
		text := failureText(res.Stdout, res.Stderr)
		return nil, s.redactErr(jerr(ClassifyFailure(res.ExitCode, text, CodeRepoUnreachable), "restic snapshots exited %d: %s", res.ExitCode, text))
	}
	snaps, err := ParseSnapshots(res.Stdout)
	if err != nil {
		return nil, s.redactErr(jerr(jobs.HandlerFailed, "%v", err))
	}
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].Time < snaps[j].Time })
	return s.redactOut(SnapshotsOutput{Snapshots: snaps})
}

func timeLeft(ctx context.Context) string {
	if err := ctx.Err(); err != nil {
		return err.Error()
	}
	return ""
}

func abortedErr(ctx context.Context, what string) *jobs.Error {
	return jerr(CodeBackupFailed, "%s aborted (%s); restic writes no snapshot for an aborted run", what, timeLeft(ctx))
}

func fmtPort(p int) string { return fmt.Sprint(p) }
