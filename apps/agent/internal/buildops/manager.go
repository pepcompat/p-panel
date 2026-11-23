package buildops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/buildtemplates"
	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// Log bounds (protocol: ≤ 2000 lines / 512 KiB; logTail = last 200 lines).
const (
	MaxLogLines   = 2000
	MaxLogBytes   = 512 << 10
	LogTailLines  = 200
	maxInspectLen = 64 << 10
	rawLogKeep    = 4 << 20
)

// Labels written on every built image.
const (
	LabelBuild  = "ppanel.build"
	LabelApp    = "ppanel.app"
	LabelCommit = "ppanel.commit"
)

// Options configure a Manager. A Manager exists only on build.enabled agents.
type Options struct {
	// Engine must come from docker.NewBuildEngine.
	Engine *docker.Engine
	Exec   execx.CmdRunner
	// GitBinary is the absolute path of git ("" = not installed).
	GitBinary string
	// WorkDir holds per-job temp dirs (<stateDir>/builds by default).
	WorkDir string
	// AllowedHosts are exact git host[:port] entries (build.gitHostsAllowlist).
	AllowedHosts []string
	Secrets      func(ctx context.Context) (*transport.JobSecrets, error)
	Log          *slog.Logger
	Now          func() time.Time
	// MaxContextBytes overrides the 500 MiB context cap (tests).
	MaxContextBytes int64
}

// Manager runs image.build / source.inspect.
type Manager struct {
	o       Options
	allowed map[string]bool
	builds  chan struct{} // one build at a time per build node
}

// New returns a Manager.
func New(o Options) *Manager {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Exec == nil {
		o.Exec = execx.System{}
	}
	if o.MaxContextBytes <= 0 {
		o.MaxContextBytes = DefaultMaxContextBytes
	}
	m := &Manager{o: o, allowed: map[string]bool{}, builds: make(chan struct{}, 1)}
	for _, h := range o.AllowedHosts {
		m.allowed[strings.ToLower(h)] = true
	}
	return m
}

func jerr(code, format string, a ...any) *jobs.Error { return jobs.Errorf(code, format, a...) }

// CheckHost applies the git host allowlist (pure; used before ack too).
func (m *Manager) CheckHost(s GitSource) error {
	hp := s.HostPort()
	if hp == "" || !m.allowed[hp] {
		return jerr(CodeGitHostNotAllowed, "git host %q is not in this build node's build.gitHostsAllowlist", hp)
	}
	return nil
}

// ---------------- secrets ----------------

type creds struct {
	gitHeader string
	authB64   string
	redact    []string
}

var headerRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}: [\x20-\x7e]+$`)

func (m *Manager) fetchSecrets(ctx context.Context, needGit, needRegistry bool) (*creds, error) {
	c := &creds{}
	if !needGit && !needRegistry {
		return c, nil
	}
	if m.o.Secrets == nil {
		return nil, jerr(containerops.CodeSecretsUnavailable, "secrets channel not configured")
	}
	s, err := m.o.Secrets(ctx)
	if err != nil {
		code := transport.Code(err)
		if code == "" {
			code = "transport error"
		}
		return nil, jerr(containerops.CodeSecretsUnavailable, "secrets fetch failed (%s)", code)
	}
	if needGit {
		if s.GitAuth == nil || len(s.GitAuth.Header) > 8192 || !headerRe.MatchString(s.GitAuth.Header) {
			return nil, jerr(containerops.CodeSecretsUnavailable, "git auth header not delivered")
		}
		c.gitHeader = s.GitAuth.Header
		c.redact = append(c.redact, secretFragments(s.GitAuth.Header)...)
	}
	if needRegistry {
		if s.RegistryAuth == nil {
			return nil, jerr(containerops.CodeSecretsUnavailable, "registry credential not delivered")
		}
		b, _ := json.Marshal(map[string]string{"username": s.RegistryAuth.Username, "password": s.RegistryAuth.Password,
			"serveraddress": s.RegistryAuth.ServerAddress})
		c.authB64 = base64.URLEncoding.EncodeToString(b)
		c.redact = append(c.redact, s.RegistryAuth.Password, c.authB64)
	}
	return c, nil
}

// secretFragments returns every form of an auth header worth redacting: the
// whole header, its value, the credential after the scheme and, for Basic,
// the decoded user:token and the token alone.
func secretFragments(header string) []string {
	out := []string{header}
	_, val, ok := strings.Cut(header, ": ")
	if !ok {
		return out
	}
	out = append(out, val)
	if _, cred, ok := strings.Cut(val, " "); ok && cred != "" {
		out = append(out, cred)
		if dec, err := base64.StdEncoding.DecodeString(cred); err == nil && len(dec) > 0 {
			out = append(out, string(dec))
			if _, tok, ok := strings.Cut(string(dec), ":"); ok && len(tok) >= 4 {
				out = append(out, tok)
			}
		}
	}
	return out
}

// ---------------- work dirs ----------------

var dirNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func (m *Manager) jobDir(name string) (string, error) {
	if m.o.WorkDir == "" || !filepath.IsAbs(m.o.WorkDir) {
		return "", jerr(jobs.HandlerFailed, "build work directory not configured")
	}
	if !dirNameRe.MatchString(name) {
		return "", jerr(jobs.HandlerFailed, "invalid work directory name")
	}
	if err := os.MkdirAll(m.o.WorkDir, 0o700); err != nil {
		return "", jerr(jobs.HandlerFailed, "create build work directory: %v", err)
	}
	dir := filepath.Join(m.o.WorkDir, name)
	_ = os.RemoveAll(dir) // leftover of an interrupted attempt
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", jerr(jobs.HandlerFailed, "create job directory: %v", err)
	}
	return dir, nil
}

// ---------------- git fetch ----------------

// errFetchTimeout marks a fetch that ran out of the job's time budget.
var errFetchTimeout = errors.New("source fetch timed out")

// gitEnv is the complete extra environment for git: no prompts, no system or
// global config, temp HOME, protocol allowlist, hooks disabled, no redirects
// and (optionally) the auth header via GIT_CONFIG_* — never argv.
func gitEnv(home, scheme, header string) []string {
	env := []string{
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + home,
		"GIT_ALLOW_PROTOCOL=" + scheme, "GIT_LFS_SKIP_SMUDGE=1", "GIT_ASKPASS=/bin/false",
	}
	cfg := [][2]string{
		{"core.hooksPath", "/dev/null"}, {"http.followRedirects", "false"},
		{"submodule.recurse", "false"}, {"fetch.recurseSubmodules", "false"}, {"core.symlinks", "true"},
	}
	if header != "" {
		cfg = append(cfg, [2]string{"http.extraHeader", header})
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(cfg)))
	for i, kv := range cfg {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return env
}

// fetch checks out src.CommitSha into <dir>/src and returns that path.
func (m *Manager) fetch(ctx context.Context, dir string, src GitSource, c *creds) (string, error) {
	if m.o.GitBinary == "" {
		return "", jerr(CodeSourceFetchFailed, "git binary not found on this build node")
	}
	scheme := src.Scheme()
	if scheme != "https" && scheme != "git" {
		return "", jerr(CodeSourceFetchFailed, "unsupported URL scheme")
	}
	if err := m.CheckHost(src); err != nil {
		return "", err
	}
	home, work := filepath.Join(dir, "home"), filepath.Join(dir, "src")
	for _, d := range []string{home, work} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return "", jerr(jobs.HandlerFailed, "create %s: %v", filepath.Base(d), err)
		}
	}
	env := gitEnv(home, scheme, c.gitHeader)
	steps := [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", src.URL},
		{"-c", "protocol.version=2", "fetch", "--depth", "1", "--no-tags", "origin", src.CommitSha},
		{"checkout", "-q", "--detach", "FETCH_HEAD"},
		{"rev-parse", "HEAD"},
	}
	var head string
	for _, args := range steps {
		left := 10 * time.Minute
		if dl, ok := ctx.Deadline(); ok {
			left = time.Until(dl)
		}
		if left <= 0 {
			return "", errFetchTimeout
		}
		if left > 10*time.Minute {
			left = 10 * time.Minute
		}
		res, err := m.o.Exec.RunCmd(ctx, execx.Cmd{Binary: m.o.GitBinary, Args: args, Env: env, Dir: work, Timeout: left, MaxOut: 1 << 20})
		step := args[0]
		if step == "-c" {
			step = args[2]
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return "", errFetchTimeout
			}
			return "", jerr(CodeSourceFetchFailed, "git %s: %s", step, containerops.Redact(err.Error(), c.redact))
		}
		if res.ExitCode != 0 {
			msg := strings.TrimSpace(containerops.StripANSI(containerops.Redact(string(res.Stderr), c.redact)))
			if len(msg) > 1000 {
				msg = msg[len(msg)-1000:]
			}
			return "", jerr(CodeSourceFetchFailed, "git %s failed (exit %d): %s", step, res.ExitCode, msg)
		}
		if step == "rev-parse" {
			head = strings.TrimSpace(string(res.Stdout))
		}
	}
	if head != src.CommitSha {
		return "", jerr(CodeSourceFetchFailed, "checked out HEAD %s does not match commitSha %s", head, src.CommitSha)
	}
	return work, nil
}

// contextRoot resolves source.subdir inside the checkout (no symlink escape).
func contextRoot(checkout string, src GitSource) (string, error) {
	root, err := resolveInside(checkout, src.Subdir)
	if err != nil {
		if errors.Is(err, errEscape) {
			return "", jerr(CodeSourceFetchFailed, "subdir %q resolves outside the checkout (symlink escape)", src.Subdir)
		}
		return "", jerr(CodeSourceFetchFailed, "subdir %q not found in commit %s", src.Subdir, src.CommitSha)
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return "", jerr(CodeSourceFetchFailed, "subdir %q is not a directory", src.Subdir)
	}
	return root, nil
}

// ---------------- image.build ----------------

// BuildOutput is the image.build success output (exact protocol field names).
type BuildOutput struct {
	Image      string   `json:"image"`
	Tag        string   `json:"tag"`
	CommitSha  string   `json:"commitSha"`
	DurationMs int64    `json:"durationMs"`
	LogTail    []string `json:"logTail"`
	Template   string   `json:"template,omitempty"`
	Log        []string `json:"log"`
}

// buildLog accumulates the raw build/push stream text (newest kept).
type buildLog struct {
	b       strings.Builder
	dropped bool
}

func (l *buildLog) add(s string) {
	l.b.WriteString(s)
	if l.b.Len() > 2*rawLogKeep {
		keep := l.b.String()[l.b.Len()-rawLogKeep:]
		l.b.Reset()
		l.b.WriteString(keep)
		l.dropped = true
	}
}

func (l *buildLog) lines(secrets []string) []string {
	text := l.b.String()
	if l.dropped {
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		}
	}
	lines, _ := containerops.LogLines(text, secrets, MaxLogLines, MaxLogBytes)
	return lines
}

func tail(lines []string, n int) []string {
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return append([]string{}, lines...)
}

func (m *Manager) failure(code, msg string, lg *buildLog, secrets []string) *jobs.Error {
	e := jerr(code, "%s", containerops.Redact(msg, secrets))
	all := lg.lines(secrets)
	e.Details = map[string]any{"logTail": tail(all, LogTailLines), "log": all}
	return e
}

// Build implements image.build.
func (m *Manager) Build(ctx context.Context, p BuildParams) (*BuildOutput, error) {
	start := m.o.Now()
	if m.o.Engine == nil || !m.o.Engine.BuildCapable() {
		return nil, jerr(CodeNotABuildNode, "this agent has no build engine")
	}
	if err := m.CheckHost(p.Source); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Limits.TimeoutSec)*time.Second)
	defer cancel()
	select {
	case m.builds <- struct{}{}:
		defer func() { <-m.builds }()
	case <-ctx.Done():
		return nil, jerr(CodeBuildTimeout, "timed out waiting for another build on this node")
	}
	log := m.o.Log.With("buildId", p.BuildID, "app", p.App)
	e := m.o.Engine
	if err := e.Ping(ctx); err != nil {
		return nil, jerr(containerops.CodeDockerUnavailable, "docker engine API not reachable on %s", e.Socket())
	}
	c, err := m.fetchSecrets(ctx, p.Source.Auth, p.RegistryAuth)
	if err != nil {
		return nil, err
	}
	dir, err := m.jobDir(p.BuildID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Error("build dir cleanup failed", "error", err.Error())
		}
	}()

	// 1. source
	log.Info("fetching source", "host", p.Source.HostPort(), "commit", p.Source.CommitSha)
	checkout, err := m.fetch(ctx, dir, p.Source, c)
	if errors.Is(err, errFetchTimeout) {
		return nil, jerr(CodeBuildTimeout, "source fetch exceeded limits.timeoutSec (%ds)", p.Limits.TimeoutSec)
	}
	if err != nil {
		return nil, err
	}
	root, err := contextRoot(checkout, p.Source)
	if err != nil {
		return nil, err
	}

	// 2. context tar (temp file next to the checkout, never inside it)
	spec := contextSpec{Root: root, MaxBytes: m.o.MaxContextBytes}
	dockerfile := p.Dockerfile
	if p.Template != "" {
		tpl, err := buildtemplates.Get(p.Template)
		if err != nil {
			return nil, jerr(jobs.HandlerFailed, "%v", err)
		}
		spec.Template, spec.TemplateAs, dockerfile = tpl, buildtemplates.FileName, buildtemplates.FileName
	} else {
		df, err := resolveInside(root, p.Dockerfile)
		if err != nil {
			return nil, jerr(CodeDockerfileNotFound, "dockerfile %q not found inside the build context", p.Dockerfile)
		}
		if st, err := os.Stat(df); err != nil || !st.Mode().IsRegular() {
			return nil, jerr(CodeDockerfileNotFound, "dockerfile %q is not a regular file inside the build context", p.Dockerfile)
		}
		spec.Dockerfile = p.Dockerfile
	}
	tarPath := filepath.Join(dir, "context.tar")
	tf, err := os.OpenFile(tarPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, jerr(jobs.HandlerFailed, "create context archive: %v", err)
	}
	defer tf.Close()
	nfiles, size, err := writeContext(spec, tf)
	if err != nil {
		switch {
		case errors.Is(err, errContextTooLarge):
			return nil, jerr(CodeSourceFetchFailed, "build context exceeds %d MiB", m.o.MaxContextBytes>>20)
		case errors.Is(err, errEscape):
			return nil, jerr(CodeSourceFetchFailed, "%v", err)
		}
		return nil, jerr(CodeSourceFetchFailed, "assemble build context: %v", err)
	}
	if _, err := tf.Seek(0, io.SeekStart); err != nil {
		return nil, jerr(jobs.HandlerFailed, "context archive: %v", err)
	}
	log.Info("build context ready", "files", nfiles, "bytes", size)

	// 3. build (classic builder)
	ref := p.PushRepo + ":" + p.Tag()
	q := url.Values{
		"t": {ref}, "dockerfile": {dockerfile}, "rm": {"1"}, "forcerm": {"1"}, "pull": {"1"},
		"memory": {strconv.FormatInt(int64(p.Limits.MemoryMb)<<20, 10)}, "memswap": {strconv.FormatInt(int64(p.Limits.MemoryMb)<<20, 10)},
		"cpuperiod": {"100000"}, "cpuquota": {strconv.FormatInt(int64(p.Limits.Cpus*100000), 10)}, "networkmode": {p.Network},
	}
	ba, _ := json.Marshal(p.BuildArgs)
	q.Set("buildargs", string(ba))
	lb, _ := json.Marshal(map[string]string{LabelBuild: p.BuildID, LabelApp: p.App, LabelCommit: p.Source.CommitSha})
	q.Set("labels", string(lb))
	if p.Target != "" {
		q.Set("target", p.Target)
	}
	lg := &buildLog{}
	defer m.removeTag(e, ref, log) // local build image never kept (pushed or not)
	var buildErr string
	err = e.Build(ctx, q, tf, func(msg *docker.StreamMsg) error {
		if em := msg.ErrMessage(); em != "" {
			buildErr = em
			lg.add("ERROR: " + em + "\n")
			return nil
		}
		if msg.Stream != "" {
			lg.add(msg.Stream)
		} else if msg.Status != "" && msg.Progress == "" {
			if msg.ID != "" {
				lg.add(msg.ID + ": ")
			}
			lg.add(msg.Status + "\n")
		}
		return nil
	})
	switch {
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		// the request (and so the classic build) is cancelled by closing it; also ask the daemon
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = e.CancelBuild(cctx, p.BuildID)
		ccancel()
		log.Warn("build timed out; cancelled", "timeoutSec", p.Limits.TimeoutSec)
		return nil, m.failure(CodeBuildTimeout, fmt.Sprintf("build exceeded limits.timeoutSec (%ds) and was cancelled", p.Limits.TimeoutSec), lg, c.redact)
	case err != nil && docker.IsUnavailable(err):
		return nil, jerr(containerops.CodeDockerUnavailable, "docker engine not reachable during build")
	case err != nil:
		msg := err.Error()
		var ae *docker.APIError
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return nil, m.failure(CodeBuildFailed, "build failed: "+msg, lg, c.redact)
	case buildErr != "":
		return nil, m.failure(CodeBuildFailed, "build failed: "+buildErr, lg, c.redact)
	}
	log.Info("build finished; pushing", "ref", ref)

	// 4. push; digest from aux.Digest
	var digest, statusDigest, pushErr string
	lg.add("pushing " + ref + "\n")
	err = e.PushImage(ctx, p.PushRepo, p.Tag(), c.authB64, func(msg *docker.StreamMsg) error {
		if em := msg.ErrMessage(); em != "" {
			pushErr = em
			lg.add("ERROR: " + em + "\n")
			return nil
		}
		if len(msg.Aux) > 0 {
			var aux struct {
				Tag    string `json:"Tag"`
				Digest string `json:"Digest"`
			}
			if json.Unmarshal(msg.Aux, &aux) == nil && aux.Digest != "" {
				digest = aux.Digest
			}
		}
		if msg.Status != "" && msg.Progress == "" && msg.ID == "" {
			lg.add(msg.Status + "\n")
			// Docker ≥ 25 with the containerd image store sends no aux message; the final
			// status line "<tag>: digest: sha256:<64> size: <n>" (for OUR tag only) is the fallback.
			if m := pushDigestRe.FindStringSubmatch(msg.Status); m != nil && m[1] == p.Tag() && statusDigest == "" {
				statusDigest = m[2]
			}
		}
		return nil
	})
	if digest == "" {
		digest = statusDigest
	}
	switch {
	case ctx.Err() != nil:
		return nil, m.failure(CodePushFailed, "push timed out (limits.timeoutSec)", lg, c.redact)
	case err != nil && docker.IsUnavailable(err):
		return nil, jerr(containerops.CodeDockerUnavailable, "docker engine not reachable during push")
	case err != nil:
		msg := err.Error()
		var ae *docker.APIError
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return nil, m.failure(CodePushFailed, "push failed: "+msg, lg, c.redact)
	case pushErr != "":
		return nil, m.failure(CodePushFailed, "push failed: "+pushErr, lg, c.redact)
	case !digestRe.MatchString(digest):
		return nil, m.failure(CodePushFailed, "push stream carried no aux.Digest (nor a digest status line for this tag)", lg, c.redact)
	}
	lg.add("pushed " + p.PushRepo + "@" + digest + "\n")
	c.authB64 = ""
	all := lg.lines(c.redact)
	out := &BuildOutput{Image: p.PushRepo + "@" + digest, Tag: p.Tag(), CommitSha: p.Source.CommitSha,
		DurationMs: m.o.Now().Sub(start).Milliseconds(), LogTail: tail(all, LogTailLines), Template: p.Template, Log: all}
	log.Info("build pushed", "image", out.Image, "durationMs", out.DurationMs)
	return out, nil
}

var (
	digestRe     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	pushDigestRe = regexp.MustCompile(`^(build-[a-f0-9]{12}): digest: (sha256:[a-f0-9]{64}) size: [0-9]+$`)
)

func (m *Manager) removeTag(e *docker.Engine, ref string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.RemoveImage(ctx, ref); err != nil && !errors.Is(err, docker.ErrNotFound) {
		log.Warn("local build tag removal failed", "ref", ref, "error", err.Error())
	}
}

// ---------------- source.inspect ----------------

// InspectOutput is the source.inspect output.
type InspectOutput struct {
	CommitSha string            `json:"commitSha"`
	Files     map[string]string `json:"files"`
	Truncated []string          `json:"truncated"`
}

// InspectTimeout bounds a source.inspect fetch.
const InspectTimeout = 5 * time.Minute

// Inspect implements source.inspect (read-only; temp dir removed after).
func (m *Manager) Inspect(ctx context.Context, p InspectParams) (*InspectOutput, error) {
	if err := m.CheckHost(p.Source); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, InspectTimeout)
	defer cancel()
	c, err := m.fetchSecrets(ctx, p.Source.Auth, false)
	if err != nil {
		return nil, err
	}
	name := "inspect-" + strings.ReplaceAll(jobs.JobID(ctx), "_", "-")
	if jobs.JobID(ctx) == "" || !dirNameRe.MatchString(name) {
		name = "inspect-" + transport.NewUUID()
	}
	dir, err := m.jobDir(name)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	checkout, err := m.fetch(ctx, dir, p.Source, c)
	if errors.Is(err, errFetchTimeout) {
		return nil, jerr(CodeSourceFetchFailed, "source fetch timed out after %s", InspectTimeout)
	}
	if err != nil {
		return nil, err
	}
	root, err := contextRoot(checkout, p.Source)
	if err != nil {
		return nil, err
	}
	out := &InspectOutput{CommitSha: p.Source.CommitSha, Files: map[string]string{}, Truncated: []string{}}
	for _, n := range SourceInspectFiles {
		fp := filepath.Join(root, n)
		st, err := os.Lstat(fp)
		if err != nil || !st.Mode().IsRegular() {
			continue // missing, symlink, dir: not reported
		}
		if st.Size() > maxInspectLen {
			out.Truncated = append(out.Truncated, n)
			continue
		}
		b, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		if len(b) > maxInspectLen {
			out.Truncated = append(out.Truncated, n)
			continue
		}
		out.Files[n] = string(b)
	}
	return out, nil
}
