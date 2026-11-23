package containerops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// Labels written on everything pPanel creates.
const (
	LabelManaged    = "ppanel.managed"
	LabelApp        = "ppanel.app"
	LabelDeployment = "ppanel.deployment"
	LabelImage      = "ppanel.image"
)

// Hardening constants (docs/AGENT_PROTOCOL.md "Hardened run").
var (
	CapAdd      = []string{"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE", "DAC_OVERRIDE"}
	SecurityOpt = []string{"no-new-privileges:true"}
)

const (
	// StopGraceSec is the stop/restart grace period.
	StopGraceSec = 10
	// LogTailLines is how many lines an unhealthy result carries.
	LogTailLines = 50
	// MaxLogBytes caps container.logs output.
	MaxLogBytes = 256 << 10
	// Redacted replaces secret values in returned text.
	Redacted = "[REDACTED]"
)

// Options configure a Manager.
type Options struct {
	Engine *docker.Engine
	// Secrets performs the one-time secrets fetch for the job in ctx.
	Secrets func(ctx context.Context) (*transport.JobSecrets, error)
	Log     *slog.Logger
	// HealthHost is where health probes go (default 127.0.0.1).
	HealthHost string
	// PortInUse overrides the loopback port check (tests).
	PortInUse func(port int) bool
	Now       func() time.Time
}

// Manager runs container jobs. One mutating job per app at a time.
type Manager struct {
	o     Options
	mu    sync.Mutex
	locks map[string]chan struct{}
	held  map[string][]string // app -> secret values held during a run job
}

// New returns a Manager.
func New(o Options) *Manager {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.HealthHost == "" {
		o.HealthHost = "127.0.0.1"
	}
	if o.PortInUse == nil {
		o.PortInUse = LoopbackPortInUse
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Manager{o: o, locks: map[string]chan struct{}{}, held: map[string][]string{}}
}

func jerr(code, format string, a ...any) *jobs.Error { return jobs.Errorf(code, format, a...) }

// lockApp serialises mutating jobs per app (ctx-aware).
func (m *Manager) lockApp(ctx context.Context, app string) (func(), error) {
	m.mu.Lock()
	ch, ok := m.locks[app]
	if !ok {
		ch = make(chan struct{}, 1)
		m.locks[app] = ch
	}
	m.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, jerr(jobs.HandlerTimeout, "timed out waiting for another container job of app %s", app)
	}
}

func (m *Manager) engine() (*docker.Engine, error) {
	if m.o.Engine == nil {
		return nil, jerr(CodeDockerUnavailable, "docker is not configured on this agent")
	}
	return m.o.Engine, nil
}

// dockerErr maps an engine error to a job error (no credentials in messages).
func (m *Manager) dockerErr(op string, err error, secrets []string) *jobs.Error {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je
	}
	if docker.IsUnavailable(err) {
		return jerr(CodeDockerUnavailable, "docker engine not reachable during %s", op)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return jerr(jobs.HandlerTimeout, "%s timed out", op)
	}
	return jerr(jobs.HandlerFailed, "%s: %s", op, Redact(err.Error(), secrets))
}

// LoopbackPortInUse reports whether 127.0.0.1:port is taken: something
// accepts a connection, or we cannot bind it ourselves. No exec involved.
func LoopbackPortInUse(port int) bool {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		return true
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	ln.Close()
	return false
}

// ---------------- redaction / log text ----------------

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// StripANSI removes ANSI escape sequences and other control characters (keeps \t, \n).
func StripANSI(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// Redact replaces every secret value in s with [REDACTED] (longest first).
func Redact(s string, secrets []string) string {
	if len(secrets) == 0 {
		return s
	}
	vs := append([]string(nil), secrets...)
	sort.Slice(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	for _, v := range vs {
		if v != "" {
			s = strings.ReplaceAll(s, v, Redacted)
		}
	}
	return s
}

// LogLines converts raw log text into clean, redacted lines; keeps the last
// maxLines and at most maxBytes (newest kept). truncated reports dropping.
func LogLines(text string, secrets []string, maxLines, maxBytes int) ([]string, bool) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return []string{}, false
	}
	// redact BEFORE stripping so a secret split by an escape code is still
	// caught on the raw text, then again after stripping.
	text = Redact(StripANSI(Redact(text, secrets)), secrets)
	all := strings.Split(text, "\n")
	truncated := false
	if len(all) > maxLines {
		all = all[len(all)-maxLines:]
		truncated = true
	}
	size := 0
	start := len(all)
	for i := len(all) - 1; i >= 0; i-- {
		if size+len(all[i])+1 > maxBytes {
			truncated = true
			break
		}
		size += len(all[i]) + 1
		start = i
	}
	return append([]string{}, all[start:]...), truncated
}

func (m *Manager) heldSecrets(app string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.held[app]...)
}

func (m *Manager) setHeld(app string, vals []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if vals == nil {
		delete(m.held, app)
		return
	}
	m.held[app] = vals
}

// ---------------- ownership ----------------

// owned applies the ownership rule. Only an inspect is made; anything that is
// not a pPanel-managed container of app → CONTAINER_NOT_MANAGED.
func (m *Manager) owned(ctx context.Context, e *docker.Engine, app, name string) (*docker.ContainerInfo, error) {
	if !NameMatchesApp(app, name) {
		return nil, jerr(CodeContainerNotManaged, "%s is not a pPanel-managed container name for app %s", name, app)
	}
	ci, err := e.InspectContainer(ctx, name)
	if errors.Is(err, docker.ErrNotFound) {
		return nil, jerr(CodeContainerNotFound, "container %s not found", name)
	}
	if err != nil {
		return nil, m.dockerErr("inspect", err, nil)
	}
	if !IsOwned(ci, app, name) {
		return nil, jerr(CodeContainerNotManaged, "container %s is not managed by pPanel for app %s", name, app)
	}
	return ci, nil
}

// IsOwned is the ownership rule applied to an inspected container.
func IsOwned(ci *docker.ContainerInfo, app, name string) bool {
	if ci == nil || ci.Name != "/"+name || !NameMatchesApp(app, name) {
		return false
	}
	l := ci.Config.Labels
	return l[LabelManaged] == "true" && l[LabelApp] == app
}

// ---------------- health ----------------

// Health is the health section of outputs.
type Health struct {
	Status     string `json:"status"`
	Attempts   int    `json:"attempts"`
	ElapsedMs  int64  `json:"elapsedMs"`
	LastStatus *int   `json:"lastStatus,omitempty"`
}

type unhealthy struct {
	reason     string
	exitCode   *int
	lastStatus *int
	lastError  string
	attempts   int
	elapsedMs  int64
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// waitHealthy polls http://<HealthHost>:<hostPort><path> until an expected
// status, the start period elapses, or the container stops running.
func (m *Manager) waitHealthy(ctx context.Context, e *docker.Engine, id string, hostPort int, hc Healthcheck) (*Health, *unhealthy, error) {
	client := &http.Client{
		Timeout:       time.Duration(hc.TimeoutSec) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	url := "http://" + net.JoinHostPort(m.o.HealthHost, strconv.Itoa(hostPort)) + hc.Path
	start := m.o.Now()
	deadline := start.Add(time.Duration(hc.StartPeriodSec) * time.Second)
	u := &unhealthy{}
	for {
		ci, err := e.InspectContainer(ctx, id)
		if err != nil {
			if errors.Is(err, docker.ErrNotFound) {
				u.reason = "container disappeared"
				break
			}
			return nil, nil, err
		}
		if !ci.State.Running || ci.State.Restarting || ci.State.Status == "exited" || ci.State.Status == "dead" {
			code := ci.State.ExitCode
			u.exitCode = &code
			u.reason = "container exited (status " + ci.State.Status + ")"
			break
		}
		u.attempts++
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req.Header.Set("User-Agent", "ppanel-agent-healthcheck")
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			st := resp.StatusCode
			u.lastStatus = &st
			u.lastError = ""
			if contains(hc.ExpectStatus, st) {
				return &Health{Status: "healthy", Attempts: u.attempts, ElapsedMs: m.o.Now().Sub(start).Milliseconds(), LastStatus: &st}, nil, nil
			}
		} else {
			u.lastError = strings.ReplaceAll(err.Error(), url, "health URL")
		}
		now := m.o.Now()
		if !now.Before(deadline) {
			u.reason = "not healthy within startPeriodSec"
			break
		}
		wait := time.Duration(hc.IntervalSec) * time.Second
		if rem := deadline.Sub(now); rem < wait {
			wait = rem
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	u.elapsedMs = m.o.Now().Sub(start).Milliseconds()
	return nil, u, nil
}

// logTail returns the last LogTailLines clean, redacted lines (best effort).
func (m *Manager) logTail(ctx context.Context, e *docker.Engine, id string, tty bool, secrets []string) []string {
	text, _, err := e.Logs(ctx, id, LogTailLines, 0, tty, MaxLogBytes)
	if err != nil {
		return []string{}
	}
	lines, _ := LogLines(text, secrets, LogTailLines, 64<<10)
	return lines
}

func unhealthyErr(name string, u *unhealthy, logTail []string, removed bool) *jobs.Error {
	e := jerr(CodeCandidateUnhealthy, "%s unhealthy: %s", name, u.reason)
	d := map[string]any{"logTail": logTail, "attempts": u.attempts, "elapsedMs": u.elapsedMs, "reason": u.reason, "removed": removed}
	if u.exitCode != nil {
		d["exitCode"] = *u.exitCode
	}
	if u.lastStatus != nil {
		d["lastStatus"] = *u.lastStatus
	}
	if u.lastError != "" {
		d["lastError"] = u.lastError
	}
	e.Details = d
	return e
}

// ---------------- run_candidate ----------------

// RunOutput is the success output of container.run_candidate.
type RunOutput struct {
	ContainerID string  `json:"containerId"`
	Name        string  `json:"name"`
	Image       string  `json:"image"`
	ImageID     string  `json:"imageId"`
	HostPort    int     `json:"hostPort"`
	Health      *Health `json:"health"`
}

// NetworkName is the per-app bridge network.
func NetworkName(app string) string { return "ppanel-" + app }

// VolumeName is the per-app named volume.
func VolumeName(app, name string) string { return "ppanel-" + app + "-" + name }

// CreateBody builds the hardened create body. env must already contain the
// secret values (they go only to the engine, never to logs/results).
func CreateBody(p RunParams, env map[string]string) map[string]any {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	envList := make([]string, 0, len(keys))
	for _, k := range keys {
		envList = append(envList, k+"="+env[k])
	}
	port := fmt.Sprintf("%d/tcp", p.ContainerPort)
	mounts := make([]map[string]any, 0, len(p.Volumes))
	for _, v := range p.Volumes {
		mounts = append(mounts, map[string]any{"Type": "volume", "Source": VolumeName(p.App, v.Name), "Target": v.MountPath, "ReadOnly": false})
	}
	mem := int64(p.Resources.MemoryMb) << 20
	pids := int64(p.Resources.Pids)
	hc := map[string]any{
		"PortBindings":    map[string]any{port: []map[string]string{{"HostIp": "127.0.0.1", "HostPort": strconv.Itoa(p.HostPort)}}},
		"PublishAllPorts": false,
		"Privileged":      false,
		"CapDrop":         []string{"ALL"},
		"CapAdd":          CapAdd,
		"SecurityOpt":     SecurityOpt,
		"Memory":          mem,
		"MemorySwap":      mem,
		"NanoCpus":        int64(p.Resources.Cpus * 1e9),
		"PidsLimit":       pids,
		"ReadonlyRootfs":  p.ReadOnlyRootfs,
		"RestartPolicy":   map[string]any{"Name": "unless-stopped"},
		"NetworkMode":     NetworkName(p.App),
		"IpcMode":         "private",
		"Mounts":          mounts,
		"LogConfig":       map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	labels := map[string]string{LabelManaged: "true", LabelApp: p.App, LabelDeployment: p.DeploymentID, LabelImage: p.Image}
	body := map[string]any{
		"Image":        p.Image,
		"Env":          envList,
		"Labels":       labels,
		"ExposedPorts": map[string]any{port: map[string]any{}},
		"Tty":          false,
		"OpenStdin":    false,
		"AttachStdin":  false,
		"AttachStdout": false,
		"AttachStderr": false,
		"HostConfig":   hc,
	}
	if p.Command != nil {
		body["Cmd"] = p.Command
	}
	if p.User != "" {
		body["User"] = p.User
	}
	return body
}

func managedLabels(app string) map[string]string {
	return map[string]string{LabelManaged: "true", LabelApp: app}
}

// RunCandidate implements container.run_candidate.
func (m *Manager) RunCandidate(ctx context.Context, p RunParams) (*RunOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockApp(ctx, p.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	log := m.o.Log.With("app", p.App, "name", p.Name)

	// 1. preflight
	if err := e.Ping(ctx); err != nil {
		return nil, jerr(CodeDockerUnavailable, "docker engine API not reachable on %s", e.Socket())
	}
	if _, err := e.InspectContainer(ctx, p.Name); err == nil {
		return nil, jerr(CodeContainerExists, "container %s already exists", p.Name)
	} else if !errors.Is(err, docker.ErrNotFound) {
		return nil, m.dockerErr("inspect", err, nil)
	}
	if m.o.PortInUse(p.HostPort) {
		return nil, jerr(CodePortInUse, "127.0.0.1:%d is already in use", p.HostPort)
	}

	// 2. secrets (fetched once, memory only)
	env := make(map[string]string, len(p.Env)+len(p.SecretEnvKeys))
	for k, v := range p.Env {
		env[k] = v
	}
	var secretVals []string
	authB64 := ""
	if len(p.SecretEnvKeys) > 0 || p.RegistryAuth {
		if m.o.Secrets == nil {
			return nil, jerr(CodeSecretsUnavailable, "secrets channel not configured")
		}
		s, err := m.o.Secrets(ctx)
		if err != nil {
			return nil, jerr(CodeSecretsUnavailable, "secrets fetch failed (%s)", secretsErrCode(err))
		}
		for _, k := range p.SecretEnvKeys {
			v, ok := s.Env[k]
			if !ok {
				return nil, jerr(CodeSecretsUnavailable, "secret %s not delivered", k)
			}
			env[k] = v
			secretVals = append(secretVals, v)
		}
		if p.RegistryAuth {
			if s.RegistryAuth == nil {
				return nil, jerr(CodeSecretsUnavailable, "registry credential not delivered")
			}
			b, _ := json.Marshal(map[string]string{"username": s.RegistryAuth.Username, "password": s.RegistryAuth.Password,
				"serveraddress": s.RegistryAuth.ServerAddress})
			authB64 = base64.URLEncoding.EncodeToString(b)
			secretVals = append(secretVals, s.RegistryAuth.Password)
		}
		log.Info("secrets received", "keys", len(p.SecretEnvKeys), "registryAuth", p.RegistryAuth)
	}
	m.setHeld(p.App, secretVals)
	defer m.setHeld(p.App, nil)

	// 3. pull by digest
	log.Info("pulling image", "image", p.Image)
	if err := e.PullImage(ctx, p.Image, authB64); err != nil {
		if docker.IsUnavailable(err) {
			return nil, jerr(CodeDockerUnavailable, "docker engine not reachable during pull")
		}
		msg := err.Error()
		var ae *docker.APIError
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		return nil, jerr(CodeImagePullFailed, "pull %s failed: %s", p.Image, Redact(msg, secretVals))
	}
	authB64 = ""
	img, err := e.InspectImage(ctx, p.Image)
	if err != nil {
		return nil, m.dockerErr("inspect image", err, secretVals)
	}

	// 4. network + volumes
	if err := m.ensureNetwork(ctx, e, p.App); err != nil {
		return nil, err
	}
	for _, v := range p.Volumes {
		vi, err := e.CreateVolume(ctx, VolumeName(p.App, v.Name), managedLabels(p.App))
		if err != nil {
			return nil, m.dockerErr("create volume", err, secretVals)
		}
		if vi.Labels[LabelManaged] != "true" || vi.Labels[LabelApp] != p.App {
			return nil, jerr(CodeContainerNotManaged, "volume %s exists but is not managed by pPanel for app %s", vi.Name, p.App)
		}
	}

	// 5. create (hardened)
	id, err := e.CreateContainer(ctx, p.Name, CreateBody(p, env))
	for k := range env {
		delete(env, k)
	}
	if err != nil {
		var ae *docker.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return nil, jerr(CodeContainerExists, "container %s already exists", p.Name)
		}
		return nil, m.dockerErr("create container", err, secretVals)
	}
	log.Info("candidate created", "containerId", short(id))

	// 6. start + health
	if err := e.StartContainer(ctx, id); err != nil {
		tail := m.logTail(ctx, e, id, false, secretVals)
		m.removeCandidate(e, id, log)
		msg := Redact(err.Error(), secretVals)
		if strings.Contains(msg, "port is already allocated") || strings.Contains(msg, "address already in use") {
			return nil, jerr(CodePortInUse, "127.0.0.1:%d is already in use (candidate removed)", p.HostPort)
		}
		return nil, unhealthyErr(p.Name, &unhealthy{reason: "start failed: " + msg}, tail, true)
	}
	h, u, err := m.waitHealthy(ctx, e, id, p.HostPort, p.Healthcheck)
	if err != nil {
		tail := m.logTail(context.Background(), e, id, false, secretVals)
		m.removeCandidate(e, id, log)
		u := &unhealthy{reason: "health loop aborted: " + Redact(err.Error(), secretVals)}
		return nil, unhealthyErr(p.Name, u, tail, true)
	}
	if u != nil {
		// 7. unhealthy → capture logs, remove candidate
		tail := m.logTail(ctx, e, id, false, secretVals)
		m.removeCandidate(e, id, log)
		log.Warn("candidate unhealthy; removed", "reason", u.reason, "attempts", u.attempts)
		return nil, unhealthyErr(p.Name, u, tail, true)
	}
	log.Info("candidate healthy", "attempts", h.Attempts, "elapsedMs", h.ElapsedMs)
	return &RunOutput{ContainerID: id, Name: p.Name, Image: p.Image, ImageID: img.ID, HostPort: p.HostPort, Health: h}, nil
}

func secretsErrCode(err error) string {
	if c := transport.Code(err); c != "" {
		return c
	}
	return "transport error"
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// removeCandidate force-removes a candidate this job created (volumes kept).
func (m *Manager) removeCandidate(e *docker.Engine, id string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.RemoveContainer(ctx, id, true); err != nil && !errors.Is(err, docker.ErrNotFound) {
		log.Error("candidate removal failed", "containerId", short(id), "error", err.Error())
	}
}

func (m *Manager) ensureNetwork(ctx context.Context, e *docker.Engine, app string) error {
	name := NetworkName(app)
	n, err := e.InspectNetwork(ctx, name)
	if err == nil {
		if n.Name != name || n.Labels[LabelManaged] != "true" {
			return jerr(CodeContainerNotManaged, "network %s exists but is not managed by pPanel", name)
		}
		return nil
	}
	if !errors.Is(err, docker.ErrNotFound) {
		return m.dockerErr("inspect network", err, nil)
	}
	if err := e.CreateNetwork(ctx, name, managedLabels(app)); err != nil {
		var ae *docker.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return nil
		}
		return m.dockerErr("create network", err, nil)
	}
	return nil
}

// ---------------- start / restart / stop / remove ----------------

// StartOutput is the output of container.start / container.restart.
type StartOutput struct {
	Name   string  `json:"name"`
	Health *Health `json:"health"`
}

// StateOutput is the output of container.stop / container.remove.
type StateOutput struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

func boundHostPort(ci *docker.ContainerInfo) (int, bool) {
	for _, bs := range ci.HostConfig.PortBindings {
		for _, b := range bs {
			if b.HostIP == "127.0.0.1" {
				if n, err := strconv.Atoi(b.HostPort); err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

// Start implements container.start (restart=false) and container.restart.
func (m *Manager) Start(ctx context.Context, p StartParams, restart bool) (*StartOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockApp(ctx, p.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ci, err := m.owned(ctx, e, p.App, p.Name)
	if err != nil {
		return nil, err
	}
	if hp, ok := boundHostPort(ci); !ok || hp != p.HostPort {
		return nil, jerr(jobs.HandlerFailed, "container %s is not bound to 127.0.0.1:%d", p.Name, p.HostPort)
	}
	if restart {
		err = e.RestartContainer(ctx, ci.ID, StopGraceSec)
	} else {
		err = e.StartContainer(ctx, ci.ID)
	}
	op := map[bool]string{true: "restart", false: "start"}[restart]
	if err != nil {
		tail := m.logTail(ctx, e, ci.ID, ci.Config.Tty, m.heldSecrets(p.App))
		m.stopQuiet(e, ci.ID)
		var ae *docker.APIError
		if errors.As(err, &ae) {
			return nil, unhealthyErr(p.Name, &unhealthy{reason: op + " failed: " + ae.Message}, tail, false)
		}
		return nil, m.dockerErr(op, err, nil)
	}
	h, u, err := m.waitHealthy(ctx, e, ci.ID, p.HostPort, p.Healthcheck)
	if err != nil {
		m.stopQuiet(e, ci.ID)
		return nil, m.dockerErr("health check", err, nil)
	}
	if u != nil {
		tail := m.logTail(ctx, e, ci.ID, ci.Config.Tty, m.heldSecrets(p.App))
		m.stopQuiet(e, ci.ID) // left stopped, NOT removed (rollback target)
		return nil, unhealthyErr(p.Name, u, tail, false)
	}
	return &StartOutput{Name: p.Name, Health: h}, nil
}

func (m *Manager) stopQuiet(e *docker.Engine, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), (StopGraceSec+20)*time.Second)
	defer cancel()
	if err := e.StopContainer(ctx, id, StopGraceSec); err != nil && !errors.Is(err, docker.ErrNotFound) {
		m.o.Log.Error("stop after failed health check failed", "containerId", short(id), "error", err.Error())
	}
}

// Stop implements container.stop (10 s grace; container kept).
func (m *Manager) Stop(ctx context.Context, p RefParams) (*StateOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockApp(ctx, p.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ci, err := m.owned(ctx, e, p.App, p.Name)
	if err != nil {
		return nil, err
	}
	if err := e.StopContainer(ctx, ci.ID, StopGraceSec); err != nil {
		return nil, m.dockerErr("stop", err, nil)
	}
	st := "exited"
	if after, err := e.InspectContainer(ctx, ci.ID); err == nil {
		st = after.State.Status
	}
	return &StateOutput{Name: p.Name, State: st}, nil
}

// CodeContainerRunning is returned by container.remove for a running container
// (HANDLER_FAILED family; the Center must stop first).
const CodeContainerRunning = jobs.HandlerFailed

// Remove implements container.remove (refuses running; never removes volumes).
func (m *Manager) Remove(ctx context.Context, p RefParams) (*StateOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockApp(ctx, p.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ci, err := m.owned(ctx, e, p.App, p.Name)
	if err != nil {
		return nil, err
	}
	if ci.State.Running || ci.State.Restarting {
		je := jerr(CodeContainerRunning, "container %s is running; stop it first", p.Name)
		je.Details = map[string]any{"state": ci.State.Status}
		return nil, je
	}
	if err := e.RemoveContainer(ctx, ci.ID, false); err != nil {
		return nil, m.dockerErr("remove", err, nil)
	}
	return &StateOutput{Name: p.Name, State: "removed"}, nil
}

// ---------------- list / logs ----------------

// ListEntry is one container.list entry.
type ListEntry struct {
	Name         string `json:"name"`
	ID           string `json:"id"`
	App          string `json:"app"`
	Image        string `json:"image"`
	State        string `json:"state"`
	Status       string `json:"status"`
	HostPort     *int   `json:"hostPort"`
	DeploymentID string `json:"deploymentId"`
	CreatedAt    string `json:"createdAt"`
}

// ListOutput is the output of container.list.
type ListOutput struct {
	Containers []ListEntry `json:"containers"`
}

// List implements container.list (read-only).
func (m *Manager) List(ctx context.Context, p ListParams) (*ListOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	filters := []string{LabelManaged + "=true"}
	if p.App != "" {
		filters = append(filters, LabelApp+"="+p.App)
	}
	cs, err := e.ListContainers(ctx, filters)
	if err != nil {
		return nil, m.dockerErr("list", err, nil)
	}
	out := &ListOutput{Containers: []ListEntry{}}
	for _, c := range cs {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		app := c.Labels[LabelApp]
		if c.Labels[LabelManaged] != "true" || !NameMatchesApp(app, name) || (p.App != "" && app != p.App) {
			continue
		}
		img := c.Labels[LabelImage]
		if img == "" {
			img = c.Image
		}
		ent := ListEntry{Name: name, ID: c.ID, App: app, Image: img, State: c.State, Status: c.Status,
			DeploymentID: c.Labels[LabelDeployment], CreatedAt: time.Unix(c.Created, 0).UTC().Format(time.RFC3339)}
		for _, pt := range c.Ports {
			if pt.IP == "127.0.0.1" && pt.PublicPort > 0 {
				hp := pt.PublicPort
				ent.HostPort = &hp
				break
			}
		}
		out.Containers = append(out.Containers, ent)
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].CreatedAt > out.Containers[j].CreatedAt })
	return out, nil
}

// LogsOutput is the output of container.logs.
type LogsOutput struct {
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}

// Logs implements container.logs (read-only, bounded, ANSI-stripped, redacted).
func (m *Manager) Logs(ctx context.Context, p LogsParams) (*LogsOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	ci, err := m.owned(ctx, e, p.App, p.Name)
	if err != nil {
		return nil, err
	}
	var since int64
	if p.SinceSec > 0 {
		since = m.o.Now().Add(-time.Duration(p.SinceSec) * time.Second).Unix()
	}
	text, truncated, err := e.Logs(ctx, ci.ID, p.TailLines, since, ci.Config.Tty, MaxLogBytes)
	if err != nil {
		return nil, m.dockerErr("logs", err, nil)
	}
	lines, t2 := LogLines(text, m.heldSecrets(p.App), p.TailLines, MaxLogBytes)
	return &LogsOutput{Lines: lines, Truncated: truncated || t2}, nil
}
