package containerops

// P4b compose execution (docs/AGENT_PROTOCOL.md "Compose (P4b) — authoritative").
// The agent never parses YAML: the Center sends a normalised, topologically
// sorted plan of services pinned by digest. Every service container gets the
// same hardened HostConfig as container.run_candidate; only the route service
// gets a 127.0.0.1 host port; all join ppanel-<app> with DNS alias = service.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// CodeComposeServiceUnhealthy is the compose failure code (BUILD_ERROR_CODES).
const CodeComposeServiceUnhealthy = "COMPOSE_SERVICE_UNHEALTHY"

var specHashRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ComposeHealth is the normalised service health check.
type ComposeHealth struct {
	Type           string `json:"type"` // http|tcp|running
	Port           int    `json:"port,omitempty"`
	Path           string `json:"path,omitempty"`
	ExpectStatus   []int  `json:"expectStatus,omitempty"`
	IntervalSec    int    `json:"intervalSec,omitempty"`
	TimeoutSec     int    `json:"timeoutSec,omitempty"`
	StartPeriodSec int    `json:"startPeriodSec"`
}

// ComposeService mirrors composeServiceSchema (defaults applied).
type ComposeService struct {
	Service       string            `json:"service"`
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	SpecHash      string            `json:"specHash"`
	Env           map[string]string `json:"env"`
	SecretEnv     map[string]string `json:"secretEnv"`
	Command       []string          `json:"command,omitempty"`
	Volumes       []Volume          `json:"volumes"`
	DependsOn     []string          `json:"dependsOn"`
	Health        ComposeHealth     `json:"health"`
	Resources     Resources         `json:"resources"`
	HostPort      int               `json:"hostPort,omitempty"`
	ContainerPort int               `json:"containerPort,omitempty"`
}

// ComposeApplyParams is compose.apply.
type ComposeApplyParams struct {
	DeploymentID string           `json:"deploymentId"`
	App          string           `json:"app"`
	Services     []ComposeService `json:"services"`
	RouteService string           `json:"routeService,omitempty"`
	RegistryAuth bool             `json:"registryAuth"`
}

// ComposeStopParams is compose.stop.
type ComposeStopParams struct {
	App string `json:"app"`
}

type rawComposeHealth struct {
	Type           *string `json:"type"`
	Port           *int    `json:"port"`
	Path           *string `json:"path"`
	ExpectStatus   []int   `json:"expectStatus"`
	IntervalSec    *int    `json:"intervalSec"`
	TimeoutSec     *int    `json:"timeoutSec"`
	StartPeriodSec *int    `json:"startPeriodSec"`
}

func (r *rawComposeHealth) resolve(svc string) (ComposeHealth, error) {
	if r == nil {
		return ComposeHealth{Type: "running", StartPeriodSec: 10}, nil
	}
	if r.Type == nil {
		return ComposeHealth{}, invalid("services[%s].health.type is required", svc)
	}
	port := func() (int, error) {
		if r.Port == nil || *r.Port < 1 || *r.Port > 65535 {
			return 0, invalid("services[%s].health.port must be 1..65535", svc)
		}
		return *r.Port, nil
	}
	httpOnly := r.Path != nil || r.ExpectStatus != nil || r.IntervalSec != nil || r.TimeoutSec != nil
	switch *r.Type {
	case "http":
		p, err := port()
		if err != nil {
			return ComposeHealth{}, err
		}
		hc, err := (&rawHealth{Path: r.Path, ExpectStatus: r.ExpectStatus, IntervalSec: r.IntervalSec, TimeoutSec: r.TimeoutSec, StartPeriodSec: r.StartPeriodSec}).resolve()
		if err != nil {
			return ComposeHealth{}, err
		}
		return ComposeHealth{Type: "http", Port: p, Path: hc.Path, ExpectStatus: hc.ExpectStatus, IntervalSec: hc.IntervalSec,
			TimeoutSec: hc.TimeoutSec, StartPeriodSec: hc.StartPeriodSec}, nil
	case "tcp":
		if httpOnly {
			return ComposeHealth{}, invalid("services[%s].health: tcp accepts only type, port, startPeriodSec", svc)
		}
		p, err := port()
		if err != nil {
			return ComposeHealth{}, err
		}
		sp, err := intIn("health.startPeriodSec", r.StartPeriodSec, 60, 1, 600)
		if err != nil {
			return ComposeHealth{}, err
		}
		return ComposeHealth{Type: "tcp", Port: p, StartPeriodSec: sp}, nil
	case "running":
		if httpOnly || r.Port != nil {
			return ComposeHealth{}, invalid("services[%s].health: running accepts only type, startPeriodSec", svc)
		}
		sp, err := intIn("health.startPeriodSec", r.StartPeriodSec, 10, 1, 600)
		if err != nil {
			return ComposeHealth{}, err
		}
		return ComposeHealth{Type: "running", StartPeriodSec: sp}, nil
	}
	return ComposeHealth{}, invalid("services[%s].health.type must be http|tcp|running", svc)
}

// DecodeComposeApply strictly decodes compose.apply params.
func DecodeComposeApply(raw json.RawMessage) (ComposeApplyParams, error) {
	type rawSvc struct {
		Service   *string           `json:"service"`
		Name      *string           `json:"name"`
		Image     *string           `json:"image"`
		SpecHash  *string           `json:"specHash"`
		Env       map[string]string `json:"env"`
		SecretEnv map[string]string `json:"secretEnv"`
		Command   []string          `json:"command"`
		Volumes   []Volume          `json:"volumes"`
		DependsOn []string          `json:"dependsOn"`
		Health    *rawComposeHealth `json:"health"`
		Resources *struct {
			MemoryMb *int     `json:"memoryMb"`
			Cpus     *float64 `json:"cpus"`
			Pids     *int     `json:"pids"`
		} `json:"resources"`
		HostPort      *int `json:"hostPort"`
		ContainerPort *int `json:"containerPort"`
	}
	var w struct {
		DeploymentID *string  `json:"deploymentId"`
		App          *string  `json:"app"`
		Services     []rawSvc `json:"services"`
		RouteService *string  `json:"routeService"`
		RegistryAuth *bool    `json:"registryAuth"`
	}
	var p ComposeApplyParams
	if err := decode(raw, &w); err != nil {
		return p, err
	}
	if w.DeploymentID == nil || !uuidRe.MatchString(*w.DeploymentID) {
		return p, invalid("deploymentId must be a UUID")
	}
	if w.App == nil || !AppSlugRe.MatchString(*w.App) {
		return p, invalid("app must match %s", AppSlugRe)
	}
	p = ComposeApplyParams{DeploymentID: strings.ToLower(*w.DeploymentID), App: *w.App}
	if len(w.Services) < 1 || len(w.Services) > 20 {
		return p, invalid("services must have 1..20 entries")
	}
	if w.RouteService != nil {
		if !ComposeServiceRe.MatchString(*w.RouteService) {
			return p, invalid("routeService must match %s", ComposeServiceRe)
		}
		p.RouteService = *w.RouteService
	}
	if w.RegistryAuth != nil {
		p.RegistryAuth = *w.RegistryAuth
	}
	seen, names, routeFound := map[string]bool{}, map[string]bool{}, false
	for i, r := range w.Services {
		if r.Service == nil || !ComposeServiceRe.MatchString(*r.Service) {
			return p, invalid("services[%d].service must match %s", i, ComposeServiceRe)
		}
		s := ComposeService{Service: *r.Service, Env: map[string]string{}, SecretEnv: map[string]string{}, Volumes: []Volume{}, DependsOn: []string{}}
		if seen[s.Service] {
			return p, invalid("service %s listed twice", s.Service)
		}
		if r.Name == nil || !NameMatchesService(p.App, s.Service, *r.Name) {
			return p, invalid("services[%s].name must be ppanel-<app>-<service>-<8 hex> (max %d chars before the hex)", s.Service, 48)
		}
		if names[*r.Name] {
			return p, invalid("container name %s used twice", *r.Name)
		}
		s.Name = *r.Name
		if r.Image == nil || len(*r.Image) > 400 || !ImageDigestRefRe.MatchString(*r.Image) {
			return p, invalid("services[%s].image must be pinned by digest", s.Service)
		}
		s.Image = *r.Image
		if r.SpecHash == nil || !specHashRe.MatchString(*r.SpecHash) {
			return p, invalid("services[%s].specHash must be 64 lowercase hex", s.Service)
		}
		s.SpecHash = *r.SpecHash
		for k, v := range r.Env {
			if !EnvKeyRe.MatchString(k) || len(v) > 4096 || strings.IndexByte(v, 0) >= 0 {
				return p, invalid("services[%s].env %q invalid", s.Service, k)
			}
			s.Env[k] = v
		}
		for k, v := range r.SecretEnv {
			if !EnvKeyRe.MatchString(k) || !EnvKeyRe.MatchString(v) {
				return p, invalid("services[%s].secretEnv %q invalid", s.Service, k)
			}
			if _, dup := s.Env[k]; dup {
				return p, invalid("services[%s]: %s is both env and secretEnv", s.Service, k)
			}
			s.SecretEnv[k] = v
		}
		if r.Command != nil {
			if len(r.Command) > 64 {
				return p, invalid("services[%s].command has more than 64 entries", s.Service)
			}
			for _, c := range r.Command {
				if len(c) > 1024 || strings.IndexByte(c, 0) >= 0 {
					return p, invalid("services[%s].command entries must be <=1024 bytes without NUL", s.Service)
				}
			}
			s.Command = append([]string{}, r.Command...)
		}
		if len(r.Volumes) > 10 {
			return p, invalid("services[%s]: at most 10 volumes", s.Service)
		}
		vn, vm := map[string]bool{}, map[string]bool{}
		for j, v := range r.Volumes {
			if !volumeNameRe.MatchString(v.Name) {
				return p, invalid("services[%s].volumes[%d].name must match %s", s.Service, j, volumeNameRe)
			}
			if !mountPathRe.MatchString(v.MountPath) || strings.Contains(v.MountPath, "..") || strings.Contains(v.MountPath, "//") {
				return p, invalid("services[%s].volumes[%d].mountPath must be an absolute canonical path", s.Service, j)
			}
			if vn[v.Name] || vm[v.MountPath] {
				return p, invalid("services[%s].volumes[%d] duplicates a name or mountPath", s.Service, j)
			}
			vn[v.Name], vm[v.MountPath] = true, true
			s.Volumes = append(s.Volumes, v)
		}
		if len(r.DependsOn) > 20 {
			return p, invalid("services[%s].dependsOn has more than 20 entries", s.Service)
		}
		dd := map[string]bool{}
		for _, d := range r.DependsOn {
			if !ComposeServiceRe.MatchString(d) || dd[d] {
				return p, invalid("services[%s].dependsOn entry %q invalid or duplicated", s.Service, d)
			}
			if !seen[d] {
				return p, invalid("services[%s] depends on %q which is not an earlier service (plan must be topologically sorted)", s.Service, d)
			}
			dd[d] = true
			s.DependsOn = append(s.DependsOn, d)
		}
		var err error
		if s.Health, err = r.Health.resolve(s.Service); err != nil {
			return p, err
		}
		s.Resources = Resources{MemoryMb: 512, Cpus: 1, Pids: 512}
		if rr := r.Resources; rr != nil {
			if s.Resources.MemoryMb, err = intIn("resources.memoryMb", rr.MemoryMb, 512, 32, 65536); err != nil {
				return p, err
			}
			if s.Resources.Pids, err = intIn("resources.pids", rr.Pids, 512, 16, 32768); err != nil {
				return p, err
			}
			if rr.Cpus != nil {
				if math.IsNaN(*rr.Cpus) || *rr.Cpus < 0.1 || *rr.Cpus > 64 {
					return p, invalid("resources.cpus must be 0.1..64")
				}
				s.Resources.Cpus = *rr.Cpus
			}
		}
		if r.ContainerPort != nil {
			if *r.ContainerPort < 1 || *r.ContainerPort > 65535 {
				return p, invalid("services[%s].containerPort must be 1..65535", s.Service)
			}
			s.ContainerPort = *r.ContainerPort
		}
		isRoute := s.Service == p.RouteService
		if r.HostPort != nil {
			if !isRoute {
				return p, invalid("services[%s]: only the routeService may have a hostPort", s.Service)
			}
			if s.HostPort, err = checkHostPort(r.HostPort); err != nil {
				return p, err
			}
		}
		if isRoute {
			routeFound = true
			if s.HostPort == 0 || s.ContainerPort == 0 {
				return p, invalid("routeService %s needs hostPort and containerPort", s.Service)
			}
		}
		seen[s.Service], names[s.Name] = true, true
		p.Services = append(p.Services, s)
	}
	if p.RouteService != "" && !routeFound {
		return p, invalid("routeService %s is not one of the services", p.RouteService)
	}
	return p, nil
}

// DecodeComposeStop decodes compose.stop.
func DecodeComposeStop(raw json.RawMessage) (ComposeStopParams, error) {
	var w struct {
		App *string `json:"app"`
	}
	if err := decode(raw, &w); err != nil {
		return ComposeStopParams{}, err
	}
	if w.App == nil || !AppSlugRe.MatchString(*w.App) {
		return ComposeStopParams{}, invalid("app must match %s", AppSlugRe)
	}
	return ComposeStopParams{App: *w.App}, nil
}

// ---------------- execution ----------------

// ComposeServiceResult is one entry of the compose.apply output.
type ComposeServiceResult struct {
	Service      string  `json:"service"`
	Name         string  `json:"name"`
	Action       string  `json:"action"` // unchanged|created|replaced
	PreviousName string  `json:"previousName,omitempty"`
	HostPort     *int    `json:"hostPort,omitempty"`
	Health       *Health `json:"health"`
}

// ComposeOutput is the compose.apply success output.
type ComposeOutput struct {
	Services []ComposeServiceResult `json:"services"`
}

// ComposeStopOutput is the compose.stop output.
type ComposeStopOutput struct {
	Stopped []string `json:"stopped"`
}

// ComposeCreateBody is the hardened create body of one compose service:
// CreateBody (run_candidate hardening) without a host port unless it is the
// route service, plus ppanel.service/ppanel.spec labels and the service DNS
// alias on ppanel-<app>.
func ComposeCreateBody(p ComposeApplyParams, s ComposeService, env map[string]string) map[string]any {
	rp := RunParams{DeploymentID: p.DeploymentID, App: p.App, Name: s.Name, Image: s.Image, ContainerPort: s.ContainerPort,
		HostPort: s.HostPort, Volumes: s.Volumes, Resources: s.Resources, Command: s.Command}
	body := CreateBody(rp, env)
	hc := body["HostConfig"].(map[string]any)
	if s.HostPort == 0 {
		delete(hc, "PortBindings")
		if s.ContainerPort == 0 {
			delete(body, "ExposedPorts")
		}
	}
	labels := body["Labels"].(map[string]string)
	labels[LabelService] = s.Service
	labels[LabelSpec] = s.SpecHash
	body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{
		NetworkName(p.App): map[string]any{"Aliases": []string{s.Service}},
	}}
	return body
}

// svcContainer is an owned container of one compose service.
type svcContainer struct {
	id, name, spec string
	running        bool
	created        int64
	hostPort       int
}

func (m *Manager) serviceContainers(ctx context.Context, e *docker.Engine, app, service string) ([]svcContainer, error) {
	cs, err := e.ListContainers(ctx, []string{LabelManaged + "=true", LabelApp + "=" + app, LabelService + "=" + service})
	if err != nil {
		return nil, m.dockerErr("list", err, nil)
	}
	var out []svcContainer
	for _, c := range cs {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		if c.Labels[LabelManaged] != "true" || c.Labels[LabelApp] != app || c.Labels[LabelService] != service || !NameMatchesService(app, service, name) {
			continue
		}
		sc := svcContainer{id: c.ID, name: name, spec: c.Labels[LabelSpec], running: c.State == "running", created: c.Created}
		for _, pt := range c.Ports {
			if pt.IP == "127.0.0.1" && pt.PublicPort > 0 {
				sc.hostPort = pt.PublicPort
			}
		}
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].created > out[j].created })
	return out, nil
}

func composeErr(service, msg string, details map[string]any, done []ComposeServiceResult) *jobs.Error {
	e := jerr(CodeComposeServiceUnhealthy, "service %s: %s", service, msg)
	if details == nil {
		details = map[string]any{}
	}
	details["service"] = service
	details["services"] = done
	e.Details = details
	return e
}

func unhealthyDetails(u *unhealthy, tail []string) map[string]any {
	d := map[string]any{"logTail": tail, "attempts": u.attempts, "elapsedMs": u.elapsedMs, "reason": u.reason}
	if u.exitCode != nil {
		d["exitCode"] = *u.exitCode
	}
	if u.lastStatus != nil {
		d["lastStatus"] = *u.lastStatus
	}
	if u.lastError != "" {
		d["lastError"] = u.lastError
	}
	return d
}

// probeAddr returns where a container port is probed from the agent.
func (m *Manager) probeAddr(ci *docker.ContainerInfo, app string, port int) string {
	ip := ""
	if n, ok := ci.NetworkSettings.Networks[NetworkName(app)]; ok {
		ip = n.IPAddress
	}
	if m.o.ProbeAddr != nil {
		return m.o.ProbeAddr(ci.ID, ip, port)
	}
	if ip == "" {
		return ""
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// waitService runs the service's health check against container id:
// http (loopback host port for the route service, container IP otherwise),
// tcp (container IP:port) or running (no exit/restart for startPeriodSec).
func (m *Manager) waitService(ctx context.Context, e *docker.Engine, app string, s ComposeService, route bool, id string) (*Health, *unhealthy, error) {
	h := s.Health
	interval := time.Second
	if h.Type == "http" {
		interval = time.Duration(h.IntervalSec) * time.Second
	}
	timeout := 2 * time.Second
	if h.TimeoutSec > 0 {
		timeout = time.Duration(h.TimeoutSec) * time.Second
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	start := m.o.Now()
	deadline := start.Add(time.Duration(h.StartPeriodSec) * time.Second)
	u := &unhealthy{}
	restarts := -1
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
		if restarts < 0 {
			restarts = ci.RestartCount
		} else if ci.RestartCount != restarts {
			u.reason = "container restarted during the start period"
			break
		}
		u.attempts++
		now := m.o.Now()
		switch h.Type {
		case "running":
			if !now.Before(deadline) {
				return &Health{Status: "healthy", Attempts: u.attempts, ElapsedMs: now.Sub(start).Milliseconds()}, nil, nil
			}
		case "tcp":
			addr := m.probeAddr(ci, app, h.Port)
			if addr == "" {
				u.lastError = "container has no address on " + NetworkName(app)
			} else if c, err := net.DialTimeout("tcp", addr, timeout); err == nil {
				c.Close()
				return &Health{Status: "healthy", Attempts: u.attempts, ElapsedMs: m.o.Now().Sub(start).Milliseconds()}, nil, nil
			} else {
				u.lastError = "tcp connect failed"
			}
		case "http":
			addr := ""
			if route {
				addr = net.JoinHostPort(m.o.HealthHost, strconv.Itoa(s.HostPort))
			} else {
				addr = m.probeAddr(ci, app, h.Port)
			}
			if addr == "" {
				u.lastError = "container has no address on " + NetworkName(app)
				break
			}
			url := "http://" + addr + h.Path
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			req.Header.Set("User-Agent", "ppanel-agent-healthcheck")
			resp, err := client.Do(req)
			if err != nil {
				u.lastError = strings.ReplaceAll(err.Error(), url, "health URL")
				break
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			st := resp.StatusCode
			u.lastStatus, u.lastError = &st, ""
			if contains(h.ExpectStatus, st) {
				return &Health{Status: "healthy", Attempts: u.attempts, ElapsedMs: m.o.Now().Sub(start).Milliseconds(), LastStatus: &st}, nil, nil
			}
		}
		now = m.o.Now()
		if !now.Before(deadline) {
			u.reason = "not healthy within startPeriodSec"
			break
		}
		wait := interval
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

// ComposeApply implements compose.apply.
func (m *Manager) ComposeApply(ctx context.Context, p ComposeApplyParams) (*ComposeOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockApp(ctx, p.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	log := m.o.Log.With("app", p.App, "deploymentId", p.DeploymentID)
	if err := e.Ping(ctx); err != nil {
		return nil, jerr(CodeDockerUnavailable, "docker engine API not reachable on %s", e.Socket())
	}

	// 1. secrets, fetched once for the whole plan (memory only)
	var secretVals []string
	secretEnv := map[string]string{}
	authB64 := ""
	needSecrets := p.RegistryAuth
	for _, s := range p.Services {
		needSecrets = needSecrets || len(s.SecretEnv) > 0
	}
	if needSecrets {
		if m.o.Secrets == nil {
			return nil, jerr(CodeSecretsUnavailable, "secrets channel not configured")
		}
		sec, err := m.o.Secrets(ctx)
		if err != nil {
			return nil, jerr(CodeSecretsUnavailable, "secrets fetch failed (%s)", secretsErrCode(err))
		}
		for _, s := range p.Services {
			for _, key := range s.SecretEnv {
				v, ok := sec.Env[key]
				if !ok {
					return nil, jerr(CodeSecretsUnavailable, "secret %s not delivered", key)
				}
				secretEnv[key] = v
				secretVals = append(secretVals, v)
			}
		}
		if p.RegistryAuth {
			if sec.RegistryAuth == nil {
				return nil, jerr(CodeSecretsUnavailable, "registry credential not delivered")
			}
			b, _ := json.Marshal(map[string]string{"username": sec.RegistryAuth.Username, "password": sec.RegistryAuth.Password,
				"serveraddress": sec.RegistryAuth.ServerAddress})
			authB64 = base64.URLEncoding.EncodeToString(b)
			secretVals = append(secretVals, sec.RegistryAuth.Password)
		}
		log.Info("secrets received", "keys", len(secretEnv), "registryAuth", p.RegistryAuth)
	}
	m.setHeld(p.App, secretVals)
	defer m.setHeld(p.App, nil)
	defer func() {
		for k := range secretEnv {
			delete(secretEnv, k)
		}
	}()

	if err := m.ensureNetwork(ctx, e, p.App); err != nil {
		return nil, err
	}
	byName := map[string]ComposeService{}
	current := map[string]string{} // service -> container id now serving it
	healthy := map[string]bool{}
	done := []ComposeServiceResult{}

	for _, s := range p.Services {
		byName[s.Service] = s
		route := s.Service == p.RouteService
		slog := log.With("service", s.Service)
		cands, err := m.serviceContainers(ctx, e, p.App, s.Service)
		if err != nil {
			return nil, err
		}
		// keep: a running container with the same spec
		var kept *svcContainer
		for i := range cands {
			if cands[i].running && cands[i].spec == s.SpecHash {
				kept = &cands[i]
				break
			}
		}
		if kept != nil {
			current[s.Service] = kept.id
			r := ComposeServiceResult{Service: s.Service, Name: kept.name, Action: "unchanged", Health: &Health{Status: "running"}}
			if route && kept.hostPort > 0 {
				hp := kept.hostPort
				r.HostPort = &hp
			}
			done = append(done, r)
			slog.Info("service unchanged", "name", kept.name)
			continue
		}
		// dependencies must be healthy first
		for _, d := range s.DependsOn {
			if healthy[d] {
				continue
			}
			id, ok := current[d]
			if !ok {
				return nil, composeErr(s.Service, "dependency "+d+" has no running container", nil, done)
			}
			_, u, err := m.waitService(ctx, e, p.App, byName[d], d == p.RouteService, id)
			if err != nil {
				return nil, m.dockerErr("dependency health check", err, secretVals)
			}
			if u != nil {
				return nil, composeErr(s.Service, "dependency "+d+" is not healthy: "+u.reason, map[string]any{"dependency": d}, done)
			}
			healthy[d] = true
		}
		// leftovers of an earlier attempt with the planned name are removed (never volumes)
		var old *svcContainer
		for i := range cands {
			c := &cands[i]
			if c.name == s.Name {
				if c.running {
					return nil, jerr(jobs.HandlerFailed, "container %s is running with a different spec; the plan must use a new name", s.Name)
				}
				if err := e.RemoveContainer(ctx, c.id, true); err != nil && !errors.Is(err, docker.ErrNotFound) {
					return nil, m.dockerErr("remove leftover", err, secretVals)
				}
				slog.Info("removed stopped leftover with the planned name", "name", c.name)
				continue
			}
			if old == nil && c.running {
				old = c
			}
		}
		if route && m.o.PortInUse(s.HostPort) {
			return nil, jerr(CodePortInUse, "127.0.0.1:%d is already in use", s.HostPort)
		}
		// image + volumes
		if err := e.PullImage(ctx, s.Image, authB64); err != nil {
			if docker.IsUnavailable(err) {
				return nil, jerr(CodeDockerUnavailable, "docker engine not reachable during pull")
			}
			msg := err.Error()
			var ae *docker.APIError
			if errors.As(err, &ae) {
				msg = ae.Message
			}
			return nil, jerr(CodeImagePullFailed, "pull %s failed: %s", s.Image, Redact(msg, secretVals))
		}
		for _, v := range s.Volumes {
			vi, err := e.CreateVolume(ctx, VolumeName(p.App, v.Name), managedLabels(p.App))
			if err != nil {
				return nil, m.dockerErr("create volume", err, secretVals)
			}
			if vi.Labels[LabelManaged] != "true" || vi.Labels[LabelApp] != p.App {
				return nil, jerr(CodeContainerNotManaged, "volume %s exists but is not managed by pPanel for app %s", vi.Name, p.App)
			}
		}
		env := make(map[string]string, len(s.Env)+len(s.SecretEnv))
		for k, v := range s.Env {
			env[k] = v
		}
		for k, key := range s.SecretEnv {
			env[k] = secretEnv[key]
		}
		// non-route: stop the old one first (brief downtime is inherent and reported)
		stoppedOld := false
		if !route && old != nil {
			if err := e.StopContainer(ctx, old.id, StopGraceSec); err != nil && !errors.Is(err, docker.ErrNotFound) {
				return nil, m.dockerErr("stop "+old.name, err, secretVals)
			}
			stoppedOld = true
			slog.Info("old container stopped", "name", old.name)
		}
		restoreOld := func() bool {
			if !stoppedOld {
				return false
			}
			rctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := e.StartContainer(rctx, old.id); err != nil {
				slog.Error("restoring old container failed", "name", old.name, "error", Redact(err.Error(), secretVals))
				return false
			}
			slog.Warn("old container restarted after failed replacement", "name", old.name)
			return true
		}
		id, err := e.CreateContainer(ctx, s.Name, ComposeCreateBody(p, s, env))
		for k := range env {
			delete(env, k)
		}
		if err != nil {
			restored := restoreOld()
			var ae *docker.APIError
			if errors.As(err, &ae) && ae.Status == http.StatusConflict {
				return nil, jerr(CodeContainerExists, "container %s already exists", s.Name)
			}
			je := m.dockerErr("create "+s.Name, err, secretVals)
			je.Details = map[string]any{"service": s.Service, "restored": restored}
			return nil, je
		}
		fail := func(u *unhealthy) error {
			tail := m.logTail(context.Background(), e, id, false, secretVals)
			m.removeCandidate(e, id, slog)
			restored := restoreOld()
			d := unhealthyDetails(u, tail)
			d["removed"], d["restored"] = true, restored
			if old != nil {
				d["previousName"] = old.name
			}
			slog.Warn("service unhealthy; new container removed", "reason", u.reason, "restored", restored)
			return composeErr(s.Service, u.reason, d, done)
		}
		if err := e.StartContainer(ctx, id); err != nil {
			return nil, fail(&unhealthy{reason: "start failed: " + Redact(err.Error(), secretVals)})
		}
		h, u, err := m.waitService(ctx, e, p.App, s, route, id)
		if err != nil {
			return nil, fail(&unhealthy{reason: "health loop aborted: " + Redact(err.Error(), secretVals)})
		}
		if u != nil {
			return nil, fail(u)
		}
		current[s.Service], healthy[s.Service] = id, true
		r := ComposeServiceResult{Service: s.Service, Name: s.Name, Action: "created", Health: h}
		if old != nil {
			r.Action, r.PreviousName = "replaced", old.name
		}
		if route {
			hp := s.HostPort
			r.HostPort = &hp
		}
		done = append(done, r)
		slog.Info("service "+r.Action, "name", s.Name, "previous", r.PreviousName, "attempts", h.Attempts)
	}
	return &ComposeOutput{Services: done}, nil
}

// ComposeStop implements compose.stop: every owned container of the app is
// stopped (10 s grace); containers and volumes are kept.
func (m *Manager) ComposeStop(ctx context.Context, p ComposeStopParams) (*ComposeStopOutput, error) {
	e, err := m.engine()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockApp(ctx, p.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cs, err := e.ListContainers(ctx, []string{LabelManaged + "=true", LabelApp + "=" + p.App})
	if err != nil {
		return nil, m.dockerErr("list", err, nil)
	}
	out := &ComposeStopOutput{Stopped: []string{}}
	for _, c := range cs {
		if len(c.Names) == 0 || c.State != "running" {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		ci, err := e.InspectContainer(ctx, c.ID)
		if err != nil || !IsOwned(ci, p.App, name) {
			continue
		}
		if err := e.StopContainer(ctx, ci.ID, StopGraceSec); err != nil && !errors.Is(err, docker.ErrNotFound) {
			return nil, m.dockerErr(fmt.Sprintf("stop %s", name), err, nil)
		}
		out.Stopped = append(out.Stopped, name)
	}
	sort.Strings(out.Stopped)
	return out, nil
}
