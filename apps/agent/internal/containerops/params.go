// Package containerops implements the P4 container.* typed jobs
// (docs/AGENT_PROTOCOL.md "Containers (P4) — authoritative") on top of the
// write-capable docker.Engine. It never shells out and never uses the docker CLI.
package containerops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Contract regexes / limits (packages/shared-contracts/src/jobs.ts).
var (
	AppSlugRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	ImageDigestRefRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$`)
	ManagedNameRe    = regexp.MustCompile(`^ppanel-[a-z0-9][a-z0-9-]{0,40}-[a-f0-9]{8}$`)
	EnvKeyRe         = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	volumeNameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	mountPathRe      = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)
	healthPathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~/?=&%-]{0,200}$`)
	userRe           = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}(:[A-Za-z0-9_.-]{1,64})?$`)
	uuidRe           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Managed host port range (127.0.0.1 only).
const (
	PortMin = 20000
	PortMax = 29999
)

// Error codes (CONTAINER_ERROR_CODES).
const (
	CodeDockerUnavailable   = "DOCKER_UNAVAILABLE"
	CodeImagePullFailed     = "IMAGE_PULL_FAILED"
	CodePortInUse           = "PORT_IN_USE"
	CodeContainerExists     = "CONTAINER_EXISTS"
	CodeContainerNotManaged = "CONTAINER_NOT_MANAGED"
	CodeContainerNotFound   = "CONTAINER_NOT_FOUND"
	CodeCandidateUnhealthy  = "CANDIDATE_UNHEALTHY"
	CodeSecretsUnavailable  = "SECRETS_UNAVAILABLE"
)

// Healthcheck mirrors containerHealthcheckSchema (defaults applied).
type Healthcheck struct {
	Path           string `json:"path"`
	ExpectStatus   []int  `json:"expectStatus"`
	IntervalSec    int    `json:"intervalSec"`
	TimeoutSec     int    `json:"timeoutSec"`
	StartPeriodSec int    `json:"startPeriodSec"`
}

// Resources mirrors containerResourcesSchema.
type Resources struct {
	MemoryMb int     `json:"memoryMb"`
	Cpus     float64 `json:"cpus"`
	Pids     int     `json:"pids"`
}

// Volume is a named volume mount (`ppanel-<app>-<name>`).
type Volume struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
}

// RunParams is container.run_candidate.
type RunParams struct {
	DeploymentID   string            `json:"deploymentId"`
	App            string            `json:"app"`
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	ContainerPort  int               `json:"containerPort"`
	HostPort       int               `json:"hostPort"`
	Env            map[string]string `json:"env"`
	SecretEnvKeys  []string          `json:"secretEnvKeys"`
	RegistryAuth   bool              `json:"registryAuth"`
	Volumes        []Volume          `json:"volumes"`
	Resources      Resources         `json:"resources"`
	Healthcheck    Healthcheck       `json:"healthcheck"`
	Command        []string          `json:"command,omitempty"`
	User           string            `json:"user,omitempty"`
	ReadOnlyRootfs bool              `json:"readOnlyRootfs"`
}

// RefParams is container.stop / container.remove.
type RefParams struct {
	App  string `json:"app"`
	Name string `json:"name"`
}

// StartParams is container.start / container.restart.
type StartParams struct {
	App         string      `json:"app"`
	Name        string      `json:"name"`
	HostPort    int         `json:"hostPort"`
	Healthcheck Healthcheck `json:"healthcheck"`
}

// ListParams is container.list.
type ListParams struct {
	App string `json:"app,omitempty"`
}

// LogsParams is container.logs.
type LogsParams struct {
	App       string `json:"app"`
	Name      string `json:"name"`
	TailLines int    `json:"tailLines"`
	SinceSec  int    `json:"sinceSec,omitempty"`
}

func invalid(format string, a ...any) error {
	return jobs.Errorf(jobs.RejectedInvalidParams, format, a...)
}

// rejectNulls refuses JSON null anywhere (zod .optional()/.default() reject null).
func rejectNulls(raw json.RawMessage) error {
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return err
	}
	var walk func(path string, v any) error
	walk = func(path string, v any) error {
		switch t := v.(type) {
		case nil:
			return invalid("%s must not be null", path)
		case map[string]any:
			for k, x := range t {
				if err := walk(path+"."+k, x); err != nil {
					return err
				}
			}
		case []any:
			for i, x := range t {
				if err := walk(fmt.Sprintf("%s[%d]", path, i), x); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk("params", v)
}

func decode(raw json.RawMessage, dst any) error {
	if err := jobs.DecodeStrict(raw, dst); err != nil {
		return invalid("%v", err)
	}
	return rejectNulls(raw)
}

var hex8Re = regexp.MustCompile(`^[a-f0-9]{8}$`)

// ComposeServiceRe is the compose service name pattern.
var ComposeServiceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// PlainNameMatchesApp reports whether name is exactly ppanel-<app>-<8hex>
// (container.run_candidate names).
func PlainNameMatchesApp(app, name string) bool {
	if !ManagedNameRe.MatchString(name) || !AppSlugRe.MatchString(app) {
		return false
	}
	rest, ok := strings.CutPrefix(name, "ppanel-"+app+"-")
	return ok && hex8Re.MatchString(rest)
}

// NameMatchesService reports whether name is exactly ppanel-<app>-<service>-<8hex>
// (compose service containers, P4b).
func NameMatchesService(app, service, name string) bool {
	if !ManagedNameRe.MatchString(name) || !AppSlugRe.MatchString(app) || !ComposeServiceRe.MatchString(service) {
		return false
	}
	rest, ok := strings.CutPrefix(name, "ppanel-"+app+"-"+service+"-")
	return ok && hex8Re.MatchString(rest)
}

// NameMatchesApp is the pure (name-only) part of the ownership rule:
// ppanel-<app>-<8hex> or a compose service container ppanel-<app>-<service>-<8hex>.
// Labels decide the rest (IsOwned).
func NameMatchesApp(app, name string) bool {
	if PlainNameMatchesApp(app, name) {
		return true
	}
	if !ManagedNameRe.MatchString(name) || !AppSlugRe.MatchString(app) {
		return false
	}
	rest, ok := strings.CutPrefix(name, "ppanel-"+app+"-")
	if !ok || len(rest) < 10 {
		return false
	}
	svc, h := rest[:len(rest)-9], rest[len(rest)-9:]
	return h[0] == '-' && hex8Re.MatchString(h[1:]) && ComposeServiceRe.MatchString(svc)
}

func checkAppName(app, name string) error {
	if !AppSlugRe.MatchString(app) {
		return invalid("app must match %s", AppSlugRe)
	}
	if !ManagedNameRe.MatchString(name) {
		return invalid("name must match %s", ManagedNameRe)
	}
	return nil
}

type rawHealth struct {
	Path           *string `json:"path"`
	ExpectStatus   []int   `json:"expectStatus"`
	IntervalSec    *int    `json:"intervalSec"`
	TimeoutSec     *int    `json:"timeoutSec"`
	StartPeriodSec *int    `json:"startPeriodSec"`
}

func intIn(name string, v *int, def, lo, hi int) (int, error) {
	if v == nil {
		return def, nil
	}
	if *v < lo || *v > hi {
		return 0, invalid("%s must be between %d and %d", name, lo, hi)
	}
	return *v, nil
}

func (r *rawHealth) resolve() (Healthcheck, error) {
	h := Healthcheck{Path: "/", ExpectStatus: []int{200}}
	if r == nil {
		r = &rawHealth{}
	}
	if r.Path != nil {
		if !healthPathRe.MatchString(*r.Path) {
			return h, invalid("healthcheck.path must match %s", healthPathRe)
		}
		h.Path = *r.Path
	}
	if r.ExpectStatus != nil {
		if len(r.ExpectStatus) < 1 || len(r.ExpectStatus) > 10 {
			return h, invalid("healthcheck.expectStatus must have 1..10 entries")
		}
		for _, s := range r.ExpectStatus {
			if s < 100 || s > 599 {
				return h, invalid("healthcheck.expectStatus entries must be 100..599")
			}
		}
		h.ExpectStatus = append([]int(nil), r.ExpectStatus...)
	}
	var err error
	if h.IntervalSec, err = intIn("healthcheck.intervalSec", r.IntervalSec, 2, 1, 30); err != nil {
		return h, err
	}
	if h.TimeoutSec, err = intIn("healthcheck.timeoutSec", r.TimeoutSec, 3, 1, 30); err != nil {
		return h, err
	}
	if h.StartPeriodSec, err = intIn("healthcheck.startPeriodSec", r.StartPeriodSec, 60, 1, 600); err != nil {
		return h, err
	}
	return h, nil
}

func checkHostPort(p *int) (int, error) {
	if p == nil {
		return 0, invalid("hostPort is required")
	}
	if *p < PortMin || *p > PortMax {
		return 0, invalid("hostPort must be between %d and %d", PortMin, PortMax)
	}
	return *p, nil
}

// DecodeRun strictly decodes container.run_candidate params.
func DecodeRun(raw json.RawMessage) (RunParams, error) {
	var w struct {
		DeploymentID  *string           `json:"deploymentId"`
		App           *string           `json:"app"`
		Name          *string           `json:"name"`
		Image         *string           `json:"image"`
		ContainerPort *int              `json:"containerPort"`
		HostPort      *int              `json:"hostPort"`
		Env           map[string]string `json:"env"`
		SecretEnvKeys []string          `json:"secretEnvKeys"`
		RegistryAuth  *bool             `json:"registryAuth"`
		Volumes       []Volume          `json:"volumes"`
		Resources     *struct {
			MemoryMb *int     `json:"memoryMb"`
			Cpus     *float64 `json:"cpus"`
			Pids     *int     `json:"pids"`
		} `json:"resources"`
		Healthcheck    *rawHealth `json:"healthcheck"`
		Command        []string   `json:"command"`
		User           *string    `json:"user"`
		ReadOnlyRootfs *bool      `json:"readOnlyRootfs"`
	}
	var p RunParams
	if err := decode(raw, &w); err != nil {
		return p, err
	}
	if w.DeploymentID == nil || !uuidRe.MatchString(*w.DeploymentID) {
		return p, invalid("deploymentId must be a UUID")
	}
	if w.App == nil || w.Name == nil {
		return p, invalid("app and name are required")
	}
	if err := checkAppName(*w.App, *w.Name); err != nil {
		return p, err
	}
	if !PlainNameMatchesApp(*w.App, *w.Name) {
		return p, invalid("name must be ppanel-<app>-<8 hex>")
	}
	if w.Image == nil || len(*w.Image) > 400 || !ImageDigestRefRe.MatchString(*w.Image) {
		return p, invalid("image must be pinned by digest (registry/repo@sha256:<64 hex>)")
	}
	if w.ContainerPort == nil || *w.ContainerPort < 1 || *w.ContainerPort > 65535 {
		return p, invalid("containerPort must be 1..65535")
	}
	hp, err := checkHostPort(w.HostPort)
	if err != nil {
		return p, err
	}
	p = RunParams{DeploymentID: strings.ToLower(*w.DeploymentID), App: *w.App, Name: *w.Name, Image: *w.Image,
		ContainerPort: *w.ContainerPort, HostPort: hp, Env: map[string]string{}, SecretEnvKeys: []string{}, Volumes: []Volume{}}
	for k, v := range w.Env {
		if !EnvKeyRe.MatchString(k) {
			return p, invalid("env key %q must match %s", k, EnvKeyRe)
		}
		if len(v) > 4096 {
			return p, invalid("env %s value longer than 4096", k)
		}
		if strings.IndexByte(v, 0) >= 0 {
			return p, invalid("env %s value contains NUL", k)
		}
		p.Env[k] = v
	}
	if len(w.SecretEnvKeys) > 100 {
		return p, invalid("secretEnvKeys has more than 100 entries")
	}
	seen := map[string]bool{}
	for _, k := range w.SecretEnvKeys {
		if !EnvKeyRe.MatchString(k) {
			return p, invalid("secretEnvKeys entry %q must match %s", k, EnvKeyRe)
		}
		if seen[k] {
			return p, invalid("secretEnvKeys entry %s duplicated", k)
		}
		if _, dup := p.Env[k]; dup {
			return p, invalid("%s is both a plain env and a secret env key", k)
		}
		seen[k] = true
		p.SecretEnvKeys = append(p.SecretEnvKeys, k)
	}
	if w.RegistryAuth != nil {
		p.RegistryAuth = *w.RegistryAuth
	}
	if len(w.Volumes) > 10 {
		return p, invalid("at most 10 volumes")
	}
	vn, vm := map[string]bool{}, map[string]bool{}
	for i, v := range w.Volumes {
		if !volumeNameRe.MatchString(v.Name) {
			return p, invalid("volumes[%d].name must match %s", i, volumeNameRe)
		}
		if !mountPathRe.MatchString(v.MountPath) || strings.Contains(v.MountPath, "..") || strings.Contains(v.MountPath, "//") {
			return p, invalid("volumes[%d].mountPath must be an absolute canonical path", i)
		}
		if vn[v.Name] || vm[v.MountPath] {
			return p, invalid("volumes[%d] duplicates a name or mountPath", i)
		}
		vn[v.Name], vm[v.MountPath] = true, true
		p.Volumes = append(p.Volumes, v)
	}
	p.Resources = Resources{MemoryMb: 512, Cpus: 1, Pids: 512}
	if r := w.Resources; r != nil {
		if p.Resources.MemoryMb, err = intIn("resources.memoryMb", r.MemoryMb, 512, 32, 65536); err != nil {
			return p, err
		}
		if p.Resources.Pids, err = intIn("resources.pids", r.Pids, 512, 16, 32768); err != nil {
			return p, err
		}
		if r.Cpus != nil {
			if math.IsNaN(*r.Cpus) || *r.Cpus < 0.1 || *r.Cpus > 64 {
				return p, invalid("resources.cpus must be 0.1..64")
			}
			p.Resources.Cpus = *r.Cpus
		}
	}
	if p.Healthcheck, err = w.Healthcheck.resolve(); err != nil {
		return p, err
	}
	if w.Command != nil {
		if len(w.Command) > 64 {
			return p, invalid("command has more than 64 entries")
		}
		for _, c := range w.Command {
			if len(c) > 1024 || strings.IndexByte(c, 0) >= 0 {
				return p, invalid("command entries must be <=1024 bytes without NUL")
			}
		}
		p.Command = append([]string{}, w.Command...)
	}
	if w.User != nil {
		if !userRe.MatchString(*w.User) {
			return p, invalid("user must match %s", userRe)
		}
		p.User = *w.User
	}
	if w.ReadOnlyRootfs != nil {
		p.ReadOnlyRootfs = *w.ReadOnlyRootfs
	}
	return p, nil
}

// DecodeRef decodes container.stop / container.remove.
func DecodeRef(raw json.RawMessage) (RefParams, error) {
	var w struct {
		App  *string `json:"app"`
		Name *string `json:"name"`
	}
	if err := decode(raw, &w); err != nil {
		return RefParams{}, err
	}
	if w.App == nil || w.Name == nil {
		return RefParams{}, invalid("app and name are required")
	}
	if err := checkAppName(*w.App, *w.Name); err != nil {
		return RefParams{}, err
	}
	return RefParams{App: *w.App, Name: *w.Name}, nil
}

// DecodeStart decodes container.start / container.restart.
func DecodeStart(raw json.RawMessage) (StartParams, error) {
	var w struct {
		App         *string    `json:"app"`
		Name        *string    `json:"name"`
		HostPort    *int       `json:"hostPort"`
		Healthcheck *rawHealth `json:"healthcheck"`
	}
	if err := decode(raw, &w); err != nil {
		return StartParams{}, err
	}
	if w.App == nil || w.Name == nil {
		return StartParams{}, invalid("app and name are required")
	}
	if err := checkAppName(*w.App, *w.Name); err != nil {
		return StartParams{}, err
	}
	hp, err := checkHostPort(w.HostPort)
	if err != nil {
		return StartParams{}, err
	}
	h, err := w.Healthcheck.resolve()
	if err != nil {
		return StartParams{}, err
	}
	return StartParams{App: *w.App, Name: *w.Name, HostPort: hp, Healthcheck: h}, nil
}

// DecodeList decodes container.list.
func DecodeList(raw json.RawMessage) (ListParams, error) {
	var w struct {
		App *string `json:"app"`
	}
	if err := decode(raw, &w); err != nil {
		return ListParams{}, err
	}
	if w.App == nil {
		return ListParams{}, nil
	}
	if !AppSlugRe.MatchString(*w.App) {
		return ListParams{}, invalid("app must match %s", AppSlugRe)
	}
	return ListParams{App: *w.App}, nil
}

// DecodeLogs decodes container.logs.
func DecodeLogs(raw json.RawMessage) (LogsParams, error) {
	var w struct {
		App       *string `json:"app"`
		Name      *string `json:"name"`
		TailLines *int    `json:"tailLines"`
		SinceSec  *int    `json:"sinceSec"`
	}
	if err := decode(raw, &w); err != nil {
		return LogsParams{}, err
	}
	if w.App == nil || w.Name == nil {
		return LogsParams{}, invalid("app and name are required")
	}
	if err := checkAppName(*w.App, *w.Name); err != nil {
		return LogsParams{}, err
	}
	p := LogsParams{App: *w.App, Name: *w.Name}
	var err error
	if p.TailLines, err = intIn("tailLines", w.TailLines, 200, 1, 1000); err != nil {
		return p, err
	}
	if w.SinceSec != nil {
		if p.SinceSec, err = intIn("sinceSec", w.SinceSec, 0, 1, 86400); err != nil {
			return p, err
		}
	}
	return p, nil
}

// DecodeParams is the strict params decode shared with other typed-job
// packages: unknown fields, trailing data and JSON null anywhere are refused
// (REJECTED_INVALID_PARAMS).
func DecodeParams(raw json.RawMessage, dst any) error { return decode(raw, dst) }

// UUIDRe matches a UUID (any version).
var UUIDRe = uuidRe
