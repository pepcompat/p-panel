// Package buildops implements the P4b build-node jobs image.build and
// source.inspect (docs/AGENT_PROTOCOL.md "Builds (P4b) — authoritative").
//
// Security model: builds only run on agents whose LOCAL config sets
// build.enabled (operator decision, never Center-controlled). Sources are
// fetched with the git binary through execx (fixed argv, minimal env, auth
// header only via GIT_CONFIG_* env), the build context is assembled by the
// agent (no .git, no symlink escape, size cap) and built through the Docker
// Engine API classic builder. A Dockerfile's RUN steps execute as containers
// on the build node: the build node must be a dedicated, trusted host.
package buildops

import (
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/ppanel/ppanel/apps/agent/internal/buildtemplates"
	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Error codes (BUILD_ERROR_CODES in packages/shared-contracts).
const (
	CodeGitHostNotAllowed  = "GIT_HOST_NOT_ALLOWED"
	CodeSourceFetchFailed  = "SOURCE_FETCH_FAILED"
	CodeDockerfileNotFound = "DOCKERFILE_NOT_FOUND"
	CodeBuildFailed        = "BUILD_FAILED"
	CodeBuildTimeout       = "BUILD_TIMEOUT"
	CodePushFailed         = "PUSH_FAILED"
	CodeNotABuildNode      = "NOT_A_BUILD_NODE"
)

// Contract regexes (packages/shared-contracts/src/jobs.ts).
var (
	CommitShaRe = regexp.MustCompile(`^[a-f0-9]{40}$`)
	GitURLRe    = regexp.MustCompile(`^(https|git)://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9._~/-]{1,300}$`)
	ImageRepoRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$`)
	subdirRe    = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
	dockerfRe   = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	targetRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// GitSource mirrors gitSourceSchema (defaults applied).
type GitSource struct {
	URL       string `json:"url"`
	CommitSha string `json:"commitSha"`
	Subdir    string `json:"subdir"`
	Auth      bool   `json:"auth"`
}

// Scheme returns "https" or "git".
func (s GitSource) Scheme() string {
	u, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// HostPort returns the lowercased host[:port] of the URL (allowlist key).
func (s GitSource) HostPort() string {
	u, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// Limits mirrors imageBuildParams.limits.
type Limits struct {
	MemoryMb   int     `json:"memoryMb"`
	Cpus       float64 `json:"cpus"`
	TimeoutSec int     `json:"timeoutSec"`
}

// BuildParams is image.build.
type BuildParams struct {
	BuildID      string            `json:"buildId"`
	App          string            `json:"app"`
	Source       GitSource         `json:"source"`
	Dockerfile   string            `json:"dockerfile,omitempty"`
	Template     string            `json:"template,omitempty"`
	BuildArgs    map[string]string `json:"buildArgs"`
	Target       string            `json:"target,omitempty"`
	PushRepo     string            `json:"pushRepo"`
	RegistryAuth bool              `json:"registryAuth"`
	Network      string            `json:"network"`
	Limits       Limits            `json:"limits"`
}

// ID12 is the first 12 hex characters of buildId (tag suffix).
func (p BuildParams) ID12() string {
	return strings.ToLower(strings.ReplaceAll(p.BuildID, "-", ""))[:12]
}

// Tag is the local + pushed tag: build-<id12>.
func (p BuildParams) Tag() string { return "build-" + p.ID12() }

// InspectParams is source.inspect.
type InspectParams struct {
	Source GitSource `json:"source"`
}

func invalid(format string, a ...any) error {
	return jobs.Errorf(jobs.RejectedInvalidParams, format, a...)
}

func relPathOK(p string) bool {
	if strings.HasPrefix(p, "/") || strings.Contains(p, "//") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == ".git" {
			return false
		}
	}
	return true
}

type rawSource struct {
	URL       *string `json:"url"`
	CommitSha *string `json:"commitSha"`
	Subdir    *string `json:"subdir"`
	Auth      *bool   `json:"auth"`
}

func (r *rawSource) resolve() (GitSource, error) {
	var s GitSource
	if r == nil {
		return s, invalid("source is required")
	}
	if r.URL == nil || len(*r.URL) > 600 || !GitURLRe.MatchString(*r.URL) {
		return s, invalid("source.url must be an https:// (or allowlisted git://) URL without credentials")
	}
	if r.CommitSha == nil || !CommitShaRe.MatchString(*r.CommitSha) {
		return s, invalid("source.commitSha must be 40 lowercase hex characters")
	}
	s.URL, s.CommitSha = *r.URL, *r.CommitSha
	if r.Subdir != nil {
		if !subdirRe.MatchString(*r.Subdir) || !relPathOK(*r.Subdir) {
			return s, invalid("source.subdir must be a relative path inside the repository (no .., no .git)")
		}
		s.Subdir = strings.TrimSuffix(*r.Subdir, "/")
	}
	if r.Auth != nil {
		s.Auth = *r.Auth
	}
	return s, nil
}

// DecodeBuild strictly decodes image.build params.
func DecodeBuild(raw json.RawMessage) (BuildParams, error) {
	var w struct {
		BuildID      *string           `json:"buildId"`
		App          *string           `json:"app"`
		Source       *rawSource        `json:"source"`
		Dockerfile   *string           `json:"dockerfile"`
		Template     *string           `json:"template"`
		BuildArgs    map[string]string `json:"buildArgs"`
		Target       *string           `json:"target"`
		PushRepo     *string           `json:"pushRepo"`
		RegistryAuth *bool             `json:"registryAuth"`
		Network      *string           `json:"network"`
		Limits       *struct {
			MemoryMb   *int     `json:"memoryMb"`
			Cpus       *float64 `json:"cpus"`
			TimeoutSec *int     `json:"timeoutSec"`
		} `json:"limits"`
	}
	var p BuildParams
	if err := containerops.DecodeParams(raw, &w); err != nil {
		return p, err
	}
	if w.BuildID == nil || !containerops.UUIDRe.MatchString(*w.BuildID) {
		return p, invalid("buildId must be a UUID")
	}
	if w.App == nil || !containerops.AppSlugRe.MatchString(*w.App) {
		return p, invalid("app must match %s", containerops.AppSlugRe)
	}
	src, err := w.Source.resolve()
	if err != nil {
		return p, err
	}
	p = BuildParams{BuildID: strings.ToLower(*w.BuildID), App: *w.App, Source: src, BuildArgs: map[string]string{}, Network: "default",
		Limits: Limits{MemoryMb: 2048, Cpus: 2, TimeoutSec: 900}}
	if (w.Dockerfile == nil) == (w.Template == nil) {
		return p, invalid("exactly one of dockerfile or template is required")
	}
	if w.Dockerfile != nil {
		if !dockerfRe.MatchString(*w.Dockerfile) || !relPathOK(*w.Dockerfile) || strings.HasSuffix(*w.Dockerfile, "/") {
			return p, invalid("dockerfile must be a relative file path inside the context")
		}
		p.Dockerfile = *w.Dockerfile
	} else {
		if !buildtemplates.Valid(*w.Template) {
			return p, invalid("template must be one of %s", strings.Join(buildtemplates.Names, "|"))
		}
		p.Template = *w.Template
	}
	if len(w.BuildArgs) > 100 {
		return p, invalid("at most 100 buildArgs")
	}
	for k, v := range w.BuildArgs {
		if !containerops.EnvKeyRe.MatchString(k) {
			return p, invalid("buildArgs key %q must match %s", k, containerops.EnvKeyRe)
		}
		if len(v) > 1024 || strings.IndexByte(v, 0) >= 0 {
			return p, invalid("buildArgs %s value must be <=1024 bytes without NUL", k)
		}
		p.BuildArgs[k] = v
	}
	if w.Target != nil {
		if !targetRe.MatchString(*w.Target) {
			return p, invalid("target must match %s", targetRe)
		}
		p.Target = *w.Target
	}
	if w.PushRepo == nil || len(*w.PushRepo) > 300 || !ImageRepoRe.MatchString(*w.PushRepo) {
		return p, invalid("pushRepo must be registry[:port]/path without tag or digest")
	}
	p.PushRepo = *w.PushRepo
	if w.RegistryAuth != nil {
		p.RegistryAuth = *w.RegistryAuth
	}
	if w.Network != nil {
		if *w.Network != "default" && *w.Network != "none" {
			return p, invalid("network must be default|none")
		}
		p.Network = *w.Network
	}
	if l := w.Limits; l != nil {
		if l.MemoryMb != nil {
			if *l.MemoryMb < 256 || *l.MemoryMb > 32768 {
				return p, invalid("limits.memoryMb must be 256..32768")
			}
			p.Limits.MemoryMb = *l.MemoryMb
		}
		if l.Cpus != nil {
			if math.IsNaN(*l.Cpus) || *l.Cpus < 0.5 || *l.Cpus > 32 {
				return p, invalid("limits.cpus must be 0.5..32")
			}
			p.Limits.Cpus = *l.Cpus
		}
		if l.TimeoutSec != nil {
			if *l.TimeoutSec < 60 || *l.TimeoutSec > 3600 {
				return p, invalid("limits.timeoutSec must be 60..3600")
			}
			p.Limits.TimeoutSec = *l.TimeoutSec
		}
	}
	return p, nil
}

// DecodeInspect strictly decodes source.inspect params.
func DecodeInspect(raw json.RawMessage) (InspectParams, error) {
	var w struct {
		Source *rawSource `json:"source"`
	}
	if err := containerops.DecodeParams(raw, &w); err != nil {
		return InspectParams{}, err
	}
	s, err := w.Source.resolve()
	if err != nil {
		return InspectParams{}, err
	}
	return InspectParams{Source: s}, nil
}

// SourceInspectFiles mirrors SOURCE_INSPECT_FILES.
var SourceInspectFiles = []string{
	"package.json", "composer.json", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
	"compose.yml", "compose.yaml", "artisan", "next.config.js", "next.config.mjs", "next.config.ts", "nest-cli.json",
}
