// Package config loads and validates the agent configuration file.
//
// The file may be YAML or JSON (JSON is a subset of YAML). Unknown keys are
// rejected so typos never silently fall back to defaults.
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the production config location.
const DefaultPath = "/etc/ppanel-agent/config.yaml"

// DefaultStateDir is the production state directory.
const DefaultStateDir = "/var/lib/ppanel-agent"

// UnitNameRe is the systemd unit allowlist pattern shared with
// packages/shared-contracts (service.restart params.unit).
var UnitNameRe = regexp.MustCompile(`^[a-zA-Z0-9@._-]{1,128}\.service$`)

// Config is the on-disk agent configuration.
type Config struct {
	// CenterURL is the Center API base URL (enrollment only), e.g. https://center.example:4000.
	CenterURL string `yaml:"centerUrl" json:"centerUrl"`
	// StateDir holds key, certificates, identity and the completed-job cache.
	StateDir string `yaml:"stateDir" json:"stateDir"`
	// LogLevel: debug|info|warn|error.
	LogLevel string `yaml:"logLevel" json:"logLevel"`
	// HeartbeatIntervalSec is the initial interval; Center may override it.
	HeartbeatIntervalSec int `yaml:"heartbeatIntervalSec" json:"heartbeatIntervalSec"`
	// PollWaitSec is the long-poll wait sent to the gateway (max 25 by protocol).
	PollWaitSec int `yaml:"pollWaitSec" json:"pollWaitSec"`
	// OwnedUnits are the systemd units service.restart may act upon.
	OwnedUnits []string `yaml:"ownedUnits" json:"ownedUnits"`
	// OwnedUnitsFile optionally lists more owned units, one per line (# comments allowed).
	OwnedUnitsFile string `yaml:"ownedUnitsFile" json:"ownedUnitsFile"`
	// MaxBufferedResults caps results held in memory while Center is unreachable.
	MaxBufferedResults int `yaml:"maxBufferedResults" json:"maxBufferedResults"`
	// DockerSocket is the Docker Engine API unix socket (read-only GETs only).
	DockerSocket string `yaml:"dockerSocket" json:"dockerSocket"`
	// NginxBinary / SystemctlBinary override binary discovery (absolute paths only).
	NginxBinary     string `yaml:"nginxBinary" json:"nginxBinary"`
	SystemctlBinary string `yaml:"systemctlBinary" json:"systemctlBinary"`
	// PhpFpmPoolGlob is where PHP-FPM pool configs are read from.
	PhpFpmPoolGlob string `yaml:"phpFpmPoolGlob" json:"phpFpmPoolGlob"`
	// Nginx configures the P3 typed nginx jobs (read_files/validate/apply/revert).
	Nginx NginxConfig `yaml:"nginx" json:"nginx"`
	// Build configures the P4b build node role (image.build / source.inspect).
	Build BuildConfig `yaml:"build" json:"build"`
	// Logs configures P5 log shipping (local config only: the Center can never
	// add sources or paths).
	Logs LogsConfig `yaml:"logs" json:"logs"`
}

// Log source names (docs/AGENT_PROTOCOL.md "Telemetry").
const (
	LogSourceNginxAccess = "nginx_access"
	LogSourceNginxError  = "nginx_error"
	LogSourceContainer   = "container"
	LogSourceAgent       = "agent"
)

// Log shipping limits.
const (
	DefaultLogBufferCap      = 64 << 20
	MinLogBufferCap          = 1 << 20
	MaxLogBufferCap          = 4 << 30
	DefaultLogShipIntervalMs = 2000
	DefaultLogMaxBatch       = 1000
	MaxLogBatchEntries       = 5000
)

// LogSource is one configured log source.
type LogSource struct {
	// Source is nginx_access | nginx_error | container | agent.
	Source string `yaml:"source" json:"source"`
	// Path is required for nginx_* (clean absolute file path), forbidden otherwise.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// LogsConfig is the `logs:` section.
type LogsConfig struct {
	// Enabled turns log shipping on (default true).
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Sources defaults to nginx access/error under /var/log/nginx, managed containers and the agent.
	Sources []LogSource `yaml:"sources" json:"sources"`
	// BufferCapBytes caps the on-disk segment buffer (default 64 MiB, min 1 MiB).
	BufferCapBytes int64 `yaml:"bufferCapBytes" json:"bufferCapBytes"`
	// ShipIntervalMs is the ship cadence (default 2000).
	ShipIntervalMs int `yaml:"shipIntervalMs" json:"shipIntervalMs"`
	// MaxBatchEntries ships early once this many entries are pending (default 1000, max 5000).
	MaxBatchEntries int `yaml:"maxBatchEntries" json:"maxBatchEntries"`
}

// DefaultLogSources is used when logs.sources is empty.
func DefaultLogSources() []LogSource {
	return []LogSource{
		{Source: LogSourceNginxAccess, Path: "/var/log/nginx/access.log"},
		{Source: LogSourceNginxError, Path: "/var/log/nginx/error.log"},
		{Source: LogSourceContainer},
		{Source: LogSourceAgent},
	}
}

// LogBufferDir is where log segments are kept.
func (c *Config) LogBufferDir() string { return filepath.Join(c.StateDir, "logs", "buffer") }

// LogStateDir holds positions.json and the in-flight batch.
func (c *Config) LogStateDir() string { return filepath.Join(c.StateDir, "logs") }

// HasLogSource reports whether a source type is configured.
func (l *LogsConfig) HasLogSource(name string) bool {
	for _, s := range l.Sources {
		if s.Source == name {
			return true
		}
	}
	return false
}

func (l *LogsConfig) validate() []string {
	var errs []string
	if len(l.Sources) == 0 {
		l.Sources = DefaultLogSources()
	}
	if l.BufferCapBytes == 0 {
		l.BufferCapBytes = DefaultLogBufferCap
	}
	if l.ShipIntervalMs == 0 {
		l.ShipIntervalMs = DefaultLogShipIntervalMs
	}
	if l.MaxBatchEntries == 0 {
		l.MaxBatchEntries = DefaultLogMaxBatch
	}
	if l.BufferCapBytes < MinLogBufferCap || l.BufferCapBytes > MaxLogBufferCap {
		errs = append(errs, "logs.bufferCapBytes must be 1 MiB..4 GiB")
	}
	if l.ShipIntervalMs < 200 || l.ShipIntervalMs > 60000 {
		errs = append(errs, "logs.shipIntervalMs must be 200..60000")
	}
	if l.MaxBatchEntries < 1 || l.MaxBatchEntries > MaxLogBatchEntries {
		errs = append(errs, "logs.maxBatchEntries must be 1..5000")
	}
	seen := map[string]bool{}
	for i, s := range l.Sources {
		s.Source = strings.TrimSpace(s.Source)
		s.Path = strings.TrimSpace(s.Path)
		l.Sources[i] = s
		switch s.Source {
		case LogSourceNginxAccess, LogSourceNginxError:
			if s.Path == "" || !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path || s.Path == "/" {
				errs = append(errs, fmt.Sprintf("logs.sources[%d]: %s needs a clean absolute file path", i, s.Source))
			}
		case LogSourceContainer, LogSourceAgent:
			if s.Path != "" {
				errs = append(errs, fmt.Sprintf("logs.sources[%d]: %s takes no path", i, s.Source))
			}
		default:
			errs = append(errs, fmt.Sprintf("logs.sources[%d]: unknown source %q (nginx_access|nginx_error|container|agent)", i, s.Source))
			continue
		}
		key := s.Source + "\x00" + s.Path
		if seen[key] || (s.Path != "" && seen["path\x00"+s.Path]) {
			errs = append(errs, fmt.Sprintf("logs.sources[%d]: duplicate source", i))
		}
		seen[key] = true
		if s.Path != "" {
			seen["path\x00"+s.Path] = true
		}
	}
	return errs
}

// BuildConfig is the `build:` section. Builds are an OPERATOR decision on the
// host: the Center can never turn them on. A build node runs Dockerfile RUN
// steps as containers on its Docker engine, so it must be a dedicated,
// trusted host (this is not an isolation guarantee).
type BuildConfig struct {
	// Enabled makes this agent a build node (default false → NOT_A_BUILD_NODE).
	Enabled bool `yaml:"enabled" json:"enabled"`
	// GitHostsAllowlist lists the exact git hosts (host or host:port) sources may
	// be fetched from. git:// URLs are accepted only for hosts listed here
	// (intended for lab/dev git daemons; production should list https hosts only).
	GitHostsAllowlist []string `yaml:"gitHostsAllowlist" json:"gitHostsAllowlist"`
	// WorkDir holds per-build temp checkouts (default <stateDir>/builds).
	WorkDir string `yaml:"workDir" json:"workDir"`
}

// GitHostRe is an allowlist entry: exact host[:port].
var GitHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,252})(:[0-9]{1,5})?$`)

// BuildWorkDir returns the effective build work directory.
func (c *Config) BuildWorkDir() string {
	if c.Build.WorkDir != "" {
		return c.Build.WorkDir
	}
	return filepath.Join(c.StateDir, "builds")
}

// NginxRoot is the only nginx config root a production agent manages.
const NginxRoot = "/etc/nginx"

// TestNginxRootEnv must be "1" for the agent to accept nginx.root other than
// /etc/nginx (or nginx.prefix / nginx.confFile). It exists for unit/lab tests
// only; production installs never set it.
const TestNginxRootEnv = "PPANEL_AGENT_TEST_NGINX_ROOT"

// NginxConfig is the `nginx:` config section.
type NginxConfig struct {
	// Root is the physical directory holding the nginx config (default /etc/nginx).
	// Job paths are always expressed as /etc/nginx/...; a non-default root is only
	// accepted when PPANEL_AGENT_TEST_NGINX_ROOT=1 (tests).
	Root string `yaml:"root" json:"root"`
	// AllowedRoots optionally NARROWS the editable/readable paths to these
	// /etc/nginx/... prefixes (directories). Empty = all of /etc/nginx.
	AllowedRoots []string `yaml:"allowedRoots" json:"allowedRoots"`
	// Prefix / ConfFile are passed to nginx as -p / -c (test builds only, see TestNginxRootEnv).
	Prefix   string `yaml:"prefix" json:"prefix"`
	ConfFile string `yaml:"confFile" json:"confFile"`
}

// NginxTestOverridesAllowed reports whether test-only nginx overrides are enabled.
func NginxTestOverridesAllowed() bool { return os.Getenv(TestNginxRootEnv) == "1" }

var nginxPathRe = regexp.MustCompile(`^/etc/nginx/[A-Za-z0-9._/-]{1,200}$`)

// ValidateNginx checks the nginx section (shared by Config.Validate and nginxops.New).
func (n *NginxConfig) ValidateNginx() []string {
	var errs []string
	if n.Root == "" {
		n.Root = NginxRoot
	}
	if !filepath.IsAbs(n.Root) || filepath.Clean(n.Root) != n.Root {
		errs = append(errs, "nginx.root must be a clean absolute path")
	} else if n.Root != NginxRoot && !NginxTestOverridesAllowed() {
		errs = append(errs, "nginx.root must be "+NginxRoot+" (other roots require "+TestNginxRootEnv+"=1, tests only)")
	}
	for name, p := range map[string]string{"nginx.prefix": n.Prefix, "nginx.confFile": n.ConfFile} {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			errs = append(errs, name+" must be a clean absolute path")
		} else if !NginxTestOverridesAllowed() {
			errs = append(errs, name+" is only accepted with "+TestNginxRootEnv+"=1 (tests only)")
		}
	}
	for _, r := range n.AllowedRoots {
		if !nginxPathRe.MatchString(r) || filepath.Clean(r) != r || strings.Contains(r, "//") {
			errs = append(errs, fmt.Sprintf("nginx.allowedRoots: %q must be a clean directory under /etc/nginx/", r))
		}
	}
	return errs
}

// Default returns a config populated with defaults.
func Default() *Config {
	return &Config{
		StateDir:             DefaultStateDir,
		LogLevel:             "info",
		HeartbeatIntervalSec: 15,
		PollWaitSec:          25,
		MaxBufferedResults:   100,
		DockerSocket:         "/var/run/docker.sock",
		PhpFpmPoolGlob:       "/etc/php/*/fpm/pool.d/*.conf",
		Logs: LogsConfig{Enabled: true, BufferCapBytes: DefaultLogBufferCap,
			ShipIntervalMs: DefaultLogShipIntervalMs, MaxBatchEntries: DefaultLogMaxBatch},
	}
}

// Load reads the file at path (YAML or JSON), applies defaults and validates.
// A missing file yields defaults (validated) so `enroll` can run before config exists.
func Load(path string) (*Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, cfg.Validate()
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := Parse(b, cfg); err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

// Parse strictly decodes b into cfg (unknown fields rejected).
func Parse(b []byte, cfg *Config) error {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}

// Validate checks all fields and normalises strings.
func (c *Config) Validate() error {
	var errs []string
	c.CenterURL = strings.TrimSpace(c.CenterURL)
	c.StateDir = strings.TrimSpace(c.StateDir)
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		errs = append(errs, "stateDir must be an absolute path")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "logLevel must be one of debug|info|warn|error")
	}
	if c.HeartbeatIntervalSec < 5 || c.HeartbeatIntervalSec > 300 {
		errs = append(errs, "heartbeatIntervalSec must be 5..300")
	}
	if c.PollWaitSec < 1 || c.PollWaitSec > 25 {
		errs = append(errs, "pollWaitSec must be 1..25")
	}
	if c.MaxBufferedResults < 1 || c.MaxBufferedResults > 10000 {
		errs = append(errs, "maxBufferedResults must be 1..10000")
	}
	for _, u := range c.OwnedUnits {
		if !UnitNameRe.MatchString(u) {
			errs = append(errs, fmt.Sprintf("ownedUnits: invalid unit name %q", u))
		}
	}
	for name, p := range map[string]string{
		"dockerSocket": c.DockerSocket, "nginxBinary": c.NginxBinary,
		"systemctlBinary": c.SystemctlBinary, "ownedUnitsFile": c.OwnedUnitsFile,
	} {
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p) {
			errs = append(errs, name+" must be a clean absolute path")
		}
	}
	errs = append(errs, c.Nginx.ValidateNginx()...)
	for i, h := range c.Build.GitHostsAllowlist {
		h = strings.ToLower(strings.TrimSpace(h))
		c.Build.GitHostsAllowlist[i] = h
		if !GitHostRe.MatchString(h) {
			errs = append(errs, fmt.Sprintf("build.gitHostsAllowlist: %q must be an exact host or host:port", h))
		}
	}
	if w := c.Build.WorkDir; w != "" && (!filepath.IsAbs(w) || filepath.Clean(w) != w || w == "/") {
		errs = append(errs, "build.workDir must be a clean absolute path (not /)")
	}
	errs = append(errs, c.Logs.validate()...)
	if len(errs) > 0 {
		return errors.New("invalid config: " + strings.Join(errs, "; "))
	}
	return nil
}

// OwnedUnitSet returns the union of OwnedUnits and the entries of OwnedUnitsFile.
// Invalid names in the file are an error (fail closed).
func (c *Config) OwnedUnitSet() (map[string]bool, error) {
	set := make(map[string]bool, len(c.OwnedUnits))
	for _, u := range c.OwnedUnits {
		set[u] = true
	}
	if c.OwnedUnitsFile == "" {
		return set, nil
	}
	f, err := os.Open(c.OwnedUnitsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return set, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !UnitNameRe.MatchString(line) {
			return nil, fmt.Errorf("ownedUnitsFile: invalid unit name %q", line)
		}
		set[line] = true
	}
	return set, sc.Err()
}
