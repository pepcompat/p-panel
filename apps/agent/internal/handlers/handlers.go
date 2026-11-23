// Package handlers contains the allowlisted, typed job handlers:
// inventory.collect, discovery.scan (read-only), service.restart (mutating,
// owned units only), the P3 nginx.* jobs (see nginx_jobs.go) and the P4 container.* jobs (container_jobs.go). There is no generic command handler by design.
package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/facts"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/netaddr"
	"github.com/ppanel/ppanel/apps/agent/internal/nginx"
	"github.com/ppanel/ppanel/apps/agent/internal/nginxops"
	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

// Deps are shared handler dependencies.
type Deps struct {
	Host    *host.Env
	Sampler *metrics.Sampler
	// OwnedUnits returns the current owned-unit allowlist (re-read per job).
	OwnedUnits func() (map[string]bool, error)
	// Nginx runs the P3 nginx typed jobs (nil = jobs fail with NGINX_NOT_PRESENT).
	Nginx *nginxops.Manager
	// Containers runs the P4 container.* jobs (nil = DOCKER_UNAVAILABLE).
	Containers *containerops.Manager
}

// RegisterAll registers every allowlisted handler.
func RegisterAll(r *jobs.Registry, d *Deps) {
	r.Register(&Inventory{d})
	r.Register(&Discovery{d})
	r.Register(&ServiceRestart{d})
	r.Register(&NginxReadFiles{d})
	r.Register(&NginxValidate{d})
	r.Register(&NginxApply{d})
	r.Register(&NginxRevert{d})
	r.Register(&ContainerRunCandidate{d})
	r.Register(&ContainerStart{d})
	r.Register(&ContainerRestart{d})
	r.Register(&ContainerStop{d})
	r.Register(&ContainerRemove{d})
	r.Register(&ContainerList{d})
	r.Register(&ContainerLogs{d})
}

// ---------------- inventory.collect ----------------

// Inventory implements inventory.collect {}.
type Inventory struct{ d *Deps }

func (*Inventory) Type() string           { return "inventory.collect" }
func (*Inventory) Mutating() bool         { return false }
func (*Inventory) Timeout() time.Duration { return 60 * time.Second }
func (*Inventory) Decode(raw json.RawMessage) (any, error) {
	var p struct{}
	return p, jobs.DecodeStrict(raw, &p)
}

type section struct {
	Status string `json:"status"` // ok|unavailable|error
	Error  string `json:"error,omitempty"`
	Data   any    `json:"data,omitempty"`
}

func ok(d any) section               { return section{Status: "ok", Data: d} }
func unavailable(msg string) section { return section{Status: "unavailable", Error: msg} }
func failed(err error) section       { return section{Status: "error", Error: err.Error()} }

func (h *Inventory) Run(ctx context.Context, _ any) (any, error) {
	d := h.d
	out := map[string]any{
		"collectedAt":  time.Now().UTC().Format(time.RFC3339),
		"agentVersion": version.Version,
		"host":         map[string]any{"hostname": facts.Hostname(), "os": facts.Collect()},
		"metrics":      d.Sampler.Detailed(),
		"addresses":    netaddr.Detect(),
		"capabilities": d.Host.Capabilities(),
		"nginx":        d.Host.Nginx(ctx),
		"docker":       dockerSection(ctx, d),
		"systemd":      systemdSection(ctx, d),
		"phpFpm":       phpSection(d),
	}
	return out, nil
}

func dockerSection(ctx context.Context, d *Deps) section {
	if d.Host.Docker == nil || !d.Host.Docker.Accessible() {
		return unavailable("docker socket not accessible")
	}
	v, err := d.Host.Docker.EngineVersion(ctx)
	if err != nil {
		return failed(err)
	}
	cs, err := d.Host.Docker.Containers(ctx)
	if err != nil {
		return failed(err)
	}
	return ok(map[string]any{"engine": v, "containers": cs})
}

func systemdSection(ctx context.Context, d *Deps) section {
	units, err := d.Host.SystemdUnits(ctx)
	if err != nil {
		return unavailable(err.Error())
	}
	if len(units) > 2000 {
		units = units[:2000]
	}
	return ok(map[string]any{"units": units})
}

func phpSection(d *Deps) section {
	pools, err := d.Host.PhpFpmPools()
	if err != nil {
		return failed(err)
	}
	if len(pools) == 0 {
		return unavailable("no php-fpm pool files found")
	}
	return ok(map[string]any{"pools": pools})
}

// ---------------- discovery.scan ----------------

// Discovery implements discovery.scan { sources: [...] } (read-only).
type Discovery struct{ d *Deps }

var discoverySources = map[string]bool{"nginx": true, "docker": true, "systemd": true, "php-fpm": true, "ports": true}

type discoveryParams struct {
	Sources []string `json:"sources"`
}

func (*Discovery) Type() string           { return "discovery.scan" }
func (*Discovery) Mutating() bool         { return false }
func (*Discovery) Timeout() time.Duration { return 120 * time.Second }
func (*Discovery) Decode(raw json.RawMessage) (any, error) {
	var p discoveryParams
	if err := jobs.DecodeStrict(raw, &p); err != nil {
		return nil, err
	}
	if len(p.Sources) == 0 {
		return nil, fmt.Errorf("sources must contain at least one entry")
	}
	seen := map[string]bool{}
	for _, s := range p.Sources {
		if !discoverySources[s] {
			return nil, fmt.Errorf("unknown source %q", s)
		}
		if seen[s] {
			return nil, fmt.Errorf("duplicate source %q", s)
		}
		seen[s] = true
	}
	return p, nil
}

func (h *Discovery) Run(ctx context.Context, params any) (any, error) {
	p := params.(discoveryParams)
	d := h.d
	res := map[string]any{"scannedAt": time.Now().UTC().Format(time.RFC3339), "mode": "discover", "readOnly": true}
	for _, s := range p.Sources {
		switch s {
		case "nginx":
			res[s] = nginxDiscovery(ctx, d)
		case "docker":
			res[s] = dockerSection(ctx, d)
		case "systemd":
			res[s] = systemdSection(ctx, d)
		case "php-fpm":
			res[s] = phpSection(d)
		case "ports":
			ls, err := d.Host.ListeningPorts()
			if err != nil {
				res[s] = unavailable(err.Error())
			} else {
				res[s] = ok(map[string]any{"listeners": ls})
			}
		}
	}
	return res, nil
}

func nginxDiscovery(ctx context.Context, d *Deps) section {
	info := d.Host.Nginx(ctx)
	if !info.Present {
		return unavailable("nginx binary not found")
	}
	dump, stderr, err := d.Host.NginxDump(ctx)
	if err != nil {
		s := failed(err)
		s.Data = map[string]any{"nginx": info, "stderr": truncate(stderr, 2000)}
		return s
	}
	rep, err := nginx.ParseAndAnalyze(dump, "nginx-T")
	if err != nil {
		s := failed(fmt.Errorf("parse nginx -T: %w", err))
		s.Data = map[string]any{"nginx": info}
		return s
	}
	useDiskChecksums(rep.Files, readConfigFile)
	return ok(map[string]any{"nginx": info, "report": rep})
}

// readConfigFile reads a config file for checksumming (follows symlinks, like nginx.read_files).
var readConfigFile = func(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxChecksumBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxChecksumBytes {
		return nil, fmt.Errorf("file larger than %d bytes", maxChecksumBytes)
	}
	return b, nil
}

const maxChecksumBytes = 4 << 20

// useDiskChecksums replaces the `nginx -T` section checksum with the sha256 of the file on disk, so
// scan checksums are directly comparable with nginx.read_files / nginx.apply (which hash file bytes).
// The dump text can differ from the file (e.g. trailing newline), which would otherwise produce
// false drift after every pPanel apply. Unreadable files keep the dump checksum, marked "nginx-T".
func useDiskChecksums(files []nginx.FileInfo, read func(string) ([]byte, error)) {
	for i := range files {
		files[i].ShaSource = "nginx-T"
		if b, err := read(files[i].Path); err == nil {
			sum := sha256.Sum256(b)
			files[i].Sha256 = hex.EncodeToString(sum[:])
			files[i].ShaSource = "disk"
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------- service.restart ----------------

// ServiceRestart implements service.restart { unit } for owned units only.
type ServiceRestart struct{ d *Deps }

type restartParams struct {
	Unit string `json:"unit"`
}

// unitRe mirrors packages/shared-contracts plus: must start with [A-Za-z0-9]
// (no option injection like "--help.service") and must not contain "..".
var unitRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,127}\.service$`)

// ValidUnitName reports whether name is an acceptable systemd service unit.
func ValidUnitName(name string) bool {
	return config.UnitNameRe.MatchString(name) && unitRe.MatchString(name) && !strings.Contains(name, "..")
}

func (*ServiceRestart) Type() string           { return "service.restart" }
func (*ServiceRestart) Mutating() bool         { return true }
func (*ServiceRestart) Timeout() time.Duration { return 120 * time.Second }
func (*ServiceRestart) Decode(raw json.RawMessage) (any, error) {
	var p restartParams
	if err := jobs.DecodeStrict(raw, &p); err != nil {
		return nil, err
	}
	if !ValidUnitName(p.Unit) {
		return nil, fmt.Errorf("invalid unit name")
	}
	return p, nil
}

// Preflight enforces the local authority boundary before ack/execution.
func (h *ServiceRestart) Preflight(params any) error {
	p := params.(restartParams)
	if !ValidUnitName(p.Unit) {
		return jobs.Errorf(jobs.RejectedInvalidParams, "invalid unit name")
	}
	owned, err := h.d.OwnedUnits()
	if err != nil {
		return jobs.Errorf(jobs.RejectedNotOwned, "owned-unit allowlist unreadable: %v", err)
	}
	if !owned[p.Unit] {
		return jobs.Errorf(jobs.RejectedNotOwned, "unit %s is not in this agent's owned-unit allowlist", p.Unit)
	}
	return nil
}

func (h *ServiceRestart) Run(ctx context.Context, params any) (any, error) {
	p := params.(restartParams)
	if err := h.Preflight(p); err != nil { // re-checked at execution time (allowlist may change)
		return nil, err
	}
	bin, found := execx.Find("systemctl", h.d.Host.SystemctlBinary)
	if !found {
		return nil, jobs.Errorf(jobs.HandlerFailed, "systemctl not found")
	}
	res, err := h.d.Host.Exec.Run(ctx, bin, []string{"restart", "--no-ask-password", "--", p.Unit}, 90*time.Second, 64<<10)
	if err != nil {
		return nil, jobs.Errorf(jobs.HandlerFailed, "systemctl restart: %v", err)
	}
	if res.ExitCode != 0 {
		e := jobs.Errorf(jobs.HandlerFailed, "systemctl restart exited %d", res.ExitCode)
		e.Details = map[string]any{"stderr": truncate(string(res.Stderr), 2000)}
		return nil, e
	}
	st, err := h.d.Host.Exec.Run(ctx, bin, []string{"is-active", "--", p.Unit}, 10*time.Second, 4<<10)
	active := ""
	if err == nil {
		active = strings.TrimSpace(string(st.Stdout))
	}
	return map[string]any{"unit": p.Unit, "restarted": true, "activeState": active}, nil
}
