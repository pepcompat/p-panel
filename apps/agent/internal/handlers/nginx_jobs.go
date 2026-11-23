package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/nginxops"
)

// P3 nginx typed jobs (docs/AGENT_PROTOCOL.md "Nginx typed jobs (P3)").
// The handlers are thin: strict decode + path policy preflight here, all file
// and process work in internal/nginxops (under a process-wide lock).

func nginxManager(d *Deps) (*nginxops.Manager, error) {
	if d.Nginx == nil {
		return nil, jobs.Errorf(nginxops.CodeNginxNotPresent, "nginx operations are not configured on this agent")
	}
	return d.Nginx, nil
}

// NginxReadFiles implements nginx.read_files (read-only).
type NginxReadFiles struct{ d *Deps }

func (*NginxReadFiles) Type() string           { return "nginx.read_files" }
func (*NginxReadFiles) Mutating() bool         { return false }
func (*NginxReadFiles) Timeout() time.Duration { return 60 * time.Second }
func (*NginxReadFiles) Decode(raw json.RawMessage) (any, error) {
	return nginxops.DecodeRead(raw)
}
func (h *NginxReadFiles) Preflight(params any) error {
	m, err := nginxManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckPaths(params.(nginxops.ReadParams).Paths, false)
}
func (h *NginxReadFiles) Run(ctx context.Context, params any) (any, error) {
	m, err := nginxManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Read(ctx, params.(nginxops.ReadParams))
}

func revisionPaths(p nginxops.RevisionParams) []string {
	out := make([]string, len(p.Files))
	for i, f := range p.Files {
		out[i] = f.Path
	}
	return out
}

// NginxValidate implements nginx.validate (mutating dry run, never reloads).
type NginxValidate struct{ d *Deps }

func (*NginxValidate) Type() string           { return "nginx.validate" }
func (*NginxValidate) Mutating() bool         { return true }
func (*NginxValidate) Timeout() time.Duration { return 120 * time.Second }
func (*NginxValidate) Decode(raw json.RawMessage) (any, error) {
	return nginxops.DecodeValidate(raw)
}
func (h *NginxValidate) Preflight(params any) error {
	m, err := nginxManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckPaths(revisionPaths(params.(nginxops.RevisionParams)), true)
}
func (h *NginxValidate) Run(ctx context.Context, params any) (any, error) {
	m, err := nginxManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Validate(ctx, params.(nginxops.RevisionParams))
}

// NginxApply implements nginx.apply (mutating).
type NginxApply struct{ d *Deps }

func (*NginxApply) Type() string           { return "nginx.apply" }
func (*NginxApply) Mutating() bool         { return true }
func (*NginxApply) Timeout() time.Duration { return 300 * time.Second }
func (*NginxApply) Decode(raw json.RawMessage) (any, error) {
	return nginxops.DecodeApply(raw)
}
func (h *NginxApply) Preflight(params any) error {
	m, err := nginxManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckPaths(revisionPaths(params.(nginxops.RevisionParams)), true)
}
func (h *NginxApply) Run(ctx context.Context, params any) (any, error) {
	m, err := nginxManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Apply(ctx, params.(nginxops.RevisionParams))
}

// NginxRevert implements nginx.revert (mutating).
type NginxRevert struct{ d *Deps }

func (*NginxRevert) Type() string           { return "nginx.revert" }
func (*NginxRevert) Mutating() bool         { return true }
func (*NginxRevert) Timeout() time.Duration { return 180 * time.Second }
func (*NginxRevert) Decode(raw json.RawMessage) (any, error) {
	return nginxops.DecodeRevert(raw)
}
func (h *NginxRevert) Preflight(params any) error {
	m, err := nginxManager(h.d)
	if err != nil {
		return err
	}
	p := params.(nginxops.RevertParams)
	paths := make([]string, len(p.ExpectedCurrent))
	for i, e := range p.ExpectedCurrent {
		paths[i] = e.Path
	}
	return m.CheckPaths(paths, true)
}
func (h *NginxRevert) Run(ctx context.Context, params any) (any, error) {
	m, err := nginxManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Revert(ctx, params.(nginxops.RevertParams))
}
