package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/buildops"
	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// P4b build-node and compose jobs (docs/AGENT_PROTOCOL.md "Builds (P4b)",
// "Compose (P4b)"). image.build / source.inspect are always registered (so the
// Center gets a clear answer) but run only when the LOCAL config enabled builds:
// otherwise NOT_A_BUILD_NODE before ack (Preflight).

func buildManager(d *Deps) (*buildops.Manager, error) {
	if d.Builds == nil {
		return nil, jobs.Errorf(buildops.CodeNotABuildNode, "this agent is not a build node (build.enabled is false in its local config)")
	}
	return d.Builds, nil
}

// ImageBuild implements image.build.
type ImageBuild struct{ d *Deps }

func (*ImageBuild) Type() string   { return "image.build" }
func (*ImageBuild) Mutating() bool { return true }

// Timeout exceeds the maximum limits.timeoutSec (3600 s) plus push/cleanup.
func (*ImageBuild) Timeout() time.Duration { return 70 * time.Minute }
func (*ImageBuild) Decode(raw json.RawMessage) (any, error) {
	return buildops.DecodeBuild(raw)
}
func (h *ImageBuild) Preflight(params any) error {
	m, err := buildManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckHost(params.(buildops.BuildParams).Source)
}
func (h *ImageBuild) Run(ctx context.Context, params any) (any, error) {
	m, err := buildManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Build(ctx, params.(buildops.BuildParams))
}

// SourceInspect implements source.inspect (read-only).
type SourceInspect struct{ d *Deps }

func (*SourceInspect) Type() string           { return "source.inspect" }
func (*SourceInspect) Mutating() bool         { return false }
func (*SourceInspect) Timeout() time.Duration { return buildops.InspectTimeout + time.Minute }
func (*SourceInspect) Decode(raw json.RawMessage) (any, error) {
	return buildops.DecodeInspect(raw)
}
func (h *SourceInspect) Preflight(params any) error {
	m, err := buildManager(h.d)
	if err != nil {
		return err
	}
	return m.CheckHost(params.(buildops.InspectParams).Source)
}
func (h *SourceInspect) Run(ctx context.Context, params any) (any, error) {
	m, err := buildManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Inspect(ctx, params.(buildops.InspectParams))
}

// ComposeApply implements compose.apply.
type ComposeApply struct{ d *Deps }

func (*ComposeApply) Type() string           { return "compose.apply" }
func (*ComposeApply) Mutating() bool         { return true }
func (*ComposeApply) Timeout() time.Duration { return 60 * time.Minute }
func (*ComposeApply) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeComposeApply(raw)
}
func (h *ComposeApply) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.ComposeApply(ctx, params.(containerops.ComposeApplyParams))
}

// ComposeStop implements compose.stop.
type ComposeStop struct{ d *Deps }

func (*ComposeStop) Type() string           { return "compose.stop" }
func (*ComposeStop) Mutating() bool         { return true }
func (*ComposeStop) Timeout() time.Duration { return 10 * time.Minute }
func (*ComposeStop) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeComposeStop(raw)
}
func (h *ComposeStop) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.ComposeStop(ctx, params.(containerops.ComposeStopParams))
}
