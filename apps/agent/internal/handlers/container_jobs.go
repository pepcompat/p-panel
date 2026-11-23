package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// P4 container typed jobs (docs/AGENT_PROTOCOL.md "Containers (P4)"). Thin
// handlers: strict decode + pure preflight here, all Docker Engine work in
// internal/containerops (the ONLY user of the write-capable docker.Engine).

func containerManager(d *Deps) (*containerops.Manager, error) {
	if d.Containers == nil {
		return nil, jobs.Errorf(containerops.CodeDockerUnavailable, "container operations are not configured on this agent")
	}
	return d.Containers, nil
}

// nameForApp is the pure part of the ownership rule, checked before ack.
func nameForApp(app, name string) error {
	if !containerops.NameMatchesApp(app, name) {
		return jobs.Errorf(containerops.CodeContainerNotManaged, "%s is not a pPanel-managed container name for app %s", name, app)
	}
	return nil
}

// ContainerRunCandidate implements container.run_candidate.
type ContainerRunCandidate struct{ d *Deps }

func (*ContainerRunCandidate) Type() string           { return "container.run_candidate" }
func (*ContainerRunCandidate) Mutating() bool         { return true }
func (*ContainerRunCandidate) Timeout() time.Duration { return 25 * time.Minute }
func (*ContainerRunCandidate) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeRun(raw)
}
func (h *ContainerRunCandidate) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.RunCandidate(ctx, params.(containerops.RunParams))
}

// ContainerStart implements container.start.
type ContainerStart struct{ d *Deps }

func (*ContainerStart) Type() string           { return "container.start" }
func (*ContainerStart) Mutating() bool         { return true }
func (*ContainerStart) Timeout() time.Duration { return 15 * time.Minute }
func (*ContainerStart) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeStart(raw)
}
func (*ContainerStart) Preflight(params any) error {
	p := params.(containerops.StartParams)
	return nameForApp(p.App, p.Name)
}
func (h *ContainerStart) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Start(ctx, params.(containerops.StartParams), false)
}

// ContainerRestart implements container.restart.
type ContainerRestart struct{ d *Deps }

func (*ContainerRestart) Type() string           { return "container.restart" }
func (*ContainerRestart) Mutating() bool         { return true }
func (*ContainerRestart) Timeout() time.Duration { return 15 * time.Minute }
func (*ContainerRestart) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeStart(raw)
}
func (*ContainerRestart) Preflight(params any) error {
	p := params.(containerops.StartParams)
	return nameForApp(p.App, p.Name)
}
func (h *ContainerRestart) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Start(ctx, params.(containerops.StartParams), true)
}

// ContainerStop implements container.stop.
type ContainerStop struct{ d *Deps }

func (*ContainerStop) Type() string           { return "container.stop" }
func (*ContainerStop) Mutating() bool         { return true }
func (*ContainerStop) Timeout() time.Duration { return 2 * time.Minute }
func (*ContainerStop) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeRef(raw)
}
func (*ContainerStop) Preflight(params any) error {
	p := params.(containerops.RefParams)
	return nameForApp(p.App, p.Name)
}
func (h *ContainerStop) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Stop(ctx, params.(containerops.RefParams))
}

// ContainerRemove implements container.remove.
type ContainerRemove struct{ d *Deps }

func (*ContainerRemove) Type() string           { return "container.remove" }
func (*ContainerRemove) Mutating() bool         { return true }
func (*ContainerRemove) Timeout() time.Duration { return 2 * time.Minute }
func (*ContainerRemove) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeRef(raw)
}
func (*ContainerRemove) Preflight(params any) error {
	p := params.(containerops.RefParams)
	return nameForApp(p.App, p.Name)
}
func (h *ContainerRemove) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Remove(ctx, params.(containerops.RefParams))
}

// ContainerList implements container.list (read-only).
type ContainerList struct{ d *Deps }

func (*ContainerList) Type() string           { return "container.list" }
func (*ContainerList) Mutating() bool         { return false }
func (*ContainerList) Timeout() time.Duration { return 60 * time.Second }
func (*ContainerList) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeList(raw)
}
func (h *ContainerList) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.List(ctx, params.(containerops.ListParams))
}

// ContainerLogs implements container.logs (read-only).
type ContainerLogs struct{ d *Deps }

func (*ContainerLogs) Type() string           { return "container.logs" }
func (*ContainerLogs) Mutating() bool         { return false }
func (*ContainerLogs) Timeout() time.Duration { return 60 * time.Second }
func (*ContainerLogs) Decode(raw json.RawMessage) (any, error) {
	return containerops.DecodeLogs(raw)
}
func (*ContainerLogs) Preflight(params any) error {
	p := params.(containerops.LogsParams)
	return nameForApp(p.App, p.Name)
}
func (h *ContainerLogs) Run(ctx context.Context, params any) (any, error) {
	m, err := containerManager(h.d)
	if err != nil {
		return nil, err
	}
	return m.Logs(ctx, params.(containerops.LogsParams))
}
