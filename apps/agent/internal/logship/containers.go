package logship

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
)

// MaxHeartbeatContainers bounds heartbeat containers[].
const MaxHeartbeatContainers = 50

// Managed is a pPanel-managed container (ownership labels + name rule).
type Managed struct {
	ID, Name, App, Service, DeploymentID, State string
}

// ManagedContainers lists pPanel-managed containers only: label
// ppanel.managed=true, a valid ppanel.app and a name matching the ownership
// rule for that app (and service, when labelled).
func ManagedContainers(ctx context.Context, cli *docker.Client) ([]Managed, error) {
	cs, err := cli.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var out []Managed
	for _, c := range cs {
		if len(c.Names) == 0 || c.Labels[containerops.LabelManaged] != "true" {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		app := c.Labels[containerops.LabelApp]
		svc := c.Labels[containerops.LabelService]
		if !containerops.NameMatchesApp(app, name) {
			continue
		}
		if svc != "" && !containerops.NameMatchesService(app, svc, name) {
			continue
		}
		if svc == "" && !containerops.PlainNameMatchesApp(app, name) {
			continue
		}
		if !docker.ContainerIDRe.MatchString(c.ID) {
			continue
		}
		out = append(out, Managed{ID: c.ID, Name: name, App: app, Service: svc, DeploymentID: c.Labels[containerops.LabelDeployment], State: c.State})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ContainerStat is one heartbeat containers[] element.
type ContainerStat struct {
	Name          string   `json:"name"`
	App           string   `json:"app"`
	Service       *string  `json:"service"`
	DeploymentID  *string  `json:"deploymentId"`
	State         string   `json:"state"`
	Health        string   `json:"health"`
	RestartCount  int      `json:"restartCount"`
	CPUPct        *float64 `json:"cpuPct,omitempty"`
	MemBytes      *uint64  `json:"memBytes,omitempty"`
	MemLimitBytes *uint64  `json:"memLimitBytes,omitempty"`
}

func normState(s string) string {
	switch s {
	case "running", "exited", "restarting", "paused", "created", "dead":
		return s
	case "removing":
		return "dead"
	}
	return "dead"
}

// Collector produces heartbeat containers[] (managed containers only).
type Collector struct {
	Docker *docker.Client
	mu     sync.Mutex
	prev   map[string]docker.CPUStats
}

// Collect returns nil when Docker is unknown/unreachable (the field is then
// omitted), else the (possibly empty) list, bounded to 50.
func (c *Collector) Collect(ctx context.Context) *[]ContainerStat {
	if c == nil || c.Docker == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ms, err := ManagedContainers(ctx, c.Docker)
	if err != nil {
		return nil
	}
	if len(ms) > MaxHeartbeatContainers {
		ms = ms[:MaxHeartbeatContainers]
	}
	out := make([]ContainerStat, len(ms))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	seen := map[string]bool{}
	for i, m := range ms {
		seen[m.ID] = true
		out[i] = ContainerStat{Name: m.Name, App: m.App, Service: strp(m.Service), DeploymentID: strp(m.DeploymentID),
			State: normState(m.State), Health: "none"}
		wg.Add(1)
		go func(i int, m Managed) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cctx, ccancel := context.WithTimeout(ctx, 4*time.Second)
			defer ccancel()
			if hi, err := c.Docker.Inspect(cctx, m.ID); err == nil {
				out[i].RestartCount = hi.RestartCount
				if hi.State.Health != nil {
					switch h := hi.State.Health.Status; h {
					case "healthy", "unhealthy", "starting":
						out[i].Health = h
					}
				}
				if hi.State.Status != "" {
					out[i].State = normState(hi.State.Status)
				}
			}
			if out[i].State != "running" {
				return
			}
			st, err := c.Docker.ContainerStats(cctx, m.ID)
			if err != nil {
				return
			}
			used := st.MemUsed()
			out[i].MemBytes = &used
			if st.MemoryStats.Limit > 0 {
				l := st.MemoryStats.Limit
				out[i].MemLimitBytes = &l
			}
			prev := st.PreCPUStats
			c.mu.Lock()
			if prev.SystemUsage == 0 {
				prev = c.prev[m.ID]
			}
			if c.prev == nil {
				c.prev = map[string]docker.CPUStats{}
			}
			c.prev[m.ID] = st.CPUStats
			c.mu.Unlock()
			if pct, ok := docker.CPUPercent(prev, st.CPUStats); ok {
				out[i].CPUPct = &pct
			}
		}(i, m)
	}
	wg.Wait()
	c.mu.Lock()
	for id := range c.prev {
		if !seen[id] {
			delete(c.prev, id)
		}
	}
	c.mu.Unlock()
	return &out
}
