package logship

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

const (
	idWeb   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idApi   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idOther = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	idFake  = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func managedLabels(app, svc string) map[string]string {
	l := map[string]string{"ppanel.managed": "true", "ppanel.app": app, "ppanel.deployment": "0190f4c2-0000-7000-8000-00000000d001"}
	if svc != "" {
		l["ppanel.service"] = svc
	}
	return l
}

func seedEngine(t *testing.T, base time.Time) *fakeEngine {
	fe := newFakeEngine(t)
	fe.add(&fakeCtr{ID: idWeb, Name: "ppanel-web-1a2b3c4d", State: "running", Health: "healthy", Restarts: 2, Labels: managedLabels("web", ""),
		MemUsage: 100 << 20, MemCache: 20 << 20,
		Logs: []fakeLog{
			{base.Add(1 * time.Millisecond), 1, `{"level":"warn","msg":"slow"}`},
			{base.Add(2 * time.Millisecond), 2, "boom token=abcdef123"},
			{base.Add(3 * time.Millisecond), 1, "third"},
		}})
	fe.add(&fakeCtr{ID: idApi, Name: "ppanel-shop-api-0badc0de", State: "exited", Labels: managedLabels("shop", "api")})
	// not managed: no labels / wrong name / name does not match labels
	fe.add(&fakeCtr{ID: idOther, Name: "postgres", State: "running", Labels: map[string]string{}})
	fe.add(&fakeCtr{ID: idFake, Name: "evil-web-1a2b3c4d", State: "running", Labels: managedLabels("web", "")})
	return fe
}

func TestManagedContainersOnly(t *testing.T) {
	fe := seedEngine(t, time.Now())
	ms, err := ManagedContainers(context.Background(), docker.New(fe.Socket))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Name != "ppanel-shop-api-0badc0de" || ms[0].Service != "api" || ms[1].Name != "ppanel-web-1a2b3c4d" {
		t.Fatalf("%+v", ms)
	}
}

func TestHeartbeatContainersCollector(t *testing.T) {
	fe := seedEngine(t, time.Now())
	c := &Collector{Docker: docker.New(fe.Socket)}
	got := c.Collect(context.Background())
	if got == nil || len(*got) != 2 {
		t.Fatalf("%v", got)
	}
	b, _ := json.Marshal(got)
	s := string(b)
	if strings.Contains(s, "postgres") || strings.Contains(s, "evil") || strings.Contains(s, "SECRET") {
		t.Fatalf("unmanaged container or env leaked: %s", s)
	}
	api, web := (*got)[0], (*got)[1]
	if web.State != "running" || web.Health != "healthy" || web.RestartCount != 2 || web.App != "web" || web.Service != nil ||
		web.DeploymentID == nil || web.MemBytes == nil || *web.MemBytes != 80<<20 || web.MemLimitBytes == nil || *web.MemLimitBytes != 536870912 {
		t.Fatalf("web %s", s)
	}
	if web.CPUPct != nil {
		t.Fatalf("first sample has no delta; cpuPct must be omitted: %v", *web.CPUPct)
	}
	if api.State != "exited" || api.Health != "none" || api.Service == nil || *api.Service != "api" || api.MemBytes != nil || api.CPUPct != nil {
		t.Fatalf("api %s", s)
	}
	got = c.Collect(context.Background())
	web = (*got)[1]
	// 50ms cpu per 1s system on 2 cpus = 10%
	if web.CPUPct == nil || *web.CPUPct != 10 {
		t.Fatalf("cpuPct %v", web.CPUPct)
	}
	for _, call := range fe.callsSnapshot() {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatalf("non-GET call %s", call)
		}
		if strings.Contains(call, "/stats") && !strings.Contains(call, "stream=false") {
			t.Fatalf("stats must be one-shot: %s", call)
		}
	}
	// docker unreachable → field omitted (nil)
	if (&Collector{Docker: docker.New("/nonexistent.sock")}).Collect(context.Background()) != nil {
		t.Fatal("unknown docker must yield nil")
	}
}

func TestContainerFollowerDemuxAndSince(t *testing.T) {
	base := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	fe := seedEngine(t, base)
	dir := t.TempDir()
	cfg := testLogsCfg(8<<20, 1000)
	cfg.Sources = []config.LogSource{{Source: SourceContainer}}
	red := redact.New()
	p, err := New(Options{Logs: cfg, StateDir: dir, Docker: docker.New(fe.Socket), Redactor: red})
	if err != nil {
		t.Fatal(err)
	}
	p.followers.StartSince = base
	p.followers.Retry = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ms, _ := ManagedContainers(ctx, p.o.Docker)
	p.followers.Sync(ctx, ms)
	if p.followers.Active() != 1 {
		t.Fatalf("followers=%d (only running managed)", p.followers.Active())
	}
	waitFor(t, "3 entries", 5*time.Second, func() bool { return p.Buffer().Stats().Pending == 3 })
	es := drain(t, p)
	if es[0].Stream == nil || *es[0].Stream != "stdout" || *es[0].Level != "warn" || *es[0].Container != "ppanel-web-1a2b3c4d" || *es[0].App != "web" || es[0].Service != nil {
		t.Fatalf("entry0 %+v", es[0])
	}
	if *es[1].Stream != "stderr" || *es[1].Level != "error" || es[1].Line != "boom token=[REDACTED]" {
		t.Fatalf("entry1 %+v line=%q", es[1], es[1].Line)
	}
	if es[2].TS != "2026-11-23T10:00:00.003Z" || es[2].Line != "third" || es[2].Level != nil {
		t.Fatalf("entry2 %+v", es[2])
	}
	if !strings.HasPrefix(fe.callsSnapshot()[len(fe.callsSnapshot())-1], "GET /containers/"+idWeb+"/logs?") {
		t.Fatal("follow call not last")
	}
	// new line arrives, stream reconnects: since = last ts + 1ns → no duplicates
	fe.mu.Lock()
	fe.ctrs[idWeb].Logs = append(fe.ctrs[idWeb].Logs, fakeLog{base.Add(4 * time.Millisecond), 1, "fourth"})
	fe.mu.Unlock()
	fe.endStream(idWeb)
	waitFor(t, "fourth", 5*time.Second, func() bool { return p.Buffer().Stats().Pending == 1 })
	es = drain(t, p)
	if len(es) != 1 || es[0].Line != "fourth" {
		t.Fatalf("after reconnect: %v", lines(es))
	}
	var follows []string
	for _, c := range fe.callsSnapshot() {
		if strings.Contains(c, "/logs?") {
			follows = append(follows, c)
		}
	}
	if len(follows) < 2 || !strings.Contains(follows[1], "since=1795428000.003000001") ||
		!strings.Contains(follows[1], "follow=1") || !strings.Contains(follows[1], "timestamps=1") || !strings.Contains(follows[1], "stderr=1") {
		t.Fatalf("reconnect query: %v", follows)
	}
	// container stops → follower stopped; positions keep last ts across restart
	fe.mu.Lock()
	fe.ctrs[idWeb].State = "exited"
	fe.mu.Unlock()
	ms, _ = ManagedContainers(ctx, p.o.Docker)
	p.followers.Sync(ctx, ms)
	if p.followers.Active() != 0 {
		t.Fatal("follower not stopped")
	}
	p.followers.Stop()
	p.pos.Save()
	pos2 := OpenPositions(filepath.Join(dir, "positions.json"))
	if got := pos2.Container(idWeb); !got.Equal(base.Add(4 * time.Millisecond)) {
		t.Fatalf("persisted since %v", got)
	}
}
