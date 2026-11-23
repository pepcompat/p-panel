package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/docker/dockertest"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/logship"
	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

// P5: heartbeat carries containers[] (managed only) + logShipping, and the
// agent's own log is shipped redacted over the mTLS gateway.
func TestHeartbeatTelemetryAndLogShipping(t *testing.T) {
	c, dir := enrolled(t, nil)
	eng := dockertest.New(t)
	eng.AddContainer(&dockertest.Container{Name: "ppanel-web-1a2b3c4d", Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "web"}, RestartCount: 1})
	eng.AddContainer(&dockertest.Container{Name: "postgres", Labels: map[string]string{}})

	cfg := config.Default()
	cfg.StateDir = dir
	cfg.Logs.Sources = []config.LogSource{{Source: config.LogSourceAgent}}
	cfg.Logs.ShipIntervalMs = 200
	cfg.Logs.BufferCapBytes = 2 << 20
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	sink := logship.NewAgentSink()
	logger := slog.New(logship.NewTee(slog.NewJSONHandler(io.Discard, nil), sink, nil))
	pipe, err := logship.New(logship.Options{Logs: cfg.Logs, StateDir: cfg.LogStateDir(), Redactor: redact.New(), Sink: sink, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	reg := jobs.NewRegistry()
	a, err := New(Options{Config: cfg, Registry: reg, Host: &host.Env{Exec: execx.System{}, PhpFpmPoolGlob: filepath.Join(dir, "none", "*")},
		Logger: logger, BackoffMin: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond, MinPollGap: 10 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond, Containers: &logship.Collector{Docker: docker.New(eng.Socket)}, Logs: pipe})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	logger.Info("deploy step", "header", "Authorization: Bearer abc.def.ghi")
	eventually(t, "heartbeats", 5*time.Second, func() bool { return c.HeartbeatCount() >= 2 })
	hb := c.HeartbeatsCopy()[1]
	cs, ok := hb["containers"].([]any)
	if !ok || len(cs) != 1 {
		t.Fatalf("containers %v", hb["containers"])
	}
	ct := cs[0].(map[string]any)
	if ct["name"] != "ppanel-web-1a2b3c4d" || ct["app"] != "web" || ct["state"] != "running" || ct["health"] != "none" || ct["restartCount"].(float64) != 1 {
		t.Fatalf("container %v", ct)
	}
	ls, ok := hb["logShipping"].(map[string]any)
	if !ok || ls["bufferCapBytes"].(float64) != 2<<20 {
		t.Fatalf("logShipping %v", hb["logShipping"])
	}
	if _, ok := ls["lastShippedAt"]; !ok {
		t.Fatal("lastShippedAt key must be present (null until first ship)")
	}
	eventually(t, "log batch", 5*time.Second, func() bool { return len(c.LogBatchesCopy()) >= 1 })
	var all strings.Builder
	for _, b := range c.LogBatchesCopy() {
		for _, e := range b["entries"].([]any) {
			m := e.(map[string]any)
			if m["source"] != "agent" {
				t.Fatalf("unexpected source %v", m)
			}
			all.WriteString(m["line"].(string) + "\n")
		}
	}
	if !strings.Contains(all.String(), "deploy step") || strings.Contains(all.String(), "abc.def.ghi") {
		t.Fatalf("agent log shipped/redacted wrongly:\n%s", all.String())
	}
	if !bytes.Contains([]byte(all.String()), []byte("[REDACTED]")) {
		t.Fatal("no redaction marker")
	}
	for _, call := range eng.MutatingCalls() {
		t.Fatalf("telemetry made a mutating docker call: %+v", call)
	}
}

// Without telemetry options the heartbeat omits the P5 keys entirely.
func TestHeartbeatOmitsTelemetryWhenDisabled(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	start(t, c, dir, &calls)
	eventually(t, "heartbeat", 5*time.Second, func() bool { return c.HeartbeatCount() >= 1 })
	hb := c.HeartbeatsCopy()[0]
	for _, k := range []string{"containers", "logShipping"} {
		if _, ok := hb[k]; ok {
			t.Fatalf("%s must be omitted when unknown", k)
		}
	}
}
