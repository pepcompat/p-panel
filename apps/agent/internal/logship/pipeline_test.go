package logship

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

func TestTeeHandler(t *testing.T) {
	var base bytes.Buffer
	sink := NewAgentSink()
	lg := slog.New(NewTee(slog.NewJSONHandler(&base, &slog.HandlerOptions{Level: slog.LevelDebug}), sink, nil)).With("component", "x")
	lg.Debug("debug not shipped")
	lg.Info("hello", "authorization", "Bearer abc")
	lg.Error("bad")
	if strings.Count(base.String(), "\n") != 3 {
		t.Fatalf("base must get every record: %s", base.String())
	}
	if len(sink.ch) != 2 {
		t.Fatalf("sink got %d (≥ info only)", len(sink.ch))
	}
	r := <-sink.ch
	if !strings.Contains(r.line, `"component":"x"`) || !strings.Contains(r.line, `"msg":"hello"`) || !strings.Contains(r.line, `"authorization":"[REDACTED]"`) {
		t.Fatalf("%s", r.line)
	}
	// overflow never blocks and is counted
	for i := 0; i < agentChanEntries+10; i++ {
		lg.Info("flood")
	}
	if sink.dropped.Load() < 10 {
		t.Fatalf("dropped=%d", sink.dropped.Load())
	}
}

// End to end: nginx line + agent log → redaction → buffer → gzip batch → Center.
func TestPipelineEndToEnd(t *testing.T) {
	fc := newFakeCenter(t)
	dir := t.TempDir()
	access := filepath.Join(dir, "access.log")
	appendLines(t, access, "preexisting line (skipped)")
	cfg := testLogsCfg(4<<20, 1000)
	cfg.Sources = []config.LogSource{{Source: SourceNginxAccess, Path: access}, {Source: SourceAgent}}
	sink := NewAgentSink()
	red := redact.New()
	red.Linger = 0
	p, err := New(Options{Logs: cfg, StateDir: filepath.Join(dir, "state"), Sink: sink, Redactor: red, PollInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	lg := slog.New(NewTee(slog.NewJSONHandler(&bytes.Buffer{}, nil), sink, nil))
	release := red.Register("Very-Secret-DB-Pass")
	p.PollOnce() // first open: pre-existing content is skipped (deterministic, before Run)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, fc.send()); close(done) }()
	appendLines(t, access, `127.0.0.1 - - [23/Nov/2026:10:00:00 +0000] "GET /?api_key=sk_live_abc123456 HTTP/1.1" 200 5 "-" "curl/8"`)
	lg.Info("job output", "out", "connecting with Very-Secret-DB-Pass")
	release()
	waitFor(t, "2 entries shipped", 5*time.Second, func() bool {
		n := 0
		for _, b := range fc.all() {
			n += len(b.Entries)
		}
		return n >= 2
	})
	var all []Entry
	for _, b := range fc.all() {
		for _, raw := range b.Entries {
			var e Entry
			json.Unmarshal(raw, &e)
			all = append(all, e)
			// null keys present
			var m map[string]any
			json.Unmarshal(raw, &m)
			for _, k := range []string{"ts", "source", "app", "service", "container", "file", "stream", "level", "line"} {
				if _, ok := m[k]; !ok {
					t.Fatalf("key %s missing in %s", k, raw)
				}
			}
		}
	}
	var sawNginx, sawAgent bool
	for _, e := range all {
		if strings.Contains(e.Line, "sk_live") || strings.Contains(e.Line, "Very-Secret") || strings.Contains(e.Line, "preexisting") {
			t.Fatalf("leaked: %q", e.Line)
		}
		if e.Source == SourceNginxAccess && strings.Contains(e.Line, "api_key=[REDACTED]") {
			sawNginx = true
		}
		if e.Source == SourceAgent && strings.Contains(e.Line, "connecting with [REDACTED]") && e.Level != nil && *e.Level == "info" {
			sawAgent = true
		}
	}
	if !sawNginx || !sawAgent {
		t.Fatalf("nginx=%v agent=%v: %+v", sawNginx, sawAgent, all)
	}
	// the Center records the batch before the shipper sees the response
	waitFor(t, "lastShippedAt", 5*time.Second, func() bool { return p.Status().LastShippedAt != nil })
	st := p.Status()
	if st.LastShippedAt == nil || st.DroppedEntries != 0 {
		t.Fatalf("status %+v", st)
	}
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), `"bufferCapBytes":4194304`) || !strings.Contains(string(b), `"lastShippedAt":"`) {
		t.Fatalf("status json %s", b)
	}
	cancel()
	<-done
	// nothing secret ever hit disk
	segs, _ := filepath.Glob(filepath.Join(dir, "state", "buffer", "*"))
	for _, s := range segs {
		raw, _ := readFile(s)
		if bytes.Contains(raw, []byte("sk_live")) || bytes.Contains(raw, []byte("Very-Secret")) {
			t.Fatalf("secret on disk in %s", s)
		}
	}
	// status JSON with nothing shipped yet has lastShippedAt: null
	p2, _ := New(Options{Logs: cfg, StateDir: t.TempDir()})
	b, _ = json.Marshal(p2.Status())
	if !strings.Contains(string(b), `"lastShippedAt":null`) {
		t.Fatalf("%s", b)
	}
}
