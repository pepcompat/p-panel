package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/redact"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// TestLabNginxShipping runs against the REAL nginx of a lab node (P5-T03/T04
// agent evidence). Opt-in, inside the node:
//
//	PPANEL_LAB_HOST=1 ./logship.test -test.run TestLabNginxShipping -test.v
func TestLabNginxShipping(t *testing.T) {
	if os.Getenv("PPANEL_LAB_HOST") != "1" {
		t.Skip("set PPANEL_LAB_HOST=1 to run against a real Linux lab host")
	}
	const access = "/var/log/nginx/access.log"
	// --- phase 1: HTTPS receiver up; curl line is tailed, redacted, shipped
	var mu sync.Mutex
	var got []Entry
	var gzSizes []int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil || r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "gzip", 400)
			return
		}
		var b struct {
			Entries []Entry `json:"entries"`
		}
		if err := json.NewDecoder(zr).Decode(&b); err != nil {
			http.Error(w, "json", 400)
			return
		}
		mu.Lock()
		got = append(got, b.Entries...)
		gzSizes = append(gzSizes, len(raw))
		mu.Unlock()
		fmt.Fprintf(w, `{"success":true,"statusCode":0,"message":"ok","data":{"accepted":%d,"duplicate":false},"meta":{"requestId":"lab"}}`, len(b.Entries))
	}))
	defer srv.Close()
	cl := &transport.Client{BaseURL: srv.URL, HTTP: srv.Client()}
	send := func(ctx context.Context, gz []byte) error { return cl.PostGzip(ctx, "/agent/v1/logs", gz, nil) }
	cfg := config.LogsConfig{Enabled: true, BufferCapBytes: 8 << 20, ShipIntervalMs: 200, MaxBatchEntries: 1000,
		Sources: []config.LogSource{{Source: SourceNginxAccess, Path: access}, {Source: SourceNginxError, Path: "/var/log/nginx/error.log"}}}
	p, err := New(Options{Logs: cfg, StateDir: filepath.Join(t.TempDir(), "logs"), Redactor: redact.New(), PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, send); close(done) }()
	time.Sleep(300 * time.Millisecond)
	out, err := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://127.0.0.1/?api_key=sk_live_abc123456").CombinedOutput()
	t.Logf("curl 'http://127.0.0.1/?api_key=sk_live_abc123456' -> HTTP %s (err=%v)", out, err)
	var hit Entry
	waitFor(t, "redacted access line shipped", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range got {
			if strings.Contains(e.Line, "sk_live") {
				t.Fatalf("SECRET SHIPPED: %q", e.Line)
			}
			if e.Source == SourceNginxAccess && strings.Contains(e.Line, "api_key=[REDACTED]") {
				hit = e
				return true
			}
		}
		return false
	})
	b, _ := json.Marshal(hit)
	t.Logf("shipped entry: %s", b)
	cancel()
	<-done
	segs, _ := filepath.Glob(filepath.Join(p.o.StateDir, "buffer", "*"))
	for _, s := range segs {
		raw, _ := os.ReadFile(s)
		if bytes.Contains(raw, []byte("sk_live")) {
			t.Fatalf("secret on disk in %s", s)
		}
	}

	// --- phase 2: receiver down; buffer stays under a 1 MiB cap, drops counted
	srv.Close()
	const capBytes = 1 << 20
	cfg.BufferCapBytes = capBytes
	state2 := filepath.Join(t.TempDir(), "logs")
	p2, err := New(Options{Logs: cfg, StateDir: state2, Redactor: redact.New(), PollInterval: 100 * time.Millisecond,
		BackoffMin: 100 * time.Millisecond, BackoffMax: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { p2.Run(ctx2, send); close(done2) }()
	time.Sleep(300 * time.Millisecond)
	hc := &http.Client{Timeout: 5 * time.Second}
	pad := strings.Repeat("p", 1500)
	const reqs = 3000
	maxSeen := int64(0)
	for i := 0; i < reqs; i++ {
		resp, err := hc.Get(fmt.Sprintf("http://127.0.0.1/?i=%d&token=tok-%d&pad=%s", i, i, pad))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if i%250 == 0 {
			time.Sleep(150 * time.Millisecond)
			if sz := dirBytes(filepath.Join(state2, "buffer")); sz > maxSeen {
				maxSeen = sz
			}
		}
	}
	time.Sleep(1500 * time.Millisecond)
	st := p2.Status()
	size := dirBytes(filepath.Join(state2, "buffer"))
	if size > maxSeen {
		maxSeen = size
	}
	seg := p2.Buffer().SegmentBytes()
	t.Logf("receiver down: %d requests of ~1.6 KiB lines → buffer on-disk=%d B (max seen %d B), cap=%d, segment=%d, droppedEntries=%d, bufferedBytes=%d, lastShippedAt=%v",
		reqs, size, maxSeen, capBytes, seg, st.DroppedEntries, st.BufferedBytes, st.LastShippedAt)
	cancel2()
	<-done2
	if maxSeen > capBytes+seg {
		t.Fatalf("buffer exceeded cap: %d > %d+%d", maxSeen, capBytes, seg)
	}
	if st.DroppedEntries == 0 {
		t.Fatal("expected dropped entries with the receiver down")
	}
	inflight, err := os.Stat(filepath.Join(state2, "inflight.bin"))
	if err != nil {
		t.Fatalf("in-flight batch not retained: %v", err)
	}
	t.Logf("in-flight batch retained: %d B", inflight.Size())
}

func dirBytes(dir string) int64 {
	var n int64
	des, _ := os.ReadDir(dir)
	for _, de := range des {
		if fi, err := de.Info(); err == nil {
			n += fi.Size()
		}
	}
	return n
}
