package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

type gotBatch struct {
	BatchID string            `json:"batchId"`
	Seq     uint64            `json:"seq"`
	SentAt  string            `json:"sentAt"`
	Entries []json.RawMessage `json:"entries"`
	Dropped struct {
		Entries uint64  `json:"entries"`
		Since   *string `json:"since"`
	} `json:"dropped"`
	gzLen int
}

// fakeCenter is a /agent/v1/logs receiver; respond decides each status.
type fakeCenter struct {
	mu      sync.Mutex
	batches []gotBatch
	respond func(n int, b gotBatch, w http.ResponseWriter) bool // true = handled (error)
	srv     *httptest.Server
	seen    map[string]bool
}

func newFakeCenter(t *testing.T) *fakeCenter {
	fc := &fakeCenter{seen: map[string]bool{}}
	fc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/logs" || r.Header.Get("Content-Encoding") != "gzip" || r.Method != http.MethodPost {
			http.Error(w, "bad", 400)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			http.Error(w, "gzip", 400)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(zr, 8<<20+1))
		var b gotBatch
		if err := json.Unmarshal(body, &b); err != nil {
			http.Error(w, "json", 400)
			return
		}
		b.gzLen = len(raw)
		fc.mu.Lock()
		n := len(fc.batches)
		fc.batches = append(fc.batches, b)
		respond := fc.respond
		fc.mu.Unlock()
		if respond != nil && respond(n, b, w) {
			return
		}
		fc.mu.Lock()
		dup := fc.seen[b.BatchID]
		fc.seen[b.BatchID] = true
		fc.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"statusCode":0,"message":"ok","data":{"accepted":%d,"duplicate":%v},"meta":{"requestId":"x"}}`, len(b.Entries), dup)
	}))
	t.Cleanup(fc.srv.Close)
	return fc
}

func (fc *fakeCenter) send() SendFunc {
	c := &transport.Client{BaseURL: fc.srv.URL, HTTP: fc.srv.Client()}
	return func(ctx context.Context, gz []byte) error { return c.PostGzip(ctx, "/agent/v1/logs", gz, nil) }
}

func (fc *fakeCenter) all() []gotBatch {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return append([]gotBatch(nil), fc.batches...)
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func newTestShipper(t *testing.T, dir string, maxEntries int, send SendFunc, sleep func(context.Context, time.Duration) bool) (*Buffer, *Shipper) {
	b, err := OpenBuffer(BufferOptions{Dir: filepath.Join(dir, "buffer"), StateFile: filepath.Join(dir, "cursor.json"), CapBytes: 64 << 20, NotifyAt: maxEntries})
	if err != nil {
		t.Fatal(err)
	}
	s := NewShipper(ShipperOptions{Buffer: b, StateDir: dir, Send: send, Interval: 20 * time.Millisecond, MaxEntries: maxEntries,
		BackoffMin: time.Millisecond, BackoffMax: 50 * time.Millisecond, Sleep: sleep})
	return b, s
}

// 429 + Retry-After: the shipper waits exactly Retry-After, keeps the batch
// (no drop) and retries it with the SAME batchId and seq.
func TestShipper429RetryAfterKeepsBatch(t *testing.T) {
	fc := newFakeCenter(t)
	fc.respond = func(n int, b gotBatch, w http.ResponseWriter) bool {
		if n < 2 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":{"code":"RATE_LIMITED","message":"slow down"}}`)
			return true
		}
		return false
	}
	var slept []time.Duration
	var mu sync.Mutex
	sleep := func(ctx context.Context, d time.Duration) bool {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		return ctx.Err() == nil
	}
	d := t.TempDir()
	b, s := newTestShipper(t, d, 1000, fc.send(), sleep)
	for i := 0; i < 10; i++ {
		b.Append(entry(i, 10))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, "accepted", 5*time.Second, func() bool { return s.SentBatches() == 1 })
	cancel()
	got := fc.all()
	if len(got) != 3 {
		t.Fatalf("attempts=%d", len(got))
	}
	for _, g := range got {
		if g.BatchID != got[0].BatchID || g.Seq != got[0].Seq || len(g.Entries) != 10 {
			t.Fatalf("retry changed the batch: %+v vs %+v", g.BatchID, got[0].BatchID)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(slept) != 2 || slept[0] != 7*time.Second || slept[1] != 7*time.Second {
		t.Fatalf("Retry-After not honoured: %v", slept)
	}
	if st := b.Stats(); st.DroppedTotal != 0 || st.Pending != 0 {
		t.Fatalf("429 must never drop: %+v", st)
	}
}

// 5xx/network failures: exponential backoff, same batchId on every retry, and
// a restart resends the persisted in-flight batch unchanged.
func TestShipperRetrySameBatchAcrossRestart(t *testing.T) {
	fc := newFakeCenter(t)
	var healthy atomic.Bool
	fc.respond = func(n int, b gotBatch, w http.ResponseWriter) bool {
		if !healthy.Load() {
			w.WriteHeader(503)
			return true
		}
		return false
	}
	var slept []time.Duration
	var mu sync.Mutex
	sleep := func(ctx context.Context, d time.Duration) bool {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		return ctx.Err() == nil
	}
	d := t.TempDir()
	b, s := newTestShipper(t, d, 1000, fc.send(), sleep)
	for i := 0; i < 5; i++ {
		b.Append(entry(i, 10))
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	waitFor(t, "3 failed attempts", 5*time.Second, func() bool { return len(fc.all()) >= 3 })
	cancel()
	time.Sleep(20 * time.Millisecond)
	id1, seq1, n1, ok := s.InFlight()
	if !ok || n1 != 5 {
		t.Fatalf("in-flight lost: %v %d", ok, n1)
	}
	b.Close()
	// "restart"
	b2, s2 := newTestShipper(t, d, 1000, fc.send(), sleep)
	defer b2.Close()
	id2, seq2, _, ok := s2.InFlight()
	if !ok || id2 != id1 || seq2 != seq1 {
		t.Fatalf("in-flight after restart: %v %s/%d vs %s/%d", ok, id2, seq2, id1, seq1)
	}
	b2.Append(entry(99, 10))
	healthy.Store(true)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go s2.Run(ctx2)
	waitFor(t, "both batches accepted", 5*time.Second, func() bool { return s2.SentBatches() == 2 })
	got := fc.all()
	ids := map[string]int{}
	for _, g := range got {
		ids[g.BatchID]++
	}
	if ids[id1] < 3 {
		t.Fatalf("batch %s retried %d times; all=%v", id1, ids[id1], ids)
	}
	last := got[len(got)-1]
	if last.BatchID == id1 || last.Seq != seq1+1 || len(last.Entries) != 1 {
		t.Fatalf("next batch: %+v", last)
	}
	mu.Lock()
	if len(slept) < 2 || slept[1] <= slept[0] {
		t.Fatalf("no exponential backoff: %v", slept)
	}
	mu.Unlock()
}

// 401/403: stop shipping and wait the max backoff; batch kept.
func TestShipperAuthErrorMaxBackoff(t *testing.T) {
	fc := newFakeCenter(t)
	fc.respond = func(n int, b gotBatch, w http.ResponseWriter) bool {
		if n < 2 {
			w.WriteHeader(403)
			return true
		}
		return false
	}
	var slept []time.Duration
	var mu sync.Mutex
	sleep := func(ctx context.Context, d time.Duration) bool {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		return ctx.Err() == nil
	}
	b, s := newTestShipper(t, t.TempDir(), 1000, fc.send(), sleep)
	b.Append(entry(1, 1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, "accepted", 5*time.Second, func() bool { return s.SentBatches() == 1 })
	mu.Lock()
	defer mu.Unlock()
	if len(slept) != 2 || slept[0] != 50*time.Millisecond || slept[1] != 50*time.Millisecond {
		t.Fatalf("401/403 must back off at max: %v", slept)
	}
}

// Batches respect ≤ 5000 entries and ≤ 1 MiB gzip even with incompressible lines.
func TestShipperBatchLimits(t *testing.T) {
	fc := newFakeCenter(t)
	d := t.TempDir()
	b, s := newTestShipper(t, d, 5000, fc.send(), nil)
	rng := rand.New(rand.NewSource(1))
	const n = 12000
	for i := 0; i < n; i++ {
		var line string
		if i%3 == 0 {
			buf := make([]byte, 600)
			rng.Read(buf)
			line = fmt.Sprintf("%d %x", i, buf) // incompressible
		} else {
			line = fmt.Sprintf("%d %s", i, strings.Repeat("a", 20))
		}
		b.Append(Entry{TS: FormatTS(time.Now()), Source: SourceAgent, Line: line})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	total := 0
	waitFor(t, "all shipped", 20*time.Second, func() bool {
		total = 0
		for _, g := range fc.all() {
			total += len(g.Entries)
		}
		return total == n
	})
	seq := uint64(0)
	for _, g := range fc.all() {
		if len(g.Entries) > MaxBatchEntries || g.gzLen > MaxBatchGzip {
			t.Fatalf("batch too big: %d entries, %d bytes gz", len(g.Entries), g.gzLen)
		}
		if g.Seq <= seq {
			t.Fatalf("seq not increasing: %d after %d", g.Seq, seq)
		}
		seq = g.Seq
		t.Logf("batch seq=%d entries=%d gz=%d", g.Seq, len(g.Entries), g.gzLen)
	}
}

// drops are reported in the next batch's `dropped` and cleared once accepted.
func TestShipperReportsDropped(t *testing.T) {
	fc := newFakeCenter(t)
	b, s := newTestShipper(t, t.TempDir(), 1000, fc.send(), nil)
	b.AddDropped(42)
	b.Append(entry(1, 1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, "sent", 5*time.Second, func() bool { return s.SentBatches() == 1 })
	g := fc.all()[0]
	if g.Dropped.Entries != 42 || g.Dropped.Since == nil {
		t.Fatalf("dropped %+v", g.Dropped)
	}
	if n, since := b.DroppedPending(); n != 0 || since != nil {
		t.Fatalf("pending after ack %d %v", n, since)
	}
	if b.Stats().DroppedTotal != 42 {
		t.Fatal("total must stay cumulative")
	}
}
