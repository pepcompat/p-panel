package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/enroll"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/fakecenter"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/state"
)

const serverID = "0190f4c2-0000-7000-8000-0000000000aa"
const token = "ppe_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// countingHandler records invocations; it stands in for real handlers.
type countingHandler struct {
	typ   string
	mut   bool
	calls *atomic.Int64
}

func (h *countingHandler) Type() string           { return h.typ }
func (h *countingHandler) Mutating() bool         { return h.mut }
func (h *countingHandler) Timeout() time.Duration { return 5 * time.Second }
func (h *countingHandler) Decode(raw json.RawMessage) (any, error) {
	var p struct{}
	return p, jobs.DecodeStrict(raw, &p)
}
func (h *countingHandler) Run(context.Context, any) (any, error) {
	h.calls.Add(1)
	return map[string]any{"ok": true}, nil
}

type harness struct {
	t      *testing.T
	c      *fakecenter.Center
	dir    string
	calls  *atomic.Int64
	cancel context.CancelFunc
	done   chan struct{}
	a      *Agent
}

func enrolled(t *testing.T, mutate func(c *fakecenter.Center)) (*fakecenter.Center, string) {
	t.Helper()
	c := fakecenter.New(t, serverID)
	if mutate != nil {
		mutate(c)
	}
	c.AddToken(token)
	url := c.StartEnrollHTTP()
	t.Setenv(enroll.InsecureEnv, "1")
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := enroll.Run(context.Background(), enroll.Options{CenterURL: url, Token: token, StateDir: dir}); err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func newAgent(t *testing.T, dir string, calls *atomic.Int64) (*Agent, error) {
	cfg := config.Default()
	cfg.StateDir = dir
	cfg.MaxBufferedResults = 10
	reg := jobs.NewRegistry()
	reg.Register(&countingHandler{typ: "inventory.collect", calls: calls})
	reg.Register(&countingHandler{typ: "service.restart", mut: true, calls: calls})
	return New(Options{Config: cfg, Registry: reg, Host: &host.Env{Exec: execx.System{}, PhpFpmPoolGlob: filepath.Join(dir, "none", "*")},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), BackoffMin: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond,
		MinPollGap: 10 * time.Millisecond, HeartbeatInterval: 50 * time.Millisecond})
}

func start(t *testing.T, c *fakecenter.Center, dir string, calls *atomic.Int64) *harness {
	t.Helper()
	a, err := newAgent(t, dir, calls)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, c: c, dir: dir, calls: calls, cancel: cancel, done: make(chan struct{}), a: a}
	go func() { a.Run(ctx); close(h.done) }()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Error("agent did not stop")
	}
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func waitResult(t *testing.T, c *fakecenter.Center, jobID string, n int) []map[string]any {
	t.Helper()
	eventually(t, "result for "+jobID, 5*time.Second, func() bool { return len(c.ResultsFor(jobID)) >= n })
	return c.ResultsFor(jobID)
}

func errCode(r map[string]any) string {
	e, _ := r["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func TestHeartbeatOverMTLS(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	start(t, c, dir, &calls)
	eventually(t, "2 heartbeats", 5*time.Second, func() bool { return c.HeartbeatCount() >= 2 })
	cn, _ := c.LastPeer()
	if cn != "agent:"+serverID {
		t.Fatalf("center saw client cert CN %q", cn)
	}
	hbs := c.HeartbeatsCopy()
	c2 := hbs[0]
	for _, k := range []string{"seq", "sentAt", "agentVersion", "metrics", "addresses", "capabilities", "runningJobIds"} {
		if _, ok := c2[k]; !ok {
			t.Errorf("heartbeat missing %q: %v", k, c2)
		}
	}
	if hbs[1]["seq"].(float64) <= c2["seq"].(float64) {
		t.Error("seq must increase")
	}
}

func TestRejectsGatewayNotSignedByPinnedCA(t *testing.T) {
	c, dir := enrolled(t, nil)
	other := fakecenter.NewCA(t, "Evil CA")
	// pin a different CA: the real gateway cert must now be rejected
	if err := os.WriteFile(filepath.Join(dir, state.CAFile), other.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	h := start(t, c, dir, &calls)
	eventually(t, "failed heartbeats", 5*time.Second, func() bool { return h.a.Stats().HeartbeatsFailed >= 2 })
	if n := c.HeartbeatCount(); n != 0 {
		t.Fatalf("center received %d heartbeats from agent that should have refused the gateway", n)
	}
}

func TestExpiredGrantRefusedNotExecuted(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	start(t, c, dir, &calls)
	c.Enqueue(c.Grant("job-expired", "inventory.collect", map[string]any{}, -2*time.Minute))
	r := waitResult(t, c, "job-expired", 1)
	if r[0]["status"] != "failed" || errCode(r[0]) != jobs.RejectedExpired || r[0]["leaseToken"] != "lease-job-expired" {
		t.Fatalf("result %v", r[0])
	}
	// within 30s skew tolerance -> executes
	c.Enqueue(c.Grant("job-skew", "inventory.collect", map[string]any{}, -10*time.Second))
	r = waitResult(t, c, "job-skew", 1)
	if r[0]["status"] != "succeeded" {
		t.Fatalf("skew-tolerant grant: %v", r[0])
	}
	if calls.Load() != 1 || c.AckCount() != 1 {
		t.Fatalf("calls=%d acks=%d (expired grant must not be acked or executed)", calls.Load(), c.AckCount())
	}
}

func TestUnknownTypeWrongServerInvalidParams(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	start(t, c, dir, &calls)
	g1 := c.Grant("job-unknown", "shell.exec", map[string]any{"cmd": "id"}, time.Minute)
	g2 := c.Grant("job-wrongsrv", "inventory.collect", map[string]any{}, time.Minute)
	g2["serverId"] = "someone-else"
	g3 := c.Grant("job-badparams", "inventory.collect", map[string]any{"extra": 1}, time.Minute)
	g4 := c.Grant("job-nonobject", "inventory.collect", []any{1}, time.Minute)
	c.Enqueue(g1, g2, g3, g4)
	want := map[string]string{"job-unknown": jobs.RejectedUnknownType, "job-wrongsrv": jobs.RejectedWrongServer,
		"job-badparams": jobs.RejectedInvalidParams, "job-nonobject": jobs.RejectedInvalidParams}
	for id, code := range want {
		r := waitResult(t, c, id, 1)
		if r[0]["status"] != "failed" || errCode(r[0]) != code {
			t.Errorf("%s: got %v want %s", id, r[0], code)
		}
	}
	if calls.Load() != 0 || c.AckCount() != 0 {
		t.Fatalf("calls=%d acks=%d", calls.Load(), c.AckCount())
	}
}

func TestDuplicateJobNotReexecutedAcrossRestart(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	h := start(t, c, dir, &calls)
	g := c.Grant("job-dup", "service.restart", map[string]any{}, time.Minute)
	c.Enqueue(g)
	waitResult(t, c, "job-dup", 1)
	c.Enqueue(g) // redelivery while running
	r := waitResult(t, c, "job-dup", 2)
	if r[1]["status"] != "succeeded" {
		t.Fatalf("replayed result %v", r[1])
	}
	h.stop()

	// restart: a fresh agent process on the same state dir
	start(t, c, dir, &calls)
	c.Enqueue(g)
	r = waitResult(t, c, "job-dup", 3)
	if r[2]["status"] != "succeeded" {
		t.Fatalf("replay after restart %v", r[2])
	}
	if calls.Load() != 1 {
		t.Fatalf("handler invoked %d times, want exactly 1", calls.Load())
	}
	if c.AckCount() != 1 {
		t.Fatalf("acks=%d want 1", c.AckCount())
	}
}

func TestStartedButUncompletedJobNeverReexecuted(t *testing.T) {
	c, dir := enrolled(t, nil)
	// simulate a crash after MarkStarted but before completion
	cache, err := jobs.OpenCache(filepath.Join(dir, state.JobCacheFile), 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cache.MarkStarted("job-crash"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	var calls atomic.Int64
	start(t, c, dir, &calls)
	c.Enqueue(c.Grant("job-crash", "service.restart", map[string]any{}, time.Minute))
	r := waitResult(t, c, "job-crash", 1)
	if r[0]["status"] != "failed" || errCode(r[0]) != jobs.AgentInterrupted || calls.Load() != 0 {
		t.Fatalf("result %v calls=%d", r[0], calls.Load())
	}
}

func TestAckConflictNotExecuted(t *testing.T) {
	c, dir := enrolled(t, func(c *fakecenter.Center) { c.AckStatus = 409 })
	var calls atomic.Int64
	start(t, c, dir, &calls)
	c.Enqueue(c.Grant("job-409", "inventory.collect", map[string]any{}, time.Minute))
	eventually(t, "ack attempt", 5*time.Second, func() bool { return c.AckCount() == 1 })
	time.Sleep(200 * time.Millisecond)
	if calls.Load() != 0 || len(c.ResultsFor("job-409")) != 0 {
		t.Fatalf("job executed despite ack 409 (calls=%d)", calls.Load())
	}
}

func TestReconnectResumesHeartbeatsWithoutHandlers(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	h := start(t, c, dir, &calls)
	eventually(t, "first heartbeat", 5*time.Second, func() bool { return c.HeartbeatCount() >= 1 })
	c.StopGateway()
	failedBefore := h.a.Stats().HeartbeatsFailed
	eventually(t, "heartbeat failures during outage", 5*time.Second, func() bool { return h.a.Stats().HeartbeatsFailed >= failedBefore+3 })
	before := c.HeartbeatCount()
	if calls.Load() != 0 {
		t.Fatalf("handler invoked during outage: %d", calls.Load())
	}
	c.StartGateway()
	eventually(t, "heartbeats resumed", 5*time.Second, func() bool { return c.HeartbeatCount() >= before+2 })
	if calls.Load() != 0 {
		t.Fatalf("handler invoked by reconnect: %d", calls.Load())
	}
	// task polling resumed too
	c.Enqueue(c.Grant("job-after", "inventory.collect", map[string]any{}, time.Minute))
	if r := waitResult(t, c, "job-after", 1); r[0]["status"] != "succeeded" || calls.Load() != 1 {
		t.Fatalf("post-reconnect job %v calls=%d", r[0], calls.Load())
	}
}

func TestCertificateRotationTwoThirdsLifetime(t *testing.T) {
	// issued cert: 30s lifetime, 25s already elapsed -> past 2/3
	c, dir := enrolled(t, func(c *fakecenter.Center) {
		c.LeafValidity = 30 * time.Second
		c.LeafNotBefore = func() time.Time { return time.Now().Add(-25 * time.Second) }
	})
	_, _, oldLeaf, _ := (state.Dir{Path: dir}).LoadTLS()
	var calls atomic.Int64
	start(t, c, dir, &calls)
	eventually(t, "rotation", 5*time.Second, func() bool { return c.RotationCount() == 1 })
	oldSerial := oldLeaf.SerialNumber.Text(16)
	eventually(t, "new cert in use", 5*time.Second, func() bool { _, s := c.LastPeer(); return s != "" && s != oldSerial })
	_, _, newLeaf, err := (state.Dir{Path: dir}).LoadTLS()
	if err != nil || newLeaf.SerialNumber.Text(16) == oldSerial {
		t.Fatalf("rotated cert not persisted: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, state.KeyFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("rotated key mode %o", st.Mode().Perm())
	}
	for _, f := range []string{state.KeyFile + ".new", state.CertFile + ".new"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Fatalf("%s left behind", f)
		}
	}
}

func TestRotationOnCertRenewAfter(t *testing.T) {
	c, dir := enrolled(t, nil)
	past := time.Now().Add(-time.Minute)
	c.RenewAfter = &past
	var calls atomic.Int64
	start(t, c, dir, &calls)
	eventually(t, "rotation via certRenewAfter", 5*time.Second, func() bool { return c.RotationCount() == 1 })
}

func TestRecoverRotation(t *testing.T) {
	d := state.Dir{Path: t.TempDir()}
	os.WriteFile(d.FilePath(state.KeyFile), []byte("old-key"), 0o600)
	os.WriteFile(d.FilePath(state.CertFile), []byte("old-cert"), 0o644)
	// crash after key swap, before cert swap
	os.WriteFile(d.FilePath(state.CertFile+".new"), []byte("new-cert"), 0o644)
	if err := RecoverRotation(d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(d.FilePath(state.CertFile)); string(b) != "new-cert" {
		t.Fatal("cert not completed")
	}
	// orphan key only -> discarded
	os.WriteFile(d.FilePath(state.KeyFile+".new"), []byte("orphan"), 0o600)
	RecoverRotation(d)
	if b, _ := os.ReadFile(d.FilePath(state.KeyFile)); string(b) != "old-key" {
		t.Fatal("orphan key must not replace current key")
	}
}

func TestBackoffBounded(t *testing.T) {
	b := &Backoff{Min: time.Second, Max: 60 * time.Second}
	var last time.Duration
	for i := 0; i < 200; i++ {
		d := b.Next()
		if d < time.Second || d > 60*time.Second {
			t.Fatalf("attempt %d: %s out of [1s,60s]", i, d)
		}
		last = d
	}
	if last < 30*time.Second {
		t.Fatalf("backoff should saturate near max, got %s", last)
	}
	b.Reset()
	if d := b.Next(); d > time.Second {
		t.Fatalf("after reset first delay %s", d)
	}
	// jitter: not all equal at saturation
	seen := map[time.Duration]bool{}
	for i := 0; i < 20; i++ {
		seen[b.Next()] = true
	}
	if len(seen) < 3 {
		t.Fatal("expected jitter")
	}
}

func TestOutboxBounded(t *testing.T) {
	o := NewOutbox(10)
	for i := 0; i < 1000; i++ {
		o.Push(&jobs.Result{JobID: string(rune('a' + i%26))})
	}
	if o.Len() != 10 || o.Dropped() != 990 {
		t.Fatalf("len=%d dropped=%d", o.Len(), o.Dropped())
	}
}

func TestCacheBoundedAndPersisted(t *testing.T) {
	if jobs.DefaultCacheSize != 1000 {
		t.Fatalf("protocol requires 1000 remembered jobIds, got %d", jobs.DefaultCacheSize)
	}
	p := filepath.Join(t.TempDir(), "c.json")
	c, _ := jobs.OpenCache(p, 50)
	for i := 0; i < 60; i++ {
		c.Complete(&jobs.Result{JobID: fmt.Sprintf("j%d", i), Status: "succeeded", Output: map[string]any{"big": strings.Repeat("x", 20000)}})
	}
	c2, err := jobs.OpenCache(p, 50)
	if err != nil || c2.Len() != 50 {
		t.Fatalf("len=%d err=%v", c2.Len(), err)
	}
	if _, ok := c2.Lookup("j0"); ok {
		t.Fatal("oldest entry should be evicted")
	}
	e, ok := c2.Lookup("j59")
	if !ok || e.State != "completed" || !strings.Contains(string(e.Output), `"truncated":true`) {
		t.Fatalf("newest entry missing or output not capped: %v", e)
	}
	// corrupt cache fails closed
	os.WriteFile(p, []byte("{garbage"), 0o600)
	if _, err := jobs.OpenCache(p, 50); err == nil {
		t.Fatal("corrupt cache must fail closed")
	}
}

type ctxHandler struct{ countingHandler }

func (h *ctxHandler) Run(ctx context.Context, _ any) (any, error) {
	return map[string]any{"jobId": jobs.JobID(ctx), "lease": jobs.LeaseToken(ctx)}, nil
}

// container.run_candidate needs jobId + leaseToken for the one-time secrets fetch.
func TestExecuteAttachesJobIDAndLeaseToken(t *testing.T) {
	a := &Agent{}
	g := &jobs.Grant{JobID: "job-9", LeaseToken: "lease-9"}
	r := a.execute(&ctxHandler{countingHandler{typ: "x", calls: &atomic.Int64{}}}, struct{}{}, g, slog.New(slog.NewTextHandler(io.Discard, nil)))
	out := r.Output.(map[string]any)
	if r.Status != "succeeded" || out["jobId"] != "job-9" || out["lease"] != "lease-9" {
		t.Fatalf("%+v", r)
	}
}
