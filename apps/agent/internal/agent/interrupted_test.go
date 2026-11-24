package agent

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/fakecenter"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/state"
)

func markStarted(t *testing.T, dir, jobID, lease string) {
	t.Helper()
	cache, err := jobs.OpenCache(filepath.Join(dir, state.JobCacheFile), 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cache.MarkStarted(jobID, lease); !ok || err != nil {
		t.Fatal(ok, err)
	}
}

// F-5: a job the previous agent process was running when it died is reported
// as failed/AGENT_INTERRUPTED at start (with the persisted lease token),
// without waiting for a re-delivery that never comes for mutating jobs.
func TestInterruptedJobReportedAtStart(t *testing.T) {
	c, dir := enrolled(t, nil)
	markStarted(t, dir, "job-killed", "lease-job-killed")
	var calls atomic.Int64
	start(t, c, dir, &calls)
	r := waitResult(t, c, "job-killed", 1)
	if r[0]["status"] != "failed" || errCode(r[0]) != jobs.AgentInterrupted || r[0]["leaseToken"] != "lease-job-killed" {
		t.Fatalf("result %v", r[0])
	}
	// the cache now holds the final result: lease token dropped, re-delivery replays
	cache, err := jobs.OpenCache(filepath.Join(dir, state.JobCacheFile), 0)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := cache.Lookup("job-killed")
	if !ok || e.State != "completed" || e.LeaseToken != "" || len(cache.Interrupted()) != 0 {
		t.Fatalf("cache entry %+v", e)
	}
	c.Enqueue(c.Grant("job-killed", "service.restart", map[string]any{}, time.Minute))
	r = waitResult(t, c, "job-killed", 2)
	if errCode(r[1]) != jobs.AgentInterrupted || calls.Load() != 0 {
		t.Fatalf("replay %v calls=%d", r[1], calls.Load())
	}
}

// The lease may already be gone (409 TASK_EXPIRED): the result is dropped,
// not retried forever.
func TestInterruptedJobRejectedByCenterIsDropped(t *testing.T) {
	c, dir := enrolled(t, func(c *fakecenter.Center) { c.ResultStatus = 409 })
	markStarted(t, dir, "job-late", "lease-job-late")
	var calls atomic.Int64
	h := start(t, c, dir, &calls)
	waitResult(t, c, "job-late", 1)
	eventually(t, "outbox drained", 5*time.Second, func() bool { return h.a.Stats().OutboxLen == 0 })
	time.Sleep(100 * time.Millisecond)
	if n := len(c.ResultsFor("job-late")); n != 1 {
		t.Fatalf("posted %d times", n)
	}
}

// F-9: after the ack, a failure to persist the job start (disk full, ...)
// is answered immediately with AGENT_STATE_WRITE_FAILED; the job is not run.
func TestMarkStartedFailureReportsFailure(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	start(t, c, dir, &calls)
	// make the cache file un-replaceable (rename over a non-empty directory fails, even as root)
	cachePath := filepath.Join(dir, state.JobCacheFile)
	_ = os.Remove(cachePath)
	if err := os.MkdirAll(filepath.Join(cachePath, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	c.Enqueue(c.Grant("job-nospace", "service.restart", map[string]any{}, time.Minute))
	r := waitResult(t, c, "job-nospace", 1)
	if r[0]["status"] != "failed" || errCode(r[0]) != jobs.AgentStateWriteFailed || r[0]["leaseToken"] != "lease-job-nospace" {
		t.Fatalf("result %v", r[0])
	}
	msg, _ := r[0]["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "not executed") || calls.Load() != 0 || c.AckCount() != 1 {
		t.Fatalf("msg=%q calls=%d acks=%d", msg, calls.Load(), c.AckCount())
	}
}
