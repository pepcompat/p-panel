package agent

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// TestGrantBoundariesRejectedBeforeAck: every malformed / out-of-authority
// grant is answered with a failed result, never acked, and the handler is
// never invoked (counted invocations = 0).
func TestGrantBoundariesRejectedBeforeAck(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	start(t, c, dir, &calls)

	giant := make([]any, jobs.MaxParamsNodes+10)
	for i := range giant {
		giant[i] = 1
	}
	deep := any(map[string]any{})
	for i := 0; i < jobs.MaxParamsDepth+5; i++ {
		deep = map[string]any{"a": deep}
	}
	type tc struct {
		id   string
		g    map[string]any
		code string
	}
	mk := func(id, typ string, params any, exp time.Duration) map[string]any {
		return c.Grant(id, typ, params, exp)
	}
	cases := []tc{
		{"b-wrongsrv", func() map[string]any {
			g := mk("b-wrongsrv", "service.restart", map[string]any{}, time.Minute)
			g["serverId"] = "0190f4c2-0000-7000-8000-0000000000bb"
			return g
		}(), jobs.RejectedWrongServer},
		{"b-srvcase", func() map[string]any {
			g := mk("b-srvcase", "service.restart", map[string]any{}, time.Minute)
			g["serverId"] = strings.ToUpper(serverID)
			return g
		}(), jobs.RejectedWrongServer},
		{"b-nosrv", func() map[string]any {
			g := mk("b-nosrv", "service.restart", map[string]any{}, time.Minute)
			delete(g, "serverId")
			return g
		}(), jobs.RejectedWrongServer},
		{"b-expired", mk("b-expired", "service.restart", map[string]any{}, -time.Hour), jobs.RejectedExpired},
		{"b-nolease", func() map[string]any {
			g := mk("b-nolease", "service.restart", map[string]any{}, time.Minute)
			g["leaseToken"] = ""
			return g
		}(), jobs.RejectedInvalidGrant},
		{"b-noexp", func() map[string]any {
			g := mk("b-noexp", "service.restart", map[string]any{}, time.Minute)
			delete(g, "expiresAt")
			return g
		}(), jobs.RejectedInvalidGrant},
		{"b-leasectl", func() map[string]any {
			g := mk("b-leasectl", "service.restart", map[string]any{}, time.Minute)
			g["leaseToken"] = "a\nb"
			return g
		}(), jobs.RejectedInvalidGrant},
		{"b-unknown", mk("b-unknown", "shell.exec", map[string]any{"cmd": "id"}, time.Minute), jobs.RejectedUnknownType},
		{"b-typecase", mk("b-typecase", "Service.Restart", map[string]any{}, time.Minute), jobs.RejectedUnknownType},
		{"b-typespace", mk("b-typespace", "service.restart ", map[string]any{}, time.Minute), jobs.RejectedUnknownType},
		{"b-unknownfield", mk("b-unknownfield", "service.restart", map[string]any{"unit": "x.service"}, time.Minute), jobs.RejectedInvalidParams},
		{"b-nestedunknown", mk("b-nestedunknown", "service.restart", map[string]any{"__proto__": map[string]any{"x": 1}}, time.Minute), jobs.RejectedInvalidParams},
		{"b-nul", mk("b-nul", "service.restart", map[string]any{"a\x00": "b\x00"}, time.Minute), jobs.RejectedInvalidParams},
		{"b-array", mk("b-array", "service.restart", []any{}, time.Minute), jobs.RejectedInvalidParams},
		{"b-string", mk("b-string", "service.restart", "{}", time.Minute), jobs.RejectedInvalidParams},
		{"b-giantarray", mk("b-giantarray", "service.restart", map[string]any{"x": giant}, time.Minute), jobs.RejectedInvalidParams},
		{"b-deep", mk("b-deep", "service.restart", deep, time.Minute), jobs.RejectedInvalidParams},
		{"b-oversized", mk("b-oversized", "service.restart", map[string]any{"x": strings.Repeat("A", jobs.MaxParamsBytes)}, time.Minute), jobs.RejectedInvalidParams},
	}
	for _, x := range cases {
		c.Enqueue(x.g)
	}
	for _, x := range cases {
		r := waitResult(t, c, x.id, 1)
		if r[0]["status"] != "failed" || errCode(r[0]) != x.code {
			t.Errorf("%s: got %v, want %s", x.id, r[0]["error"], x.code)
		}
	}
	// a grant whose jobId would be a path is refused as malformed (the result
	// cannot even be addressed reliably, so it must at least never execute)
	c.Enqueue(mk("../../etc/passwd", "service.restart", map[string]any{}, time.Minute))
	time.Sleep(300 * time.Millisecond)
	if calls.Load() != 0 || c.AckCount() != 0 {
		t.Fatalf("handler calls=%d acks=%d, want 0/0", calls.Load(), c.AckCount())
	}
}

// TestReplayedJobIDAfterRestartDifferentType: the same jobId re-delivered
// after an agent restart with a DIFFERENT type/params is answered from the
// completed-job cache and never executed again.
func TestReplayedJobIDAfterRestartDifferentType(t *testing.T) {
	c, dir := enrolled(t, nil)
	var calls atomic.Int64
	h := start(t, c, dir, &calls)
	c.Enqueue(c.Grant("job-replay", "inventory.collect", map[string]any{}, time.Minute))
	waitResult(t, c, "job-replay", 1)
	h.stop()
	start(t, c, dir, &calls)
	g := c.Grant("job-replay", "service.restart", map[string]any{}, time.Minute)
	g["leaseToken"] = "lease-other"
	c.Enqueue(g)
	waitResult(t, c, "job-replay", 2)
	if calls.Load() != 1 || c.AckCount() != 1 {
		t.Fatalf("calls=%d acks=%d, want 1/1", calls.Load(), c.AckCount())
	}
}
