package jobs

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

type nopH struct{}

func (nopH) Type() string           { return "inventory.collect" }
func (nopH) Mutating() bool         { return false }
func (nopH) Timeout() time.Duration { return time.Second }
func (nopH) Decode(raw json.RawMessage) (any, error) {
	var p struct{}
	return p, DecodeStrict(raw, &p)
}
func (nopH) Run(context.Context, any) (any, error) { return nil, nil }

func TestValidate(t *testing.T) {
	r := NewRegistry()
	r.Register(nopH{})
	now := time.Now()
	base := func() *Grant {
		return &Grant{JobID: "j", Type: "inventory.collect", LeaseToken: "l", ServerID: "s", ExpiresAt: now.Add(time.Minute), Params: json.RawMessage(`{}`)}
	}
	cases := []struct {
		mut  func(g *Grant)
		code string
	}{
		{func(g *Grant) {}, ""},
		{func(g *Grant) { g.Params = nil }, ""},
		{func(g *Grant) { g.ExpiresAt = now.Add(-31 * time.Second) }, RejectedExpired},
		{func(g *Grant) { g.ExpiresAt = now.Add(-29 * time.Second) }, ""},
		{func(g *Grant) { g.ServerID = "x" }, RejectedWrongServer},
		{func(g *Grant) { g.Type = "exec" }, RejectedUnknownType},
		{func(g *Grant) { g.Params = json.RawMessage(`{"a":1}`) }, RejectedInvalidParams},
		{func(g *Grant) { g.Params = json.RawMessage(`{} {}`) }, RejectedInvalidParams},
		{func(g *Grant) { g.Params = json.RawMessage(`"x"`) }, RejectedInvalidParams},
		{func(g *Grant) { g.LeaseToken = "" }, RejectedInvalidGrant},
	}
	for i, c := range cases {
		g := base()
		c.mut(g)
		_, _, rej := r.Validate(g, "s", now)
		got := ""
		if rej != nil {
			got = rej.Code
		}
		if got != c.code {
			t.Errorf("case %d: got %q want %q", i, got, c.code)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("duplicate register must panic")
		}
	}()
	r.Register(nopH{})
}

func TestCacheReplay(t *testing.T) {
	c, err := OpenCache(filepath.Join(t.TempDir(), "c.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.MarkStarted("a", "lease-a"); !ok {
		t.Fatal("first MarkStarted must be fresh")
	}
	if ok, _ := c.MarkStarted("a", "lease-a"); ok {
		t.Fatal("second MarkStarted must not be fresh")
	}
	e, _ := c.Lookup("a")
	if r := e.ReplayResult("a", "l2"); r.Error.Code != AgentInterrupted || r.LeaseToken != "l2" {
		t.Fatalf("%+v", r)
	}
	c.Complete(&Result{JobID: "a", Status: "succeeded", Output: map[string]int{"n": 1}})
	e, _ = c.Lookup("a")
	if r := e.ReplayResult("a", "l3"); r.Status != "succeeded" || r.Error != nil {
		t.Fatalf("%+v", r)
	}
}

func TestCacheInterruptedKeepsLeaseUntilComplete(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	c, _ := OpenCache(p, 0)
	c.MarkStarted("a", "lease-a")
	c.MarkStarted("b", "lease-b")
	c.Complete(&Result{JobID: "a", Status: "succeeded"})
	c2, err := OpenCache(p, 0) // restart
	if err != nil {
		t.Fatal(err)
	}
	in := c2.Interrupted()
	if len(in) != 1 || in[0].JobID != "b" || in[0].LeaseToken != "lease-b" {
		t.Fatalf("%+v", in)
	}
	if e, _ := c2.Lookup("a"); e.LeaseToken != "" {
		t.Fatal("lease token must be dropped on completion")
	}
}
