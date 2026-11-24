package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/fakecenter"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/provider"
	"github.com/ppanel/ppanel/apps/agent/internal/sshkeys"
)

func startP9(t *testing.T, c *fakecenter.Center, dir string, prov func(context.Context) *provider.Info, mods ...func(*Options)) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.StateDir = dir
	reg := jobs.NewRegistry()
	calls := &atomic.Int64{}
	reg.Register(&countingHandler{typ: "inventory.collect", calls: calls})
	o := Options{Config: cfg, Registry: reg, Host: &host.Env{Exec: execx.System{}, PhpFpmPoolGlob: filepath.Join(dir, "none", "*")},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), BackoffMin: 20 * time.Millisecond, BackoffMax: 100 * time.Millisecond,
		MinPollGap: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond, ProbeInterval: 100 * time.Millisecond,
		Provider: prov}
	for _, m := range mods {
		m(&o)
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, c: c, dir: dir, calls: calls, cancel: cancel, done: make(chan struct{}), a: a}
	go func() { a.Run(ctx); close(h.done) }()
	t.Cleanup(h.stop)
	return h
}

func lastHeartbeatPath(c *fakecenter.Center) string {
	p := c.HeartbeatPathsCopy()
	if len(p) == 0 {
		return ""
	}
	return p[len(p)-1]
}

// An agent enrolled by an older Center (gatewayUrl only, no connection block)
// keeps working over the public path; connection.json is written 0600.
func TestP9BackwardCompatibleGatewayURLOnly(t *testing.T) {
	c, dir := enrolled(t, nil)
	st, err := os.Stat(filepath.Join(dir, connpath.FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("connection.json %v %v", st, err)
	}
	// pre-P9 state dir: no connection.json at all
	if err := os.Remove(filepath.Join(dir, connpath.FileName)); err != nil {
		t.Fatal(err)
	}
	h := startP9(t, c, dir, nil)
	eventually(t, "heartbeats over public", 5*time.Second, func() bool { return c.HeartbeatCount() >= 3 })
	if lastHeartbeatPath(c) != "public" {
		t.Fatalf("path %q", lastHeartbeatPath(c))
	}
	hb := c.HeartbeatsCopy()
	conn, _ := hb[len(hb)-1]["connection"].(map[string]any)
	if conn == nil || conn["activePath"] != "public" {
		t.Fatalf("connection report %v", hb[len(hb)-1]["connection"])
	}
	if _, has := hb[len(hb)-1]["provider"]; has {
		t.Fatal("provider must be omitted when no provider source is configured")
	}
	if _, has := hb[len(hb)-1]["ssh"]; has {
		t.Fatal("ssh must be omitted when no ssh fact source is configured")
	}
	_ = h
}

// P9-T2 (unit level): private_only. The first dial (policy unknown → public
// first) is refused with 403; the agent switches to private and learns
// private_only. With the private listener down it never dials public, and it
// reconnects over private once restored.
func TestP9PrivateOnlyFailsClosedAndRecovers(t *testing.T) {
	var privURL string
	c, dir := enrolled(t, func(c *fakecenter.Center) {
		privURL = c.AddListener("private")
		c.EnrollEndpoints = []map[string]any{{"path": "public", "url": c.GatewayURL}, {"path": "private", "url": privURL}}
		c.SetPolicy("private_only", []map[string]any{{"path": "public", "url": c.GatewayURL}, {"path": "private", "url": privURL}}, "private")
	})
	h := startP9(t, c, dir, func(context.Context) *provider.Info {
		return &provider.Info{Name: "digitalocean", DropletID: 7, Region: "lab1", Interfaces: provider.Interfaces{Private: []string{"10.110.0.11"}, Public: []string{}}}
	})
	eventually(t, "heartbeat over private", 5*time.Second, func() bool { return lastHeartbeatPath(c) == "private" })
	eventually(t, "policy learned", 5*time.Second, func() bool { return h.a.Conn().Policy() == connpath.PolicyPrivateOnly })
	hb := c.HeartbeatsCopy()
	last := hb[len(hb)-1]
	if p, _ := last["provider"].(map[string]any); p == nil || p["region"] != "lab1" {
		t.Fatalf("provider %v", last["provider"])
	}
	// public is forbidden now (403 seen); with private_only it is never tried again
	pubBefore := c.PathCount("public")
	c.StopListener("private")
	time.Sleep(800 * time.Millisecond) // several heartbeat attempts + probe cycles
	if got := c.PathCount("public"); got != pubBefore {
		t.Fatalf("private_only agent dialled public %d times while private was down", got-pubBefore)
	}
	if _, ok := h.a.Conn().Active(); !ok {
		t.Fatal("active endpoint should stay private (fail closed), not none")
	}
	if ep, _ := h.a.Conn().Active(); ep.Path != connpath.PathPrivate {
		t.Fatalf("active %v", ep)
	}
	n := c.HeartbeatCount()
	c.StartListener("private")
	eventually(t, "reconnect over private", 5*time.Second, func() bool { return c.HeartbeatCount() > n+1 && lastHeartbeatPath(c) == "private" })
	if got := c.PathCount("public"); got != pubBefore {
		t.Fatalf("public dialled after restore: %d", got-pubBefore)
	}
	// connection.json carries the policy and the forbidden public path
	m, err := connpath.Load(connpath.Options{StateDir: dir, FallbackURL: c.GatewayURL})
	if err != nil || m.Policy() != connpath.PolicyPrivateOnly || len(m.Forbidden()) != 1 || m.Forbidden()[0] != "public" {
		t.Fatalf("persisted %v %v %v", err, m.Policy(), m.Forbidden())
	}
}

// private_preferred: private down → public; private back → fail-back to private.
func TestP9PrivatePreferredFailoverAndFailback(t *testing.T) {
	var privURL string
	c, dir := enrolled(t, func(c *fakecenter.Center) {
		privURL = c.AddListener("private")
		eps := []map[string]any{{"path": "public", "url": c.GatewayURL}, {"path": "private", "url": privURL}}
		c.EnrollEndpoints = eps
		c.SetPolicy("private_preferred", eps, "private", "public")
	})
	h := startP9(t, c, dir, nil)
	eventually(t, "on private", 5*time.Second, func() bool { return lastHeartbeatPath(c) == "private" })
	c.StopListener("private")
	eventually(t, "failover to public", 5*time.Second, func() bool { return lastHeartbeatPath(c) == "public" })
	c.StartListener("private")
	eventually(t, "fail-back to private", 5*time.Second, func() bool { return lastHeartbeatPath(c) == "private" })
	rep := h.a.Conn().Report()
	if rep.ActivePath == nil || *rep.ActivePath != "private" || len(rep.Endpoints) != 2 {
		t.Fatalf("report %+v", rep)
	}
	for _, e := range rep.Endpoints {
		if !e.OK || e.LatencyMs == nil {
			t.Fatalf("probe %+v", e)
		}
	}
}

// P10: the heartbeat carries the ssh fact (host key fingerprints + port), read
// at every heartbeat; a host without host keys reports ssh: null.
func TestP10HeartbeatSSHFacts(t *testing.T) {
	c, dir := enrolled(t, nil)
	var fp atomic.Value
	fp.Store("SHA256:R4iRQRZj8Jlz6b8IoSGQneNlAqkeMxvZNuxVwjVcHZg")
	var none atomic.Bool
	startP9(t, c, dir, nil, func(o *Options) {
		o.SSHFacts = func() *sshkeys.Facts {
			if none.Load() {
				return nil
			}
			port := 22
			return &sshkeys.Facts{HostKeys: []sshkeys.HostKey{{Algorithm: "ssh-ed25519", FingerprintSha256: fp.Load().(string)}}, Port: &port}
		}
	})
	eventually(t, "heartbeats", 5*time.Second, func() bool { return c.HeartbeatCount() >= 2 })
	hb := c.HeartbeatsCopy()
	ssh, _ := hb[len(hb)-1]["ssh"].(map[string]any)
	keys, _ := ssh["hostKeys"].([]any)
	if ssh == nil || ssh["port"] != float64(22) || len(keys) != 1 {
		t.Fatalf("ssh fact %v", hb[len(hb)-1]["ssh"])
	}
	// a rekeyed host is reported at the next heartbeat
	fp.Store("SHA256:w3V8zTBQtDRcwMp1crD2386l74CC46ED83/VA1mrfYw")
	eventually(t, "new fingerprint", 5*time.Second, func() bool {
		hb := c.HeartbeatsCopy()
		s, _ := hb[len(hb)-1]["ssh"].(map[string]any)
		k, _ := s["hostKeys"].([]any)
		if len(k) != 1 {
			return false
		}
		return k[0].(map[string]any)["fingerprintSha256"] == "SHA256:w3V8zTBQtDRcwMp1crD2386l74CC46ED83/VA1mrfYw"
	})
	none.Store(true)
	eventually(t, "ssh null", 5*time.Second, func() bool {
		hb := c.HeartbeatsCopy()
		v, has := hb[len(hb)-1]["ssh"]
		return has && v == nil
	})
}
