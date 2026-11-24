package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
)

// FuzzGrantValidate: an arbitrary TaskGrant JSON goes through the real
// allowlist registry (every production handler) exactly as the agent does
// before ack. Properties: never panics; a grant for another server, an
// expired grant or an unknown type is always rejected; an accepted grant's
// type is allowlisted and its params passed the typed decoder.
func FuzzGrantValidate(f *testing.F) {
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Host: &host.Env{Exec: execx.System{}}, Sampler: &metrics.Sampler{},
		OwnedUnits: func() (map[string]bool, error) { return map[string]bool{"app.service": true}, nil }})
	types := map[string]bool{}
	for _, t := range reg.Types() {
		types[t] = true
	}
	const srv = "0190f4c2-0000-7000-8000-0000000000aa"
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, s := range []string{
		`{"jobId":"j1","type":"service.restart","params":{"unit":"app.service"},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"` + srv + `"}`,
		`{"jobId":"j2","type":"service.restart","params":{"unit":"--help.service"},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"` + srv + `"}`,
		`{"jobId":"j3","type":"discovery.scan","params":{"sources":["nginx","nginx"]},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"` + srv + `"}`,
		`{"jobId":"j4","type":"inventory.collect","params":{},"leaseToken":"l","expiresAt":"2000-01-01T00:00:00Z","serverId":"` + srv + `"}`,
		`{"jobId":"j5","type":"shell.exec","params":{"cmd":"id"},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"` + srv + `"}`,
		`{"jobId":"j6","type":"container.run_candidate","params":{},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"other"}`,
		`{"jobId":"j7","type":"nginx.apply","params":{"revisionId":"x"},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"` + srv + `"}`,
		`{"jobId":"j8","type":"backup.run","params":{"a":"\u0000"},"leaseToken":"l","expiresAt":"` + exp + `","serverId":"` + srv + `"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var g jobs.Grant
		if json.Unmarshal(raw, &g) != nil {
			return
		}
		now := time.Now()
		h, _, rej := reg.Validate(&g, srv, now)
		if rej != nil {
			if rej.Code == "" {
				t.Fatal("rejection without code")
			}
			return
		}
		if g.ServerID != srv {
			t.Fatalf("grant for server %q accepted", g.ServerID)
		}
		if g.ExpiresAt.Add(jobs.ClockSkew).Before(now) {
			t.Fatal("expired grant accepted")
		}
		if !types[g.Type] || h == nil || h.Type() != g.Type {
			t.Fatalf("type %q accepted", g.Type)
		}
		if g.Type == "service.restart" {
			var p struct{ Unit string }
			_ = json.Unmarshal(g.Params, &p)
			if p.Unit != "app.service" {
				t.Fatalf("restart of non-owned unit %q accepted", p.Unit)
			}
		}
	})
}
