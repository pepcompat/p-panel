package handlers

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
)

// TestLabRealHostDiscovery runs the real read-only probes (nginx -T, php-fpm
// pools, /proc ports, inventory) on a Linux lab host. Opt-in:
//
//	PPANEL_LAB_HOST=1 go test ./internal/handlers -run TestLabRealHostDiscovery -v
func TestLabRealHostDiscovery(t *testing.T) {
	if os.Getenv("PPANEL_LAB_HOST") != "1" {
		t.Skip("set PPANEL_LAB_HOST=1 to run against a real Linux lab host")
	}
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Host: &host.Env{Exec: execx.System{}, PhpFpmPoolGlob: "/etc/php/*/fpm/pool.d/*.conf"},
		Sampler: &metrics.Sampler{}, OwnedUnits: func() (map[string]bool, error) { return map[string]bool{}, nil }})
	for _, g := range []*jobs.Grant{
		grant("discovery.scan", map[string]any{"sources": []string{"nginx", "php-fpm", "ports", "systemd", "docker"}}),
		grant("inventory.collect", map[string]any{}),
	} {
		h, p, rej := reg.Validate(g, "s", time.Now())
		if rej != nil {
			t.Fatal(rej)
		}
		out, err := h.Run(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(out, "", " ")
		if os.Getenv("PPANEL_LAB_OUT") != "" {
			os.WriteFile(os.Getenv("PPANEL_LAB_OUT")+"/"+g.Type+".json", b, 0o644)
		}
		t.Logf("%s: %d bytes of output", g.Type, len(b))
	}
}
