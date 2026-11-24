package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
	"github.com/ppanel/ppanel/apps/agent/internal/netdiag"
)

// NetworkDeps are the P9 network job dependencies (wired once the agent's
// connection manager exists).
type NetworkDeps struct {
	// Endpoints returns the advertised Center endpoints.
	Endpoints func() []connpath.Endpoint
	// ProbeCenter probes the advertised endpoints (heartbeat probe semantics).
	ProbeCenter func(ctx context.Context) []connpath.ProbeResult
	// Diagnoser / Prober override the system implementations (tests).
	Diagnoser *netdiag.Diagnoser
	Prober    *netdiag.Prober
	// LookupHost resolves endpoint host names (default net.DefaultResolver, 2 s).
	LookupHost func(ctx context.Context, host string) ([]netip.Addr, error)
}

// centerAddrs resolves the advertised endpoints to address:port pairs.
func (n *NetworkDeps) centerAddrs() []netip.AddrPort {
	if n == nil || n.Endpoints == nil {
		return nil
	}
	var out []netip.AddrPort
	for _, e := range n.Endpoints() {
		u, err := url.Parse(e.URL)
		if err != nil {
			continue
		}
		port := 443
		if ps := u.Port(); ps != "" {
			if v, err := strconv.Atoi(ps); err == nil {
				port = v
			}
		}
		host := u.Hostname()
		if a, err := netip.ParseAddr(host); err == nil {
			out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(port)))
			continue
		}
		lookup := n.LookupHost
		if lookup == nil {
			lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addrs, err := lookup(ctx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(port)))
		}
	}
	return out
}

// ---------------- network.diagnose ----------------

// NetworkDiagnose implements network.diagnose (read-only).
type NetworkDiagnose struct{ d *Deps }

func (*NetworkDiagnose) Type() string           { return "network.diagnose" }
func (*NetworkDiagnose) Mutating() bool         { return false }
func (*NetworkDiagnose) Timeout() time.Duration { return 60 * time.Second }
func (h *NetworkDiagnose) Decode(raw json.RawMessage) (any, error) {
	return netdiag.DecodeDiagnose(raw, h.d.Network.centerAddrs)
}

func (h *NetworkDiagnose) Run(ctx context.Context, params any) (any, error) {
	p := params.(netdiag.DiagnoseParams)
	d := &netdiag.Diagnoser{}
	if h.d.Network != nil && h.d.Network.Diagnoser != nil {
		cp := *h.d.Network.Diagnoser
		d = &cp
	}
	if d.ProbeCenter == nil && h.d.Network != nil {
		d.ProbeCenter = h.d.Network.ProbeCenter
	}
	return d.Run(ctx, p)
}

// ---------------- http.probe ----------------

// HTTPProbe implements http.probe (read-only).
type HTTPProbe struct{ d *Deps }

func (*HTTPProbe) Type() string           { return "http.probe" }
func (*HTTPProbe) Mutating() bool         { return false }
func (*HTTPProbe) Timeout() time.Duration { return 20 * time.Second }
func (*HTTPProbe) Decode(raw json.RawMessage) (any, error) {
	return netdiag.DecodeProbe(raw)
}

func (h *HTTPProbe) Run(ctx context.Context, params any) (any, error) {
	p := params.(netdiag.ProbeParams)
	pr := &netdiag.Prober{}
	if h.d.Network != nil && h.d.Network.Prober != nil {
		pr = h.d.Network.Prober
	}
	return pr.Run(ctx, p), nil
}
