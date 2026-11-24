package netdiag

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
)

// Timeouts.
const (
	DNSTimeout = 3 * time.Second
	TCPTimeout = 3 * time.Second
)

// Interface is one network interface.
type Interface struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
}

// DNSResult is one resolve outcome.
type DNSResult struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
}

// TCPResult is one tcp check outcome.
type TCPResult struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	OK        bool   `json:"ok"`
	LatencyMs *int64 `json:"latencyMs"`
	Error     string `json:"error,omitempty"`
}

// DiagnoseResult is the network.diagnose output.
type DiagnoseResult struct {
	Interfaces      []Interface            `json:"interfaces"`
	Routes          []Route                `json:"routes"`
	RoutesError     string                 `json:"routesError,omitempty"`
	DNS             []DNSResult            `json:"dns"`
	TCP             []TCPResult            `json:"tcp"`
	CenterEndpoints []connpath.ProbeResult `json:"centerEndpoints"`
	CheckedAt       string                 `json:"checkedAt"`
}

// Diagnoser runs network.diagnose. Zero values use the real system.
type Diagnoser struct {
	// ProcRoot is where net/route and net/ipv6_route are read (default /proc).
	ProcRoot string
	// Resolver / Dial override DNS and TCP (tests).
	Resolver *net.Resolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	// Interfaces overrides interface listing (tests).
	Interfaces func() ([]Interface, error)
	// ProbeCenter probes the advertised Center endpoints (same as the heartbeat probe).
	ProbeCenter func(ctx context.Context) []connpath.ProbeResult
}

// Run executes a validated diagnose. It only reads: no OS configuration,
// route or address is ever changed.
func (d *Diagnoser) Run(ctx context.Context, p DiagnoseParams) (*DiagnoseResult, error) {
	res := &DiagnoseResult{Routes: []Route{}, DNS: []DNSResult{}, TCP: []TCPResult{}, CenterEndpoints: []connpath.ProbeResult{},
		CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	list := d.Interfaces
	if list == nil {
		list = SystemInterfaces
	}
	ifs, err := list()
	if err != nil {
		ifs = []Interface{}
	}
	res.Interfaces = ifs
	if p.IncludeRoutes {
		res.Routes, res.RoutesError = d.routes()
	}
	var wg sync.WaitGroup
	res.DNS = make([]DNSResult, len(p.Resolve))
	for i, h := range p.Resolve {
		wg.Add(1)
		go func(i int, h string) { defer wg.Done(); res.DNS[i] = d.resolve(ctx, h) }(i, h)
	}
	res.TCP = make([]TCPResult, len(p.TCP))
	for i, t := range p.TCP {
		wg.Add(1)
		go func(i int, t TCPTarget) { defer wg.Done(); res.TCP[i] = d.tcp(ctx, t) }(i, t)
	}
	if d.ProbeCenter != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := d.ProbeCenter(ctx); r != nil {
				res.CenterEndpoints = r
			}
		}()
	}
	wg.Wait()
	return res, nil
}

func (d *Diagnoser) routes() ([]Route, string) {
	root := d.ProcRoot
	if root == "" {
		if runtime.GOOS != "linux" {
			return []Route{}, "UNSUPPORTED_OS"
		}
		root = "/proc"
	}
	out := []Route{}
	f4, err4 := os.Open(filepath.Join(root, "net", "route"))
	if err4 == nil {
		out = append(out, ParseIPv4Routes(f4)...)
		f4.Close()
	}
	f6, err6 := os.Open(filepath.Join(root, "net", "ipv6_route"))
	if err6 == nil {
		out = append(out, ParseIPv6Routes(f6)...)
		f6.Close()
	}
	if len(out) > MaxRoutes {
		out = out[:MaxRoutes]
	}
	if err4 != nil && err6 != nil {
		return out, "ROUTES_UNAVAILABLE"
	}
	return out, ""
}

func (d *Diagnoser) resolve(ctx context.Context, host string) DNSResult {
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, DNSTimeout)
	defer cancel()
	res := DNSResult{Host: host, Addresses: []string{}}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		var de *net.DNSError
		switch {
		case errors.As(err, &de) && de.IsNotFound:
			res.Error = "NOT_FOUND"
		case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
			res.Error = "TIMEOUT"
		default:
			res.Error = connpath.ErrDNSFailed
		}
		return res
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			res.Addresses = append(res.Addresses, ip.Unmap().String())
		}
		if len(res.Addresses) >= 16 {
			break
		}
	}
	sort.Strings(res.Addresses)
	return res
}

func (d *Diagnoser) tcp(ctx context.Context, t TCPTarget) TCPResult {
	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, TCPTimeout)
	defer cancel()
	res := TCPResult{Host: t.Host, Port: t.Port}
	start := time.Now()
	c, err := dial(ctx, "tcp", netip.AddrPortFrom(t.Addr, uint16(t.Port)).String())
	if err != nil {
		res.Error = connpath.ClassifyError(err)
		return res
	}
	c.Close()
	ms := time.Since(start).Milliseconds()
	res.OK, res.LatencyMs = true, &ms
	return res
}

// SystemInterfaces lists the host's interfaces (≤ 64, ≤ 32 addresses each).
func SystemInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := []Interface{}
	for _, ifc := range ifs {
		it := Interface{Name: ifc.Name, MTU: ifc.MTU, Up: ifc.Flags&net.FlagUp != 0, Addresses: []string{}}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if len(it.Addresses) >= 32 {
					break
				}
				it.Addresses = append(it.Addresses, a.String())
			}
		}
		out = append(out, it)
		if len(out) >= 64 {
			break
		}
	}
	return out, nil
}
