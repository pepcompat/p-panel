// Package netdiag implements the P9 read-only network jobs (contract §4, §5):
// network.diagnose (interfaces, routes, DNS, TCP reachability of private
// targets and Center endpoints) and http.probe (one GET/HEAD to a private
// address with a Host/SNI override). Neither changes OS configuration, routes
// or addresses, and every parameter is re-validated here: the Center is not
// trusted.
package netdiag

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Limits (contract §4/§5).
const (
	MaxResolve      = 10
	MaxTCP          = 20
	MaxAllowedPorts = 32
	MaxURLBytes     = 2048
	MaxExpectStatus = 10
	// MaxProbeTimeoutSec bounds http.probe (contract: 10 s).
	MaxProbeTimeoutSec = 10
)

// DiagnosePorts is the fixed port allowlist of network.diagnose tcp targets.
var DiagnosePorts = []int{22, 80, 443, 4443, 4444, 5432, 6379, 3306}

// ProbePorts is the fixed port allowlist of http.probe URLs.
var ProbePorts = []int{80, 443, 8080, 8443}

// privateRanges are the only target ranges (besides advertised Center
// endpoint addresses): RFC 1918, RFC 6598 (100.64/10), fd00::/8.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd00::/8"),
}

// InPrivateRange reports whether a is inside the allowed private ranges.
func InPrivateRange(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privateRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func invalid(format string, a ...any) error {
	return jobs.Errorf(jobs.RejectedInvalidParams, format, a...)
}

var hostLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ValidHostname reports whether s is a DNS host name (RFC 1123 labels, ≤ 253
// bytes, an optional trailing dot, at least one letter in the last label so
// IP literals are not names).
func ValidHostname(s string) bool {
	t := strings.TrimSuffix(s, ".")
	if t == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(t, ".")
	for _, l := range labels {
		if !hostLabelRe.MatchString(l) {
			return false
		}
	}
	last := labels[len(labels)-1]
	return strings.ContainsAny(strings.ToLower(last), "abcdefghijklmnopqrstuvwxyz")
}

// parseIP parses an IP literal (no zone), returning the unmapped address.
func parseIP(s string) (netip.Addr, bool) {
	if len(s) > 64 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func portSet(base []int, extra []int) map[int]bool {
	m := map[int]bool{}
	for _, p := range base {
		m[p] = true
	}
	for _, p := range extra {
		m[p] = true
	}
	return m
}

func checkAllowedPorts(ps []int) error {
	if len(ps) > MaxAllowedPorts {
		return invalid("allowedPorts: at most %d entries", MaxAllowedPorts)
	}
	for i, p := range ps {
		if p < 1 || p > 65535 {
			return invalid("allowedPorts[%d]: must be 1..65535", i)
		}
	}
	return nil
}

// ---------------- network.diagnose ----------------

// TCPTarget is one validated tcp check.
type TCPTarget struct {
	Host string     `json:"host"`
	Port int        `json:"port"`
	Addr netip.Addr `json:"-"`
}

// DiagnoseParams are the validated network.diagnose params.
type DiagnoseParams struct {
	Resolve       []string
	TCP           []TCPTarget
	IncludeRoutes bool
	AllowedPorts  []int
}

type tcpWire struct {
	Host *string `json:"host"`
	Port *int    `json:"port"`
}

type diagnoseWire struct {
	Resolve       []string  `json:"resolve"`
	TCP           []tcpWire `json:"tcp"`
	IncludeRoutes bool      `json:"includeRoutes"`
	AllowedPorts  []int     `json:"allowedPorts"`
}

// CenterAddrs returns the addresses (with port) of the advertised Center
// endpoints. It is called only when a tcp target is outside the private
// ranges (it may resolve endpoint host names).
type CenterAddrs func() []netip.AddrPort

// DecodeDiagnose strictly decodes and validates network.diagnose params.
// tcp.host must be an IP literal in a private range or an advertised Center
// endpoint address; ports must be in DiagnosePorts ∪ allowedPorts (∪ the
// endpoint's own port for a Center endpoint address).
func DecodeDiagnose(raw json.RawMessage, center CenterAddrs) (DiagnoseParams, error) {
	var w diagnoseWire
	var p DiagnoseParams
	if err := containerops.DecodeParams(raw, &w); err != nil {
		return p, err
	}
	if len(w.Resolve) > MaxResolve {
		return p, invalid("resolve: at most %d host names", MaxResolve)
	}
	seen := map[string]bool{}
	for i, h := range w.Resolve {
		if !ValidHostname(h) {
			return p, invalid("resolve[%d]: not a valid host name", i)
		}
		k := strings.ToLower(strings.TrimSuffix(h, "."))
		if seen[k] {
			return p, invalid("resolve[%d]: duplicate host name", i)
		}
		seen[k] = true
	}
	if err := checkAllowedPorts(w.AllowedPorts); err != nil {
		return p, err
	}
	if len(w.TCP) > MaxTCP {
		return p, invalid("tcp: at most %d targets", MaxTCP)
	}
	ports := portSet(DiagnosePorts, w.AllowedPorts)
	var centerList []netip.AddrPort
	centerLoaded := false
	seenT := map[string]bool{}
	for i, t := range w.TCP {
		if t.Host == nil || t.Port == nil {
			return p, invalid("tcp[%d]: host and port are required", i)
		}
		a, ok := parseIP(*t.Host)
		if !ok {
			return p, invalid("tcp[%d].host: must be an IP literal", i)
		}
		port := *t.Port
		if port < 1 || port > 65535 {
			return p, invalid("tcp[%d].port: must be 1..65535", i)
		}
		allowedAddr := InPrivateRange(a)
		portOK := ports[port]
		if !allowedAddr || !portOK {
			if !centerLoaded && center != nil {
				centerList, centerLoaded = center(), true
			}
			for _, c := range centerList {
				if c.Addr().Unmap() == a {
					allowedAddr = true
					if int(c.Port()) == port {
						portOK = true
					}
				}
			}
		}
		if !allowedAddr {
			return p, invalid("tcp[%d].host: %s is not in a private range (RFC 1918, 100.64/10, fd00::/8) nor a Center endpoint address", i, a)
		}
		if !portOK {
			return p, invalid("tcp[%d].port: %d is not allowed (allowlist or allowedPorts)", i, port)
		}
		key := netip.AddrPortFrom(a, uint16(port)).String()
		if seenT[key] {
			return p, invalid("tcp[%d]: duplicate target", i)
		}
		seenT[key] = true
		p.TCP = append(p.TCP, TCPTarget{Host: a.String(), Port: port, Addr: a})
	}
	p.Resolve = append([]string{}, w.Resolve...)
	p.IncludeRoutes = w.IncludeRoutes
	p.AllowedPorts = append([]int{}, w.AllowedPorts...)
	if p.TCP == nil {
		p.TCP = []TCPTarget{}
	}
	return p, nil
}

// ---------------- http.probe ----------------

// ProbeParams are the validated http.probe params.
type ProbeParams struct {
	URL          string
	Hostname     string // Host header / SNI
	Port         int
	ResolveTo    netip.Addr
	Method       string
	ExpectStatus []int
	AllowedPorts []int
	Timeout      time.Duration
}

type probeWire struct {
	URL          *string         `json:"url"`
	ResolveTo    *string         `json:"resolveTo"`
	Port         *int            `json:"port"`
	ExpectStatus json.RawMessage `json:"expectStatus"`
	Method       *string         `json:"method"`
	TimeoutSec   *int            `json:"timeoutSec"`
	AllowedPorts []int           `json:"allowedPorts"`
}

func validStatus(n int) bool { return n >= 100 && n <= 599 }

func decodeExpect(raw json.RawMessage) ([]int, error) {
	if len(raw) == 0 {
		return []int{200}, nil // shared-contracts default
	}
	var one int
	if err := json.Unmarshal(raw, &one); err == nil {
		if !validStatus(one) {
			return nil, invalid("expectStatus: must be 100..599")
		}
		return []int{one}, nil
	}
	var many []int
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, invalid("expectStatus: must be a status code or a list of status codes")
	}
	if len(many) == 0 || len(many) > MaxExpectStatus {
		return nil, invalid("expectStatus: 1..%d status codes", MaxExpectStatus)
	}
	for _, n := range many {
		if !validStatus(n) {
			return nil, invalid("expectStatus: must be 100..599")
		}
	}
	sort.Ints(many)
	return many, nil
}

// DecodeProbe strictly decodes and validates http.probe params: url is
// http(s)://<host>[:port]<path> with no userinfo/fragment; the port (params.port,
// else the URL port, else 80/443) must be in ProbePorts ∪ allowedPorts;
// resolveTo is a private-range IP literal; a URL host that is itself an IP
// literal must equal resolveTo; method GET|HEAD; timeoutSec 1..10.
func DecodeProbe(raw json.RawMessage) (ProbeParams, error) {
	var w probeWire
	var p ProbeParams
	if err := containerops.DecodeParams(raw, &w); err != nil {
		return p, err
	}
	if w.URL == nil || w.ResolveTo == nil {
		return p, invalid("url and resolveTo are required")
	}
	if err := checkAllowedPorts(w.AllowedPorts); err != nil {
		return p, err
	}
	raw0 := *w.URL
	if len(raw0) == 0 || len(raw0) > MaxURLBytes {
		return p, invalid("url: 1..%d bytes", MaxURLBytes)
	}
	for i := 0; i < len(raw0); i++ {
		if raw0[i] <= 0x20 || raw0[i] >= 0x7f || raw0[i] == '\\' {
			return p, invalid("url: control, space, backslash or non-ASCII character")
		}
	}
	u, err := url.Parse(raw0)
	if err != nil {
		return p, invalid("url: %v", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.Host == "" {
		return p, invalid("url: must be http(s)://host[:port]/path")
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw0, "#") || strings.Contains(raw0, "@") {
		return p, invalid("url: userinfo and fragments are not allowed")
	}
	if u.Path != "" && !strings.HasPrefix(u.Path, "/") {
		return p, invalid("url: path must start with /")
	}
	to, ok := parseIP(*w.ResolveTo)
	if !ok || !InPrivateRange(to) {
		return p, invalid("resolveTo: must be an IP literal in a private range (RFC 1918, 100.64/10, fd00::/8)")
	}
	host := u.Hostname()
	if ip, isIP := parseIP(host); isIP {
		if ip != to {
			return p, invalid("url: an IP-literal host must equal resolveTo")
		}
	} else if !ValidHostname(host) {
		return p, invalid("url: host must be a DNS name or an IP literal")
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if ps := u.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil || n < 1 || n > 65535 {
			return p, invalid("url: port must be 1..65535")
		}
		port = n
	} else if strings.HasSuffix(u.Host, ":") {
		return p, invalid("url: empty port")
	}
	if w.Port != nil {
		if *w.Port < 1 || *w.Port > 65535 {
			return p, invalid("port: must be 1..65535")
		}
		if u.Port() != "" && *w.Port != port {
			return p, invalid("port: differs from the url port")
		}
		port = *w.Port
	}
	if !portSet(ProbePorts, w.AllowedPorts)[port] {
		return p, invalid("url: port %d is not allowed (allowlist or allowedPorts)", port)
	}
	method := "GET"
	if w.Method != nil {
		method = *w.Method
	}
	if method != "GET" && method != "HEAD" {
		return p, invalid("method: GET or HEAD only")
	}
	exp, err := decodeExpect(w.ExpectStatus)
	if err != nil {
		return p, err
	}
	timeout := MaxProbeTimeoutSec
	if w.TimeoutSec != nil {
		if *w.TimeoutSec < 1 || *w.TimeoutSec > MaxProbeTimeoutSec {
			return p, invalid("timeoutSec: must be 1..%d", MaxProbeTimeoutSec)
		}
		timeout = *w.TimeoutSec
	}
	return ProbeParams{URL: u.String(), Hostname: strings.ToLower(strings.TrimSuffix(host, ".")), Port: port, ResolveTo: to,
		Method: method, ExpectStatus: exp, AllowedPorts: append([]int{}, w.AllowedPorts...),
		Timeout: time.Duration(timeout) * time.Second}, nil
}

// String renders the probe target for logs.
func (p ProbeParams) String() string {
	return fmt.Sprintf("%s %s via %s", p.Method, p.URL, netip.AddrPortFrom(p.ResolveTo, uint16(p.Port)))
}
