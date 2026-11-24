package netdiag

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

func center() []netip.AddrPort {
	return []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:4443"), netip.MustParseAddrPort("10.110.0.2:4444")}
}

func code(err error) string {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je.Code
	}
	return ""
}

func TestDecodeDiagnoseAccepts(t *testing.T) {
	p, err := DecodeDiagnose(json.RawMessage(`{"resolve":["lab-center-private","db.internal."],"tcp":[
		{"host":"10.120.0.12","port":22},{"host":"172.20.0.5","port":5432},{"host":"192.168.1.1","port":8081},
		{"host":"100.64.1.1","port":443},{"host":"fd00::5","port":6379},{"host":"203.0.113.5","port":4443},
		{"host":"::ffff:10.1.2.3","port":3306}],
		"includeRoutes":true,"allowedPorts":[8081]}`), center)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.TCP) != 7 || !p.IncludeRoutes || p.TCP[6].Host != "10.1.2.3" || len(p.Resolve) != 2 {
		t.Fatalf("%+v", p)
	}
	if p, err := DecodeDiagnose(json.RawMessage(`{}`), nil); err != nil || p.TCP == nil || p.IncludeRoutes {
		t.Fatalf("empty: %+v %v", p, err)
	}
}

func TestDecodeDiagnoseRejects(t *testing.T) {
	cases := []string{
		`{"tcp":[{"host":"8.8.8.8","port":443}]}`,                               // public, not a Center endpoint
		`{"tcp":[{"host":"203.0.113.5","port":22}]}`,                            // Center address, but port not its own nor allowlisted → 22 IS allowlisted
		`{"tcp":[{"host":"127.0.0.1","port":22}]}`,                              // loopback
		`{"tcp":[{"host":"169.254.169.254","port":80}]}`,                        // link-local metadata
		`{"tcp":[{"host":"fe80::1%eth0","port":22}]}`,                           // zone
		`{"tcp":[{"host":"fc00::1","port":22}]}`,                                // fc00::/8 is not fd00::/8
		`{"tcp":[{"host":"10.0.0.1","port":8080}]}`,                             // port not allowed
		`{"tcp":[{"host":"10.0.0.1","port":0}]}`,                                // port range
		`{"tcp":[{"host":"10.0.0.1","port":70000}]}`,                            // port range
		`{"tcp":[{"host":"10.0.0.1","port":22.5}]}`,                             // non-int
		`{"tcp":[{"host":"lab-node-b","port":22}]}`,                             // not an IP literal
		`{"tcp":[{"host":"10.0.0.1"}]}`,                                         // missing port
		`{"tcp":[{"host":"10.0.0.1","port":22,"x":1}]}`,                         // unknown nested field
		`{"tcp":[{"host":"10.0.0.1","port":22},{"host":"10.0.0.1","port":22}]}`, // duplicate
		`{"tcp":null}`, `{"resolve":null}`, `{"includeRoutes":"yes"}`, `{"cmd":"rm"}`,
		`{"resolve":["-x"]}`, `{"resolve":["a..b"]}`, `{"resolve":["10.0.0.1"]}`, `{"resolve":["a b"]}`, `{"resolve":["x","X."]}`,
		`{"resolve":["` + strings.Repeat("a", 64) + `.com"]}`,
		`{"resolve":["a","b","c","d","e","f","g","h","i","j","k"]}`,
		`{"allowedPorts":[0]}`, `{"allowedPorts":[65536]}`,
		`[]`, `{"tcp":[{"host":"10.0.0.1","port":22}]} {}`,
	}
	for _, c := range cases {
		_, err := DecodeDiagnose(json.RawMessage(c), center)
		if c == `{"tcp":[{"host":"203.0.113.5","port":22}]}` {
			if err != nil {
				t.Errorf("center address with allowlisted port refused: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("accepted %s", c)
		}
	}
	if _, err := DecodeDiagnose(json.RawMessage(`{"tcp":[{"host":"203.0.113.5","port":4444}]}`), center); err == nil {
		// 4444 is allowlisted → accepted (allowlist applies to Center addresses too)
	} else {
		t.Errorf("4444: %v", err)
	}
	if _, err := DecodeDiagnose(json.RawMessage(`{"tcp":[{"host":"203.0.113.5","port":9000}]}`), center); err == nil {
		t.Error("center address with a foreign port accepted")
	}
	tcp21 := make([]string, 21)
	for i := range tcp21 {
		tcp21[i] = `{"host":"10.0.0.` + string(rune('1'+i%9)) + `","port":` + []string{"22", "80", "443"}[i/9] + `}`
	}
	if _, err := DecodeDiagnose(json.RawMessage(`{"tcp":[`+strings.Join(tcp21, ",")+`]}`), nil); err == nil {
		t.Error("21 tcp targets accepted")
	}
	_, err := DecodeDiagnose(json.RawMessage(`{"tcp":[{"host":"8.8.8.8","port":443}]}`), nil)
	if code(err) != jobs.RejectedInvalidParams {
		t.Fatalf("code %v", err)
	}
}

func TestDecodeProbe(t *testing.T) {
	p, err := DecodeProbe(json.RawMessage(`{"url":"http://shop.example.lab/health?x=1","resolveTo":"10.110.0.20","expectStatus":200}`))
	if err != nil || p.Port != 80 || p.Hostname != "shop.example.lab" || p.Method != "GET" || len(p.ExpectStatus) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = DecodeProbe(json.RawMessage(`{"url":"https://Shop.Example.Lab:8443/","resolveTo":"fd00::20","expectStatus":[301,200],"method":"HEAD"}`))
	if err != nil || p.Port != 8443 || p.Hostname != "shop.example.lab" || p.ExpectStatus[0] != 200 {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := DecodeProbe(json.RawMessage(`{"url":"http://10.110.0.20:9000/","resolveTo":"10.110.0.20","allowedPorts":[9000]}`)); err != nil || p.Port != 9000 {
		t.Fatalf("ip host = resolveTo + allowedPorts: %v", err)
	}
	// the Center's shape (shared-contracts httpProbeParams): port + timeoutSec + expectStatus list
	p, err = DecodeProbe(json.RawMessage(`{"url":"http://static.example.lab/","resolveTo":"10.110.0.11","port":8080,"method":"GET","expectStatus":[200],"timeoutSec":5}`))
	if err != nil || p.Port != 8080 || p.Timeout.Seconds() != 5 {
		t.Fatalf("center shape: %+v %v", p, err)
	}
	if p, err := DecodeProbe(json.RawMessage(`{"url":"http://a.lab/","resolveTo":"10.0.0.1"}`)); err != nil || len(p.ExpectStatus) != 1 || p.ExpectStatus[0] != 200 {
		t.Fatalf("default expectStatus: %+v %v", p, err)
	}
	for _, c := range []string{
		`{"url":"http://shop.example.lab/","resolveTo":"8.8.8.8"}`,          // public override
		`{"url":"http://shop.example.lab/","resolveTo":"127.0.0.1"}`,        // loopback
		`{"url":"http://shop.example.lab/","resolveTo":"169.254.169.254"}`,  // metadata
		`{"url":"http://shop.example.lab/","resolveTo":"shop.example.lab"}`, // not an IP
		`{"url":"http://10.0.0.9/","resolveTo":"10.0.0.8"}`,                 // IP host != resolveTo
		`{"url":"http://shop.example.lab:22/","resolveTo":"10.0.0.8"}`,      // port not allowed
		`{"url":"http://shop.example.lab:/","resolveTo":"10.0.0.8"}`,        // empty port
		`{"url":"ftp://shop.example.lab/","resolveTo":"10.0.0.8"}`,          // scheme
		`{"url":"file:///etc/passwd","resolveTo":"10.0.0.8"}`,               // scheme
		`{"url":"http://u:p@shop.example.lab/","resolveTo":"10.0.0.8"}`,     // userinfo
		`{"url":"http://shop.example.lab/#x","resolveTo":"10.0.0.8"}`,       // fragment
		`{"url":"http://shop.example.lab/ x","resolveTo":"10.0.0.8"}`,       // space
		`{"url":"http://shop.example.lab/é","resolveTo":"10.0.0.8"}`,        // non-ASCII
		`{"url":"http://shop_example/","resolveTo":"10.0.0.8"}`,             // bad host
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","method":"POST"}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","method":"get"}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","expectStatus":99}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","expectStatus":[]}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","expectStatus":"200"}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","expectStatus":null}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","headers":{"X":"1"}}`,
		`{"url":"http://shop.example.lab/"}`, `{"resolveTo":"10.0.0.8"}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","allowedPorts":[-1]}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","port":3000}`,
		`{"url":"http://shop.example.lab:8080/","resolveTo":"10.0.0.8","port":80}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","timeoutSec":11}`,
		`{"url":"http://shop.example.lab/","resolveTo":"10.0.0.8","timeoutSec":0}`,
		`{"url":"http://shop.example.lab` + strings.Repeat("/a", 1100) + `","resolveTo":"10.0.0.8"}`,
	} {
		if _, err := DecodeProbe(json.RawMessage(c)); err == nil {
			t.Errorf("accepted %s", c)
		}
	}
}

func TestRoutesParse(t *testing.T) {
	v4 := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth1\t00006E0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"bad line\n"
	r := ParseIPv4Routes(strings.NewReader(v4))
	if len(r) != 2 || r[0].Dst != "0.0.0.0/0" || r[0].Gateway != "192.168.0.1" || r[0].Metric != 100 || r[1].Dst != "10.110.0.0/24" || r[1].Iface != "eth1" {
		t.Fatalf("%+v", r)
	}
	v6 := "fd000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth1\n" +
		"zz\n"
	r = ParseIPv6Routes(strings.NewReader(v6))
	if len(r) != 1 || r[0].Dst != "fd00::/8" || r[0].Metric != 256 || r[0].Gateway != "::" {
		t.Fatalf("%+v", r)
	}
}

func TestDiagnoseRun(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := ln.Addr().String()
	var mu sync.Mutex
	var dialled []string
	d := &Diagnoser{
		ProcRoot: t.TempDir(),
		Interfaces: func() ([]Interface, error) {
			return []Interface{{Name: "eth0", MTU: 1500, Up: true, Addresses: []string{"10.110.0.11/24"}}}, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialled = append(dialled, addr)
			mu.Unlock()
			if addr == "10.110.0.20:22" {
				return (&net.Dialer{}).DialContext(ctx, network, open)
			}
			return nil, &net.OpError{Op: "dial", Err: errors.New("i/o timeout"), Net: "tcp"}
		},
		ProbeCenter: func(context.Context) []connpath.ProbeResult {
			return []connpath.ProbeResult{{Path: "private", URL: "https://lab-center-private:4444", OK: true}}
		},
	}
	p, err := DecodeDiagnose(json.RawMessage(`{"tcp":[{"host":"10.110.0.20","port":22},{"host":"10.120.0.12","port":22}],"includeRoutes":true}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TCP[0].OK || res.TCP[0].LatencyMs == nil || res.TCP[1].OK || res.TCP[1].Error == "" {
		t.Fatalf("tcp %+v", res.TCP)
	}
	if len(res.CenterEndpoints) != 1 || res.RoutesError != "ROUTES_UNAVAILABLE" || len(res.Interfaces) != 1 {
		t.Fatalf("%+v", res)
	}
	for _, a := range dialled {
		if a != "10.110.0.20:22" && a != "10.120.0.12:22" {
			t.Fatalf("dialled unexpected %s", a)
		}
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"routes":[]`) || !strings.Contains(string(b), `"dns":[]`) {
		t.Fatalf("empty lists must be [] not null: %s", b)
	}
}

// http.probe: Host/SNI override — the connection always goes to resolveTo,
// the Host header carries the domain, redirects are not followed, body ≤ 1 MiB.
func TestHTTPProbeHostOverrideNoRedirectBodyCap(t *testing.T) {
	var gotHost string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost = r.Host
		mu.Unlock()
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "http://evil.example/", http.StatusFound)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", MaxProbeBody+100)))
		default:
			w.Header().Set("Server", "nginx")
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer srv.Close()
	var dialled []string
	pr := &Prober{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, addr)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}
	run := func(raw string) *ProbeResult {
		p, err := DecodeProbe(json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		return pr.Run(context.Background(), p)
	}
	r := run(`{"url":"http://shop.example.lab/","resolveTo":"10.110.0.20","expectStatus":200}`)
	if !r.OK || *r.Status != 200 || r.BodyBytes != 5 || *r.BodySha256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" || r.Headers["Server"] != "nginx" {
		t.Fatalf("%+v", r)
	}
	if gotHost != "shop.example.lab" {
		t.Fatalf("host header %q", gotHost)
	}
	r = run(`{"url":"http://shop.example.lab/redirect","resolveTo":"10.110.0.20","expectStatus":200}`)
	if r.OK || *r.Status != 302 || r.StatusMatch || r.Headers["Location"] != "http://evil.example/" {
		t.Fatalf("redirect %+v", r)
	}
	r = run(`{"url":"http://shop.example.lab/big","resolveTo":"10.110.0.20"}`)
	if !r.Truncated || r.BodyBytes != MaxProbeBody || !r.OK {
		t.Fatalf("big %+v", r)
	}
	r = run(`{"url":"http://shop.example.lab/","resolveTo":"10.110.0.20","method":"HEAD"}`)
	if !r.OK || r.BodyBytes != 0 {
		t.Fatalf("head %+v", r)
	}
	for _, a := range dialled {
		if a != "10.110.0.20:80" {
			t.Fatalf("dialled %s instead of resolveTo", a)
		}
	}
}

func TestHTTPProbeTLSSNIAndFailures(t *testing.T) {
	var sni string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { sni = h.ServerName; return nil, nil }}
	srv.StartTLS()
	defer srv.Close()
	pr := &Prober{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}
	p, _ := DecodeProbe(json.RawMessage(`{"url":"https://shop.example.lab/","resolveTo":"10.110.0.20"}`))
	r := pr.Run(context.Background(), p)
	if !r.OK || r.TLS == nil || r.TLS.Verified || r.TLS.VerifyError == "" || sni != "shop.example.lab" {
		t.Fatalf("%+v sni=%q tls=%+v", r, sni, r.TLS)
	}
	// refused
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	pr2 := &Prober{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dead)
	}}
	p, _ = DecodeProbe(json.RawMessage(`{"url":"http://shop.example.lab/","resolveTo":"10.110.0.20"}`))
	if r := pr2.Run(context.Background(), p); r.OK || r.Error != connpath.ErrRefused || r.Status != nil {
		t.Fatalf("refused %+v", r)
	}
}

func FuzzDecodeDiagnose(f *testing.F) {
	f.Add(`{"resolve":["a.b"],"tcp":[{"host":"10.0.0.1","port":22}],"includeRoutes":true,"allowedPorts":[8080]}`)
	f.Add(`{"tcp":[{"host":"203.0.113.5","port":4443}]}`)
	f.Add(`{"tcp":[{"host":"::ffff:8.8.8.8","port":22}]}`)
	f.Add(`{"tcp":[{"host":"fd00::1%25x","port":22}]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := DecodeDiagnose(json.RawMessage(raw), center)
		if err != nil {
			return
		}
		ports := portSet(DiagnosePorts, p.AllowedPorts)
		if len(p.TCP) > MaxTCP || len(p.Resolve) > MaxResolve || len(p.AllowedPorts) > MaxAllowedPorts {
			t.Fatalf("limits %+v", p)
		}
		for _, tg := range p.TCP {
			isCenter := false
			for _, c := range center() {
				if c.Addr() == tg.Addr {
					isCenter = true
				}
			}
			if !InPrivateRange(tg.Addr) && !isCenter {
				t.Fatalf("accepted public target %s", tg.Addr)
			}
			if tg.Addr.Zone() != "" || tg.Addr.Is4In6() || tg.Addr.IsLoopback() || tg.Addr.IsLinkLocalUnicast() {
				t.Fatalf("accepted %s", tg.Addr)
			}
			if !ports[tg.Port] && !(isCenter && (tg.Port == 4443 || tg.Port == 4444)) {
				t.Fatalf("accepted port %d", tg.Port)
			}
		}
		for _, h := range p.Resolve {
			if !ValidHostname(h) {
				t.Fatalf("accepted name %q", h)
			}
		}
	})
}

func FuzzDecodeProbe(f *testing.F) {
	f.Add(`{"url":"http://shop.example.lab/health","resolveTo":"10.110.0.20","expectStatus":200}`)
	f.Add(`{"url":"https://a.b:8443/x?y=1","resolveTo":"fd00::1","expectStatus":[200,301],"method":"HEAD","allowedPorts":[9000]}`)
	f.Add(`{"url":"http://10.0.0.1@evil/","resolveTo":"10.0.0.1"}`)
	f.Add(`{"url":"http://[fd00::1]/","resolveTo":"fd00::1"}`)
	f.Add(`{"url":"http://a.lab/","resolveTo":"10.0.0.1","port":8443,"timeoutSec":3,"expectStatus":[200]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := DecodeProbe(json.RawMessage(raw))
		if err != nil {
			return
		}
		if !InPrivateRange(p.ResolveTo) || p.ResolveTo.Zone() != "" {
			t.Fatalf("resolveTo %s", p.ResolveTo)
		}
		if p.Method != "GET" && p.Method != "HEAD" {
			t.Fatalf("method %q", p.Method)
		}
		if !portSet(ProbePorts, p.AllowedPorts)[p.Port] {
			t.Fatalf("port %d", p.Port)
		}
		if strings.ContainsAny(p.URL, " \n\r\t#@\\") || len(p.URL) > MaxURLBytes+16 {
			t.Fatalf("url %q", p.URL)
		}
		if !strings.HasPrefix(p.URL, "http://") && !strings.HasPrefix(p.URL, "https://") {
			t.Fatalf("scheme %q", p.URL)
		}
		if ip, ok := parseIP(p.Hostname); ok && ip != p.ResolveTo {
			t.Fatalf("ip host %s != resolveTo %s", ip, p.ResolveTo)
		}
		if p.Timeout <= 0 || p.Timeout > ProbeTimeout {
			t.Fatalf("timeout %s", p.Timeout)
		}
		for _, s := range p.ExpectStatus {
			if !validStatus(s) {
				t.Fatalf("status %d", s)
			}
		}
	})
}
