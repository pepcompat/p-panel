package connpath

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

var (
	pub  = Endpoint{Path: PathPublic, URL: "https://center.example:4443"}
	priv = Endpoint{Path: PathPrivate, URL: "https://10.110.0.2:4444"}
	both = []Endpoint{pub, priv}
)

func paths(eps []Endpoint) string {
	var s []string
	for _, e := range eps {
		s = append(s, e.Path)
	}
	return strings.Join(s, ",")
}

func TestOrderPerPolicy(t *testing.T) {
	cases := []struct {
		policy string
		eps    []Endpoint
		want   string
	}{
		{PolicyPrivateOnly, both, "private"},
		{PolicyPrivateOnly, []Endpoint{pub}, ""}, // fail closed: never public
		{PolicyPublicOnly, both, "public"},
		{PolicyPrivatePreferred, both, "private,public"},
		{PolicyPublicPreferred, both, "public,private"},
		{PolicyAuto, both, "private,public"},
		{PolicyAuto, []Endpoint{pub}, "public"},
		{PolicyUnknown, both, "public,private"},
	}
	for _, c := range cases {
		if got := paths(Order(c.policy, c.eps)); got != c.want {
			t.Errorf("%s %v: got %q want %q", c.policy, paths(c.eps), got, c.want)
		}
	}
	if Allows(PolicyPrivateOnly, PathPublic) || !Allows(PolicyPrivateOnly, PathPrivate) || Allows(PolicyPublicOnly, PathPrivate) || Allows(PolicyAuto, "x") {
		t.Fatal("Allows")
	}
	if Probeable(PolicyPrivateOnly, PathPublic) || !Probeable(PolicyPublicOnly, PathPrivate) {
		t.Fatal("Probeable")
	}
}

func TestNormalizeURLAndEndpoints(t *testing.T) {
	good := map[string]string{
		"https://center.example:4443":  "https://center.example:4443",
		"https://center.example:4443/": "https://center.example:4443",
		"https://10.0.0.1":             "https://10.0.0.1",
		"https://[fd00::1]:4444":       "https://[fd00::1]:4444",
	}
	for in, want := range good {
		got, err := NormalizeURL(in)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "http://c:4443", "https://", "https://u:p@c", "https://c/x", "https://c?q", "https://c#f",
		"https://c:0", "https://c:99999", "https://c:", "https://c :1", "ftp://c", "https://c\n", "//c", strings.Repeat("a", 600)} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ValidateEndpoints(nil); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := ValidateEndpoints([]Endpoint{{Path: "vpn", URL: pub.URL}}); err == nil {
		t.Fatal("unknown path accepted")
	}
	if _, err := ValidateEndpoints([]Endpoint{pub, {Path: PathPrivate, URL: pub.URL + "/"}}); err == nil {
		t.Fatal("duplicate url accepted")
	}
	many := make([]Endpoint, MaxEndpoints+1)
	for i := range many {
		many[i] = Endpoint{Path: PathPublic, URL: fmt.Sprintf("https://c%d", i)}
	}
	if _, err := ValidateEndpoints(many); err == nil {
		t.Fatal("too many accepted")
	}
}

type fakeProbe struct {
	mu  sync.Mutex
	ok  map[string]bool
	hit map[string]int
}

func (f *fakeProbe) probe(_ context.Context, ep Endpoint) ProbeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hit[ep.Path]++
	r := ProbeResult{Path: ep.Path, URL: ep.URL, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if f.ok[ep.URL] {
		r.OK, r.LatencyMs = true, ms(time.Millisecond)
	} else {
		r.Error = ErrRefused
	}
	return r
}

func newMgr(t *testing.T, eps []Endpoint, fp *fakeProbe, now func() time.Time) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	if err := SaveEnrollment(dir, pub.URL, eps); err != nil {
		t.Fatal(err)
	}
	o := Options{StateDir: dir, FallbackURL: pub.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: now}
	if fp != nil {
		o.Probe = fp.probe
	}
	m, err := Load(o)
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

func active(m *Manager) string {
	e, ok := m.Active()
	if !ok {
		return ""
	}
	return e.Path
}

func netErr() error { return &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED} }

func forbiddenErr() error { return &transport.APIError{HTTPStatus: 403, Code: CodePathNotAllowed} }

func TestFallbackWithoutStateFile(t *testing.T) {
	m, err := Load(Options{StateDir: t.TempDir(), FallbackURL: pub.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.BaseURL()
	if err != nil || u != pub.URL {
		t.Fatalf("%q %v", u, err)
	}
	if _, err := Load(Options{StateDir: t.TempDir(), FallbackURL: "http://insecure"}); err == nil {
		t.Fatal("non-https fallback accepted")
	}
}

func TestCorruptStateFallsBack(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"policy":"weird","endpoints":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(Options{StateDir: dir, FallbackURL: pub.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil || active(m) != PathPublic || m.Policy() != PolicyUnknown {
		t.Fatalf("%v %s %q", err, active(m), m.Policy())
	}
}

func TestStateFileSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(t.TempDir(), "x.json")
	b, _ := json.Marshal(persisted{Policy: PolicyPrivateOnly, Endpoints: []Endpoint{priv}})
	_ = os.WriteFile(other, b, 0o600)
	if err := os.Symlink(other, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	m, err := Load(Options{StateDir: dir, FallbackURL: pub.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil || m.Policy() == PolicyPrivateOnly {
		t.Fatalf("followed symlinked connection.json: %v %q", err, m.Policy())
	}
}

func TestPrivateOnlyNeverSelectsPublic(t *testing.T) {
	fp := &fakeProbe{ok: map[string]bool{pub.URL: true}, hit: map[string]int{}}
	m, dir := newMgr(t, both, fp, nil)
	m.Apply(&Block{Policy: PolicyPrivateOnly, Endpoints: both})
	m.ProbeAll(context.Background())
	if active(m) != PathPrivate {
		t.Fatalf("active %q", active(m))
	}
	if fp.hit[PathPublic] != 0 {
		t.Fatal("private_only probed the public endpoint")
	}
	for i := 0; i < 5; i++ { // repeated failures rotate among private only
		m.Observe(context.Background(), priv.URL, netErr())
		if u, err := m.BaseURL(); err != nil || u != priv.URL {
			t.Fatalf("base %q %v", u, err)
		}
	}
	// a private_only policy with no private endpoint: no path at all
	m.Apply(&Block{Policy: PolicyPrivateOnly, Endpoints: []Endpoint{pub}})
	if _, err := m.BaseURL(); !errors.Is(err, ErrNoPath) {
		t.Fatalf("want ErrNoPath, got %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st, err)
	}
}

func TestForbiddenUntilNewPolicyAllows(t *testing.T) {
	fp := &fakeProbe{ok: map[string]bool{pub.URL: true, priv.URL: true}, hit: map[string]int{}}
	m, dir := newMgr(t, both, fp, nil)
	if active(m) != PathPublic { // unknown policy: public first
		t.Fatalf("active %q", active(m))
	}
	m.Observe(context.Background(), pub.URL, forbiddenErr())
	if active(m) != PathPrivate {
		t.Fatalf("after 403: %q", active(m))
	}
	m.ProbeAll(context.Background()) // public probes healthy but stays forbidden
	if active(m) != PathPrivate {
		t.Fatalf("forbidden path re-selected: %q", active(m))
	}
	// same-as-recorded policy ("" → private_only does not allow public) keeps it forbidden
	m.Apply(&Block{Policy: PolicyPrivateOnly})
	if len(m.Forbidden()) != 1 {
		t.Fatal("cleared too early")
	}
	// reload from disk keeps it
	m2, _ := Load(Options{StateDir: dir, FallbackURL: pub.URL, Probe: fp.probe})
	if len(m2.Forbidden()) != 1 || m2.Policy() != PolicyPrivateOnly {
		t.Fatalf("persisted %v %q", m2.Forbidden(), m2.Policy())
	}
	m.Apply(&Block{Policy: PolicyPublicPreferred})
	if len(m.Forbidden()) != 0 || active(m) != PathPublic {
		t.Fatalf("new policy should clear: %v %q", m.Forbidden(), active(m))
	}
	// 403 under the same policy again: not cleared by a repeat of that policy
	m.Observe(context.Background(), pub.URL, forbiddenErr())
	m.Apply(&Block{Policy: PolicyPublicPreferred})
	if len(m.Forbidden()) != 1 {
		t.Fatal("repeat of the same policy must not clear the forbidden path")
	}
}

func TestAllForbiddenLastResortInterval(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	m, _ := newMgr(t, []Endpoint{pub}, nil, clock)
	m.Apply(&Block{Policy: PolicyPublicOnly})
	m.Observe(context.Background(), pub.URL, forbiddenErr())
	if _, err := m.BaseURL(); err != nil { // first last-resort retry right away
		t.Fatalf("last resort: %v", err)
	}
	m.Observe(context.Background(), pub.URL, forbiddenErr())
	if _, err := m.BaseURL(); !errors.Is(err, ErrNoPath) {
		t.Fatalf("second retry within interval: %v", err)
	}
	now = now.Add(ForbiddenRetryInterval)
	if _, err := m.BaseURL(); err != nil {
		t.Fatalf("retry after interval: %v", err)
	}
}

func TestFailoverRotationAndFailback(t *testing.T) {
	fp := &fakeProbe{ok: map[string]bool{pub.URL: true, priv.URL: true}, hit: map[string]int{}}
	m, _ := newMgr(t, both, fp, nil)
	var switches []string
	m.SetOnSwitch(func(_, to string) { switches = append(switches, to) })
	m.Apply(&Block{Policy: PolicyAuto, Endpoints: both})
	m.ProbeAll(context.Background())
	if active(m) != PathPrivate {
		t.Fatalf("auto with private: %q", active(m))
	}
	m.Observe(context.Background(), priv.URL, netErr())
	if active(m) != PathPublic {
		t.Fatalf("failover: %q", active(m))
	}
	// context cancellation / API errors / bad responses do not count as failures
	m.Observe(context.Background(), pub.URL, context.Canceled)
	m.Observe(context.Background(), pub.URL, &transport.APIError{HTTPStatus: 500, Code: "X"})
	m.Observe(context.Background(), pub.URL, fmt.Errorf("%w: x", transport.ErrBadResponse))
	if active(m) != PathPublic {
		t.Fatalf("non-network errors moved the path: %q", active(m))
	}
	m.ProbeAll(context.Background())
	if active(m) != PathPrivate {
		t.Fatalf("fail-back: %q", active(m))
	}
	if len(switches) < 2 {
		t.Fatalf("switch callbacks %v", switches)
	}
	rep := m.Report()
	if rep.ActivePath == nil || *rep.ActivePath != PathPrivate || len(rep.Endpoints) != 2 || rep.Policy != PolicyAuto {
		t.Fatalf("report %+v", rep)
	}
}

func TestInvalidBlocksIgnored(t *testing.T) {
	m, _ := newMgr(t, both, nil, nil)
	if m.Apply(&Block{Policy: "everything"}) || m.Apply(&Block{Policy: PolicyAuto, Endpoints: []Endpoint{{Path: PathPublic, URL: "http://x"}}}) {
		t.Fatal("invalid block applied")
	}
	if m.Policy() != PolicyUnknown || len(m.Endpoints()) != 2 {
		t.Fatal("state changed")
	}
	if m.Apply(nil) {
		t.Fatal("nil applied")
	}
	if !m.Apply(&Block{Policy: PolicyPublicOnly}) || len(m.Endpoints()) != 2 {
		t.Fatal("empty endpoint list must keep endpoints")
	}
}

func TestSaveEnrollmentRejectsInvalid(t *testing.T) {
	if err := SaveEnrollment(t.TempDir(), pub.URL, []Endpoint{{Path: PathPrivate, URL: "https://u@x"}}); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
}

func TestClassifyError(t *testing.T) {
	cases := map[string]error{
		ErrDNSFailed:   &net.DNSError{Err: "no such host", Name: "x"},
		ErrRefused:     netErr(),
		ErrUnreachable: &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH},
		ErrDialTimeout: context.DeadlineExceeded,
		ErrTLSFailed:   tls.AlertError(42),
		ErrConnFailed:  errors.New("x"),
	}
	for want, err := range cases {
		if got := ClassifyError(err); got != want {
			t.Errorf("%v: got %s want %s", err, got, want)
		}
	}
}

func TestProberAgainstTLSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path != PingPath:
			w.WriteHeader(404)
		case r.Header.Get("X-Agent-Protocol") == "":
			w.WriteHeader(426)
		case strings.Contains(r.Host, "forbidden"):
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"code":"CONNECTION_PATH_NOT_ALLOWED","message":"x"}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"data":{"pong":true}}`))
		}
	}))
	srv.StartTLS()
	defer srv.Close()
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	addr := srv.Listener.Addr().String()
	dialTo := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	p := &Prober{TLS: func() *tls.Config { return &tls.Config{RootCAs: pool} }, Dial: dialTo}
	_, port, _ := net.SplitHostPort(addr)
	r := p.Probe(context.Background(), Endpoint{Path: PathPrivate, URL: "https://example.com:" + port})
	if !r.OK || r.LatencyMs == nil || r.Error != "" {
		t.Fatalf("ok probe %+v", r)
	}
	// wrong name for the cert → TLS_FAILED
	r = p.Probe(context.Background(), Endpoint{Path: PathPrivate, URL: "https://wrong.invalid:" + port})
	if r.OK || r.Error != ErrTLSFailed || r.LatencyMs != nil {
		t.Fatalf("tls probe %+v", r)
	}
	// untrusted CA → TLS_FAILED
	p2 := &Prober{TLS: func() *tls.Config { return &tls.Config{} }, Dial: dialTo}
	if r := p2.Probe(context.Background(), Endpoint{Path: PathPublic, URL: "https://example.com:" + port}); r.Error != ErrTLSFailed {
		t.Fatalf("untrusted %+v", r)
	}
	// refused
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	p3 := &Prober{Timeout: time.Second}
	if r := p3.Probe(context.Background(), Endpoint{Path: PathPublic, URL: "https://" + dead}); r.Error != ErrRefused {
		t.Fatalf("refused %+v", r)
	}
	// DNS
	if r := p3.Probe(context.Background(), Endpoint{Path: PathPublic, URL: "https://nonexistent.invalid:4443"}); r.Error != ErrDNSFailed {
		t.Fatalf("dns %+v", r)
	}
}

func TestProberPathForbiddenAndHTTPError(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"error":{"code":"CONNECTION_PATH_NOT_ALLOWED"}}`))
	}))
	srv.StartTLS()
	defer srv.Close()
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	p := &Prober{TLS: func() *tls.Config { return &tls.Config{RootCAs: pool} },
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}
	if r := p.Probe(context.Background(), Endpoint{Path: PathPublic, URL: "https://example.com:" + port}); r.OK || r.Error != ErrPathForbidden {
		t.Fatalf("forbidden %+v", r)
	}
}

func FuzzValidateEndpoints(f *testing.F) {
	f.Add(`[{"path":"public","url":"https://c:4443"},{"path":"private","url":"https://10.0.0.2:4444"}]`)
	f.Add(`[{"path":"private","url":"https://u:p@c"}]`)
	f.Add(`[{"path":"public","url":"https://c/x?y#z"}]`)
	f.Fuzz(func(t *testing.T, raw string) {
		var eps []Endpoint
		if json.Unmarshal([]byte(raw), &eps) != nil {
			return
		}
		out, err := ValidateEndpoints(eps)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, e := range out {
			if !ValidPath(e.Path) || !strings.HasPrefix(e.URL, "https://") || strings.ContainsAny(e.URL, "@?# \n") || seen[e.URL] {
				t.Fatalf("accepted bad endpoint %+v", e)
			}
			if again, err := NormalizeURL(e.URL); err != nil || again != e.URL {
				t.Fatalf("not idempotent: %q -> %q %v", e.URL, again, err)
			}
			seen[e.URL] = true
		}
		// private_only never orders a public endpoint
		for _, e := range Order(PolicyPrivateOnly, out) {
			if e.Path != PathPrivate {
				t.Fatal("private_only yielded public")
			}
		}
	})
}

func TestObserveOnStalePathDropsConnections(t *testing.T) {
	fp := &fakeProbe{ok: map[string]bool{pub.URL: true, priv.URL: true}, hit: map[string]int{}}
	m, _ := newMgr(t, both, fp, nil)
	m.Apply(&Block{Policy: PolicyPrivateOnly, Endpoints: both})
	var calls []string
	m.SetOnSwitch(func(from, _ string) { calls = append(calls, from) })
	m.Observe(context.Background(), pub.URL, nil) // long-poll on public finished after the switch
	m.Observe(context.Background(), priv.URL, nil)
	if len(calls) != 1 || calls[0] != pub.URL {
		t.Fatalf("stale callbacks %v", calls)
	}
}

func TestPingPolicyAllowsFalseNeverSelected(t *testing.T) {
	no, yes := false, true
	m, _ := newMgr(t, both, nil, nil)
	m.o.Probe = func(_ context.Context, ep Endpoint) ProbeResult {
		r := ProbeResult{Path: ep.Path, URL: ep.URL, OK: true, LatencyMs: ms(time.Millisecond), CheckedAt: "x"}
		if ep.Path == PathPrivate {
			r.PolicyAllows = &no
		} else {
			r.PolicyAllows = &yes
		}
		return r
	}
	m.Apply(&Block{Policy: PolicyPrivatePreferred, Endpoints: both})
	m.ProbeAll(context.Background())
	if active(m) != PathPublic {
		t.Fatalf("selected a path the Center's ping disallows: %q", active(m))
	}
	rep := m.Report()
	for _, e := range rep.Endpoints {
		if e.PolicyAllows == nil {
			t.Fatalf("policyAllows not reported: %+v", e)
		}
	}
	if pingPolicyAllows([]byte(`{"data":{"policyAllows":false}}`)) == nil || pingPolicyAllows([]byte(`{}`)) != nil {
		t.Fatal("pingPolicyAllows")
	}
}
