package docker

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// recorder is an inner RoundTripper that records what would reach the socket.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls = append(r.calls, req.Method+" "+req.URL.String())
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
}

func rawReq(t *testing.T, method, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return &http.Request{Method: method, URL: u, Header: http.Header{}, Host: u.Host}
}

// TestEngineAllowlistBypassAttempts sends crafted requests straight to the
// allowlist RoundTripper: none may reach the inner transport (the socket).
func TestEngineAllowlistBypassAttempts(t *testing.T) {
	type tc struct {
		name, method, url string
		hdr               map[string]string
	}
	cases := []tc{
		{"double slash", "POST", "http://docker//containers/ppanel-web-0a1b2c3d/start", nil},
		{"double slash exec", "POST", "http://docker//containers/x/exec", nil},
		{"percent-encoded dotdot", "POST", "http://docker/containers/x/%2e%2e/exec", nil},
		{"percent-encoded slash", "DELETE", "http://docker/containers/ppanel-web-0a1b2c3d%2Fexec", nil},
		{"percent-encoded name", "POST", "http://docker/containers/%70panel/start", nil},
		{"versioned exec traversal", "POST", "http://docker/v1.47/containers/x/../exec", nil},
		{"versioned start", "POST", "http://docker/v1.47/containers/ppanel-web-0a1b2c3d/start", nil},
		{"versioned secrets read", "GET", "http://docker/v1.47/secrets", nil},
		{"versioned configs read", "GET", "http://docker/v1.47/configs", nil},
		{"dotdot read secrets", "GET", "http://docker/images/../secrets", nil},
		{"dotdot read configs", "GET", "http://docker/containers/x/../../configs", nil},
		{"dot segment", "POST", "http://docker/containers/./create", nil},
		{"trailing slash", "POST", "http://docker/containers/create/", nil},
		{"trailing slash start", "POST", "http://docker/containers/ppanel-web-0a1b2c3d/start/", nil},
		{"uppercase path", "POST", "http://docker/CONTAINERS/create", nil},
		{"lowercase method", "post", "http://docker/containers/create", nil},
		{"mixed-case method", "Delete", "http://docker/containers/ppanel-web-0a1b2c3d", nil},
		{"absolute url other host", "GET", "http://127.0.0.1:2375/containers/json", nil},
		{"https scheme", "GET", "https://docker/containers/json", nil},
		{"userinfo", "GET", "http://user:pw@docker/containers/json", nil},
		{"fragment", "GET", "http://docker/containers/json#frag", nil},
		{"backslash", "POST", "http://docker/containers\\create", nil},
		{"semicolon param", "POST", "http://docker/containers/create;x=1", nil},
		{"method override header", "POST", "http://docker/containers/ppanel-web-0a1b2c3d/start", map[string]string{"X-HTTP-Method-Override": "DELETE"}},
		{"method override header 2", "GET", "http://docker/_ping", map[string]string{"X-HTTP-Method": "POST"}},
		{"method override header 3", "GET", "http://docker/_ping", map[string]string{"X-Method-Override": "POST"}},
		{"exec create", "POST", "http://docker/containers/ppanel-web-0a1b2c3d/exec", nil},
		{"exec start", "POST", "http://docker/exec/abc/start", nil},
		{"exec read", "GET", "http://docker/exec/abc/json", nil},
		{"export", "GET", "http://docker/containers/ppanel-web-0a1b2c3d/export", nil},
		{"image save", "GET", "http://docker/images/get", nil},
		{"image save by name", "GET", "http://docker/images/nginx/get", nil},
		{"image ref smuggles json", "GET", "http://docker/images/x/json/json", nil},
		{"swarm", "GET", "http://docker/swarm", nil},
		{"plugins", "GET", "http://docker/plugins", nil},
		{"attach", "POST", "http://docker/containers/ppanel-web-0a1b2c3d/attach", nil},
		{"update (privilege change)", "POST", "http://docker/containers/ppanel-web-0a1b2c3d/update", nil},
		{"commit", "POST", "http://docker/commit", nil},
		{"volume delete", "DELETE", "http://docker/volumes/ppanel-web-data", nil},
		{"network delete (non restore)", "DELETE", "http://docker/networks/ppanel-web", nil},
		{"network connect", "POST", "http://docker/networks/bridge/connect", nil},
		{"system prune", "POST", "http://docker/containers/prune", nil},
		{"archive put app container", "PUT", "http://docker/containers/ppanel-web-0a1b2c3d/archive", nil},
		{"anon volume delete app", "DELETE", "http://docker/containers/ppanel-web-0a1b2c3d?v=1", nil},
		{"anon volume delete app v=true", "DELETE", "http://docker/containers/ppanel-web-0a1b2c3d?v=true", nil},
		{"build on non-build engine", "POST", "http://docker/build", nil},
		{"PATCH", "PATCH", "http://docker/containers/create", nil},
		{"OPTIONS", "OPTIONS", "http://docker/containers/json", nil},
		{"CONNECT", "CONNECT", "http://docker/containers/json", nil},
		{"null byte", "POST", "http://docker/containers/create%00", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{}
			rt := allowlist{rt: rec}
			req := rawReq(t, c.method, c.url)
			for k, v := range c.hdr {
				req.Header.Set(k, v)
			}
			resp, err := rt.RoundTrip(req)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("%s %s was allowed", c.method, c.url)
			}
			if len(rec.calls) != 0 {
				t.Fatalf("refused request reached the socket: %v", rec.calls)
			}
		})
	}
	// Host header override (URL is fine, Host differs).
	rec := &recorder{}
	req := rawReq(t, "GET", "http://docker/containers/json")
	req.Host = "evil"
	if _, err := (allowlist{rt: rec}).RoundTrip(req); err == nil || len(rec.calls) != 0 {
		t.Fatal("Host override must be refused")
	}
}

// TestEngineAllowlistLegitimateCalls guards against over-tightening.
func TestEngineAllowlistLegitimateCalls(t *testing.T) {
	ok := []struct{ m, u string }{
		{"GET", "http://docker/_ping"},
		{"GET", "http://docker/containers/json?all=1&filters=%7B%7D"},
		{"GET", "http://docker/containers/ppanel-web-0a1b2c3d/json"},
		{"GET", "http://docker/containers/abc/logs?stdout=1"},
		{"GET", "http://docker/containers/abc/stats?stream=false&one-shot=true"},
		{"GET", "http://docker/containers/abc/archive?path=%2Fbackup"},
		{"GET", "http://docker/images/lab-registry:5000/acme/web@sha256:" + strings.Repeat("a", 64) + "/json"},
		{"GET", "http://docker/networks/ppanel-web"},
		{"GET", "http://docker/volumes/ppanel-web-data"},
		{"POST", "http://docker/containers/create?name=ppanel-web-0a1b2c3d"},
		{"POST", "http://docker/containers/ppanel-web-0a1b2c3d/start"},
		{"POST", "http://docker/images/create?fromImage=x&tag=sha256%3Aab"},
		{"DELETE", "http://docker/containers/ppanel-web-0a1b2c3d?v=0&force=0"},
		{"DELETE", "http://docker/containers/ppanel-restore-0a1b2c3d-db?v=1&force=1"},
		{"PUT", "http://docker/containers/ppanel-bk-0123456789abcdef/archive?path=%2Fwork"},
		{"DELETE", "http://docker/networks/ppanel-restore-0a1b2c3d"},
	}
	for _, c := range ok {
		rec := &recorder{}
		resp, err := (allowlist{rt: rec}).RoundTrip(rawReq(t, c.m, c.u))
		if err != nil {
			t.Errorf("%s %s refused: %v", c.m, c.u, err)
			continue
		}
		resp.Body.Close()
		if len(rec.calls) != 1 {
			t.Errorf("%s %s did not reach the transport", c.m, c.u)
		}
	}
}

func TestReadOnlyClientAllowlistBypass(t *testing.T) {
	for _, u := range []string{
		"http://docker/v1.47/secrets", "http://docker/images/../secrets", "http://docker//exec/x/json",
		"http://docker/containers/x/export", "http://docker/images/get", "http://docker/info/../configs",
		"http://docker/containers/x%2F..%2F..%2Fsecrets/json",
	} {
		rec := &recorder{}
		if _, err := (getOnly{rec}).RoundTrip(rawReq(t, "GET", u)); err == nil || len(rec.calls) != 0 {
			t.Errorf("read-only client allowed %s", u)
		}
	}
	rec := &recorder{}
	if _, err := (getOnly{rec}).RoundTrip(rawReq(t, "POST", "http://docker/containers/create")); err == nil || len(rec.calls) != 0 {
		t.Error("read-only client allowed POST")
	}
}

// unixServer serves h on a fresh unix socket (short path for macOS limits).
func unixServer(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dkp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// TestRedirectsNeverFollowed: a 30x from the socket must not turn an allowed
// request into a request for another (forbidden) path or host.
func TestRedirectsNeverFollowed(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/containers/json":
			http.Redirect(w, r, "/secrets", http.StatusFound)
		case "/version":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusMovedPermanently)
		case "/containers/ppanel-web-0a1b2c3d/start":
			http.Redirect(w, r, "/containers/ppanel-web-0a1b2c3d/exec", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(200)
		}
	}))
	e := NewEngine(sock)
	if _, err := e.ListContainers(context.Background(), nil); err == nil {
		t.Error("engine followed or accepted a redirect")
	}
	if err := e.StartContainer(context.Background(), "ppanel-web-0a1b2c3d"); err == nil {
		t.Error("engine followed a 307 on POST")
	}
	c := New(sock)
	var out any
	if err := c.Get(context.Background(), "/containers/json", &out); err == nil {
		t.Error("read-only client followed a redirect")
	}
	if _, err := c.EngineVersion(context.Background()); err == nil {
		t.Error("read-only client followed an absolute redirect")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if strings.Contains(s, "secrets") || strings.Contains(s, "exec") || strings.Contains(s, "meta-data") {
			t.Fatalf("redirect target was requested: %v", seen)
		}
	}
}

// TestUnixSocketCannotBePointedElsewhere: even a request whose URL names a
// TCP host is refused before dialing, and the dialer ignores the address.
func TestUnixSocketCannotBePointedElsewhere(t *testing.T) {
	tcpHits := 0
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { tcpHits++ })}
	go srv.Serve(ln)
	defer srv.Close()
	unixHits := 0
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { unixHits++; w.Write([]byte("OK")) }))

	e := NewEngine(sock)
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/_ping", nil)
	if resp, err := e.hc.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("request to a TCP host was allowed")
	}
	// The transport dialer itself always dials the socket, whatever the address.
	inner := e.hc.Transport.(allowlist).rt.(*http.Transport)
	conn, err := inner.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr().Network() != "unix" {
		t.Fatalf("dialer reached %s", conn.RemoteAddr().Network())
	}
	conn.Close()
	// Ping still works (over the socket) and the TCP server was never touched.
	if err := e.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tcpHits != 0 || unixHits == 0 {
		t.Fatalf("tcpHits=%d unixHits=%d", tcpHits, unixHits)
	}
}

// TestEngineRefRejection: helper methods validate references before building a path.
func TestEngineRefRejection(t *testing.T) {
	e := NewEngine("/nonexistent.sock")
	ctx := context.Background()
	for _, ref := range []string{"../secrets", "x/../../exec", "UPPER", "a?x=1", "a#b", "x/json/../../secrets", ""} {
		if _, err := e.InspectImage(ctx, ref); err == nil || IsUnavailable(err) {
			t.Errorf("InspectImage(%q) not rejected locally: %v", ref, err)
		}
	}
	for _, n := range []string{"../secrets", "-x", "a/b", "", "a?b"} {
		if _, err := e.InspectNetwork(ctx, n); err == nil || IsUnavailable(err) {
			t.Errorf("InspectNetwork(%q) not rejected locally: %v", n, err)
		}
		if _, err := e.InspectContainer(ctx, n); err == nil || IsUnavailable(err) {
			t.Errorf("InspectContainer(%q) not rejected locally: %v", n, err)
		}
	}
}

// FuzzAllowedCall: whatever (method, path, query) is allowed must be canonical,
// never an exec/secret/swarm/plugin/export endpoint, and a mutating call must
// target one of the documented resource families.
func FuzzAllowedCall(f *testing.F) {
	seeds := []struct{ m, p, q string }{
		{"GET", "/_ping", ""}, {"POST", "/containers/create", "name=x"}, {"POST", "//containers/x/start", ""},
		{"POST", "/v1.47/containers/x/../exec", ""}, {"GET", "/images/../secrets", ""}, {"DELETE", "/containers/ppanel-restore-0a1b2c3d-db", "v=1"},
		{"DELETE", "/containers/ppanel-web-0a1b2c3d", "v=1"}, {"POST", "/images/ghcr.io/acme/web/push", "tag=build-0123456789ab"},
		{"DELETE", "/images/ghcr.io/acme/web:build-0123456789ab", "force=1"}, {"GET", "/containers/x%2f../exec", ""},
		{"PUT", "/containers/ppanel-bk-0123456789abcdef/archive", "path=/w"}, {"post", "/build", ""}, {"GET", "/containers/x/json/", ""},
	}
	for _, s := range seeds {
		f.Add(s.m, s.p, s.q, false)
		f.Add(s.m, s.p, s.q, true)
	}
	bad := []string{"/exec", "/secrets", "/configs", "/swarm", "/plugins", "/export", "/get", "/attach", "/update", "/commit", "/prune", "/session", "/distribution", "/connect", "/disconnect"}
	f.Fuzz(func(t *testing.T, method, p, rawq string, build bool) {
		q, _ := url.ParseQuery(rawq)
		var allowed bool
		if build {
			allowed = AllowedBuildCall(method, p, q) && AllowedQuery(method, p, q)
		} else {
			allowed = AllowedCall(method, p) && AllowedQuery(method, p, q)
		}
		if !allowed {
			return
		}
		if !CanonicalPath(p) || path.Clean(p) != p || strings.Contains(p, "..") || strings.Contains(p, "//") || versionPrefixRe.MatchString(p) {
			t.Fatalf("non-canonical path allowed: %s %q", method, p)
		}
		for _, b := range bad {
			if strings.Contains(p, b+"/") || strings.HasSuffix(p, b) {
				// /images/<ref>/json may legitimately contain e.g. "get" inside a repo name segment only as a full segment
				if !(strings.HasPrefix(p, "/images/") && (strings.HasSuffix(p, "/json") || strings.HasSuffix(p, "/push") || strings.Contains(p, ":build-"))) {
					t.Fatalf("dangerous endpoint allowed: %s %q", method, p)
				}
			}
		}
		switch method {
		case "GET", "HEAD":
		case "POST", "PUT", "DELETE":
			if !(strings.HasPrefix(p, "/containers/") || strings.HasPrefix(p, "/images/") || strings.HasPrefix(p, "/networks/") ||
				strings.HasPrefix(p, "/volumes/") || (build && strings.HasPrefix(p, "/build"))) {
				t.Fatalf("mutating call outside resource families: %s %q", method, p)
			}
			if method == "DELETE" && strings.HasPrefix(p, "/volumes/") {
				t.Fatalf("volume deletion allowed: %q", p)
			}
			if method == "DELETE" && q.Get("v") != "" && q.Get("v") != "0" && !ScratchNameRe.MatchString(strings.TrimPrefix(p, "/containers/")) {
				t.Fatalf("anonymous-volume delete allowed for non-scratch container: %q %v", p, q)
			}
			if method == "PUT" && !HelperNameRe.MatchString(strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/archive")) {
				t.Fatalf("archive upload allowed into non-helper: %q", p)
			}
		default:
			t.Fatalf("method %q allowed", method)
		}
	})
}

// FuzzRoundTripShape: arbitrary raw URLs and override headers through the
// real allowlist RoundTripper. Whatever reaches the inner transport has a
// canonical, unencoded path on host "docker" and is allowlisted.
func FuzzRoundTripShape(f *testing.F) {
	for _, s := range []string{
		"http://docker/containers/json", "http://docker//containers/x/start", "http://docker/containers/x/%2e%2e/exec",
		"http://docker/v1.47/containers/x/start", "http://evil/containers/json", "http://docker/containers/create?name=a&x=/../",
		"http://docker/containers/ppanel-web-0a1b2c3d?v=1", "http://u:p@docker/_ping", "http://docker/containers/x/start/",
	} {
		f.Add("POST", s, "")
		f.Add("GET", s, "X-HTTP-Method-Override")
	}
	f.Fuzz(func(t *testing.T, method, raw, hdr string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		rec := &recorder{}
		req := &http.Request{Method: method, URL: u, Header: http.Header{}, Host: u.Host}
		if hdr != "" && validHeaderName(hdr) {
			req.Header.Set(hdr, "DELETE")
		}
		resp, err := (allowlist{rt: rec}).RoundTrip(req)
		if err != nil {
			if len(rec.calls) != 0 {
				t.Fatal("refused request reached the transport")
			}
			return
		}
		resp.Body.Close()
		if u.Host != "docker" || u.RawPath != "" || !CanonicalPath(u.Path) || !AllowedCall(method, u.Path) {
			t.Fatalf("non-canonical request reached the transport: %s %q", method, raw)
		}
		for _, h := range methodOverrideHeaders {
			if req.Header.Get(h) != "" {
				t.Fatalf("override header passed: %s", h)
			}
		}
	})
}

func validHeaderName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
