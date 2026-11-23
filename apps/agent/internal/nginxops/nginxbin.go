package nginxops

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

const (
	nginxTestTimeout   = 30 * time.Second
	nginxTestOutputCap = 16 << 10
	reloadTimeout      = 30 * time.Second
	dumpOutputCap      = 16 << 20
	probeTimeout       = 5 * time.Second
	defaultPidFile     = "/run/nginx.pid"
)

// Reload methods reported in output.reloadMethod.
const (
	ReloadSystemctl = "systemctl"
	ReloadSignal    = "nginx -s reload"
)

func (m *Manager) nginxBin() (string, error) {
	bin, ok := execx.Find("nginx", m.o.NginxBinary)
	if !ok {
		return "", jobs.Errorf(CodeNginxNotPresent, "nginx binary not found")
	}
	return bin, nil
}

// nginxArgs prefixes the test-only -p/-c overrides (empty in production).
func (m *Manager) nginxArgs(extra ...string) []string {
	var a []string
	if m.o.Prefix != "" {
		a = append(a, "-p", m.o.Prefix)
	}
	if m.o.ConfFile != "" {
		a = append(a, "-c", m.o.ConfFile)
	}
	return append(a, extra...)
}

func capOut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…[truncated]"
	}
	return s
}

// nginxTest runs `nginx -t` (30 s, 16 KiB). ok=false on non-zero exit or exec error.
func (m *Manager) nginxTest(ctx context.Context) (bool, string) {
	bin, err := m.nginxBin()
	if err != nil {
		return false, err.Error()
	}
	res, err := m.o.Exec.Run(ctx, bin, m.nginxArgs("-t"), nginxTestTimeout, nginxTestOutputCap)
	out := strings.TrimSpace(string(res.Stderr) + string(res.Stdout))
	if err != nil {
		return false, capOut(strings.TrimSpace(out+"\n"+err.Error()), nginxTestOutputCap)
	}
	return res.ExitCode == 0, capOut(out, nginxTestOutputCap)
}

// systemdPID1 reports whether systemd is the init system.
func (m *Manager) systemdPID1() bool {
	d := m.o.SystemdRunDir
	if d == "" {
		d = "/run/systemd/system"
	}
	st, err := os.Stat(d)
	return err == nil && st.IsDir()
}

// reload reloads nginx: `systemctl reload nginx.service` when systemd is PID 1
// and the unit is active, else `nginx -s reload`.
func (m *Manager) reload(ctx context.Context) (string, error) {
	if m.systemdPID1() {
		if sc, ok := execx.Find("systemctl", m.o.SystemctlBinary); ok {
			st, err := m.o.Exec.Run(ctx, sc, []string{"is-active", "--quiet", "nginx.service"}, 10*time.Second, 4<<10)
			if err == nil && st.ExitCode == 0 {
				res, err := m.o.Exec.Run(ctx, sc, []string{"reload", "--no-ask-password", "nginx.service"}, reloadTimeout, 16<<10)
				if err != nil {
					return ReloadSystemctl, err
				}
				if res.ExitCode != 0 {
					return ReloadSystemctl, fmt.Errorf("systemctl reload nginx exited %d: %s", res.ExitCode, capOut(strings.TrimSpace(string(res.Stderr)), 2000))
				}
				return ReloadSystemctl, nil
			}
		}
	}
	bin, err := m.nginxBin()
	if err != nil {
		return ReloadSignal, err
	}
	res, err := m.o.Exec.Run(ctx, bin, m.nginxArgs("-s", "reload"), reloadTimeout, 16<<10)
	if err != nil {
		return ReloadSignal, err
	}
	if res.ExitCode != 0 {
		return ReloadSignal, fmt.Errorf("nginx -s reload exited %d: %s", res.ExitCode, capOut(strings.TrimSpace(string(res.Stderr)), 2000))
	}
	return ReloadSignal, nil
}

var pidDirectiveRe = regexp.MustCompile(`(?m)^\s*pid\s+([^;\s]+)\s*;`)

// pidFile returns the pid file from `nginx -T`'s pid directive, else the default.
func (m *Manager) pidFile(ctx context.Context) string {
	def := m.o.DefaultPidFile
	if def == "" {
		def = defaultPidFile
	}
	bin, err := m.nginxBin()
	if err != nil {
		return def
	}
	res, err := m.o.Exec.Run(ctx, bin, m.nginxArgs("-T"), nginxTestTimeout, dumpOutputCap)
	if err != nil || res.ExitCode != 0 {
		return def
	}
	if mm := pidDirectiveRe.FindSubmatch(res.Stdout); mm != nil {
		p := string(mm[1])
		if strings.HasPrefix(p, "/") {
			return p
		}
		if m.o.Prefix != "" {
			return strings.TrimRight(m.o.Prefix, "/") + "/" + p
		}
	}
	return def
}

// masterAlive reads the pid file and checks the process exists.
func masterAlive(pidFile string) (int, bool, error) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, false, fmt.Errorf("pid file %s: invalid content", pidFile)
	}
	err = syscall.Kill(pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return pid, true, nil
	}
	return pid, false, nil
}

// ProbeResult is one postcheck result (output.postchecks[]).
type ProbeResult struct {
	HostHeader string `json:"hostHeader"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

var loopback = net.IPv4(127, 0, 0, 1)

// probe performs one loopback-only GET. The URL host is the literal 127.0.0.1;
// the dialer additionally refuses any other address. Host header and SNI are
// the requested hostHeader; TLS verification is off (loopback only); no proxy;
// redirects are not followed.
func (m *Manager) probe(ctx context.Context, pc Postcheck) ProbeResult {
	r := ProbeResult{HostHeader: pc.HostHeader, Path: pc.Path}
	timeout := m.o.ProbeTimeout
	if timeout <= 0 {
		timeout = probeTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil || !net.ParseIP(host).Equal(loopback) {
				return nil, fmt.Errorf("postcheck refused non-loopback address %q", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSClientConfig:        &tls.Config{ServerName: pc.HostHeader, InsecureSkipVerify: true}, //nolint:gosec // loopback-only probe
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := fmt.Sprintf("%s://127.0.0.1:%d%s", pc.Scheme, pc.Port, pc.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Host = pc.HostHeader
	req.Header.Set("User-Agent", "ppanel-agent-postcheck")
	resp, err := client.Do(req)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	r.Status = resp.StatusCode
	for _, s := range pc.ExpectStatus {
		if s == resp.StatusCode {
			r.OK = true
		}
	}
	if !r.OK {
		r.Error = fmt.Sprintf("status %d not in expectStatus %v", resp.StatusCode, pc.ExpectStatus)
	}
	return r
}
