package connpath

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/transport"
	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

// ProbeTimeout bounds one endpoint probe (TCP + TLS handshake + ping).
const ProbeTimeout = 5 * time.Second

// Probe error codes (short codes, contract §1).
const (
	ErrDialTimeout   = "DIAL_TIMEOUT"
	ErrTLSFailed     = "TLS_FAILED"
	ErrRefused       = "REFUSED"
	ErrDNSFailed     = "DNS_FAILED"
	ErrUnreachable   = "UNREACHABLE"
	ErrPathForbidden = "PATH_FORBIDDEN"
	ErrConnFailed    = "CONNECTION_FAILED"
)

// ProbeResult is one endpoint's latest probe outcome (heartbeat
// `connection.endpoints[]`). LatencyMs is null when the probe failed.
type ProbeResult struct {
	Path      string `json:"path"`
	URL       string `json:"url"`
	OK        bool   `json:"ok"`
	LatencyMs *int64 `json:"latencyMs"`
	CheckedAt string `json:"checkedAt"`
	Error     string `json:"error,omitempty"`
	// PolicyAllows is the Center's ping answer: false = reachable, but the
	// server's policy forbids this path (never selected as the active path).
	PolicyAllows *bool `json:"policyAllows,omitempty"`
}

// ClassifyError maps a dial/TLS/HTTP client error to a short code.
func ClassifyError(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var alert tls.AlertError
	var recErr tls.RecordHeaderError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var ne net.Error
	switch {
	case errors.As(err, &dnsErr):
		return ErrDNSFailed
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return ErrUnreachable
	case errors.As(err, &certErr), errors.As(err, &alert), errors.As(err, &recErr),
		errors.As(err, &unknownAuth), errors.As(err, &hostErr), errors.As(err, &invalidErr):
		return ErrTLSFailed
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return ErrDialTimeout
	case errors.As(err, &ne) && ne.Timeout():
		return ErrDialTimeout
	}
	return ErrConnFailed
}

// Prober performs TLS handshake + GET /agent/v1/ping against one endpoint with
// the agent's mTLS identity. It never uses a proxy and never follows redirects.
type Prober struct {
	// TLS returns the mTLS client config (pinned CA + client certificate).
	TLS     func() *tls.Config
	Timeout time.Duration
	Now     func() time.Time
	// Dial overrides the TCP dialer (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func ms(d time.Duration) *int64 {
	v := d.Milliseconds()
	return &v
}

// Probe probes ep once.
func (p *Prober) Probe(ctx context.Context, ep Endpoint) ProbeResult {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = ProbeTimeout
	}
	res := ProbeResult{Path: ep.Path, URL: ep.URL, CheckedAt: now().UTC().Format(time.RFC3339Nano)}
	u, err := url.Parse(ep.URL)
	if err != nil || u.Hostname() == "" {
		res.Error = ErrConnFailed
		return res
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		res.Error = ClassifyError(err)
		return res
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.TLS != nil {
		cfg = p.TLS().Clone()
	}
	cfg.ServerName = u.Hostname()
	cfg.NextProtos = []string{"http/1.1"}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		res.Error = ErrTLSFailed
		if c := ClassifyError(err); c == ErrDialTimeout {
			res.Error = c
		}
		return res
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL+PingPath, nil)
	req.Close = true
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Request-ID", transport.NewUUID())
	req.Header.Set("X-Client-Version", version.Version)
	req.Header.Set("X-Agent-Protocol", version.ProtocolVersion)
	req.Header.Set("User-Agent", "ppanel-agent/"+version.Version)
	if err := req.Write(tc); err != nil {
		res.Error = ClassifyError(err)
		return res
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		res.Error = ClassifyError(err)
		return res
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	elapsed := time.Since(start)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.OK = true
		res.LatencyMs = ms(elapsed)
		res.PolicyAllows = pingPolicyAllows(body)
	case resp.StatusCode == http.StatusForbidden && errorCode(body) == CodePathNotAllowed:
		res.Error = ErrPathForbidden
	default:
		res.Error = "HTTP_" + strconv.Itoa(resp.StatusCode)
	}
	return res
}

// pingPolicyAllows reads data.policyAllows of a ping answer (nil = absent).
func pingPolicyAllows(body []byte) *bool {
	var env struct {
		Data struct {
			PolicyAllows *bool `json:"policyAllows"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil {
		return nil
	}
	return env.Data.PolicyAllows
}

func errorCode(body []byte) string {
	var env struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil || env.Error == nil {
		return ""
	}
	return env.Error.Code
}
