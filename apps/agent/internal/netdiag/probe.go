package netdiag

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

// http.probe limits (contract §5).
const (
	ProbeTimeout  = 10 * time.Second
	MaxProbeBody  = 1 << 20
	maxHeaderSize = 64 << 10
)

// TLSInfo describes the server certificate seen by an https probe. The probe
// never fails on certificate problems (shadow tests compare responses); it
// reports whether the chain verified against the system roots for the host.
type TLSInfo struct {
	Version     string `json:"version"`
	Verified    bool   `json:"verified"`
	VerifyError string `json:"verifyError,omitempty"`
	Subject     string `json:"subject,omitempty"`
	NotAfter    string `json:"notAfter,omitempty"`
}

// ProbeResult is the http.probe output.
type ProbeResult struct {
	URL          string            `json:"url"`
	ResolveTo    string            `json:"resolveTo"`
	Method       string            `json:"method"`
	OK           bool              `json:"ok"`
	Status       *int              `json:"status"`
	ExpectStatus []int             `json:"expectStatus"`
	StatusMatch  bool              `json:"statusMatch"`
	LatencyMs    int64             `json:"latencyMs"`
	BodySha256   *string           `json:"bodySha256"`
	BodyBytes    int64             `json:"bytesRead"`
	Truncated    bool              `json:"truncated"`
	Headers      map[string]string `json:"headers"`
	RemoteAddr   string            `json:"remoteAddr,omitempty"`
	TLS          *TLSInfo          `json:"tls,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// reportedHeaders are the only response headers returned.
var reportedHeaders = []string{"Content-Type", "Content-Length", "Server", "Location", "Cache-Control", "Etag"}

// Prober runs http.probe.
type Prober struct {
	// Dial overrides the TCP dialer (tests). It is always called with the
	// resolveTo address, never with the URL host.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Roots overrides the system roots for the Verified flag (tests).
	Roots *x509.CertPool
}

// Run performs one GET/HEAD to p.ResolveTo:p.Port with Host/SNI = the URL
// host, no proxy, no redirects, ≤ 1 MiB body read, 10 s overall. A transport
// failure is reported in the result (ok=false, error), not as a job failure.
func (pr *Prober) Run(ctx context.Context, p ProbeParams) *ProbeResult {
	target := netip.AddrPortFrom(p.ResolveTo, uint16(p.Port)).String()
	res := &ProbeResult{URL: p.URL, ResolveTo: p.ResolveTo.String(), Method: p.Method, ExpectStatus: p.ExpectStatus, Headers: map[string]string{}}
	if res.ExpectStatus == nil {
		res.ExpectStatus = []int{}
	}
	dial := pr.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	var tlsInfo *TLSInfo
	timeout := p.Timeout
	if timeout <= 0 || timeout > ProbeTimeout {
		timeout = ProbeTimeout
	}
	tr := &http.Transport{
		Proxy: nil,
		// Host/SNI override: whatever host:port net/http derives from the URL,
		// the connection goes to resolveTo only.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, "tcp", target)
		},
		TLSClientConfig:        pr.tlsConfig(p.Hostname, &tlsInfo),
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: maxHeaderSize,
		ResponseHeaderTimeout:  timeout,
		TLSHandshakeTimeout:    5 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var remote string
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if i.Conn != nil {
			remote = i.Conn.RemoteAddr().String()
		}
	}})
	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, nil)
	if err != nil {
		res.Error = "INVALID_REQUEST"
		return res
	}
	req.Header.Set("User-Agent", "ppanel-agent-probe/"+version.Version)
	req.Header.Set("Accept", "*/*")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.LatencyMs = time.Since(start).Milliseconds()
		res.Error = probeErr(err)
		res.TLS = tlsInfo
		return res
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, rerr := io.Copy(h, io.LimitReader(resp.Body, MaxProbeBody))
	res.LatencyMs = time.Since(start).Milliseconds()
	res.BodyBytes = n
	if n == MaxProbeBody {
		var one [1]byte
		if m, _ := resp.Body.Read(one[:]); m > 0 {
			res.Truncated = true
		}
	}
	res.BodySha256 = sum(h)
	st := resp.StatusCode
	res.Status = &st
	res.RemoteAddr = remote
	res.TLS = tlsInfo
	for _, k := range reportedHeaders {
		if v := resp.Header.Get(k); v != "" {
			if len(v) > 512 {
				v = v[:512]
			}
			res.Headers[k] = v
		}
	}
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		res.Error = probeErr(rerr)
	}
	res.StatusMatch = statusMatches(st, p.ExpectStatus)
	res.OK = res.Error == "" && res.StatusMatch
	return res
}

func sum(h hash.Hash) *string {
	s := hex.EncodeToString(h.Sum(nil))
	return &s
}

func statusMatches(st int, exp []int) bool {
	if len(exp) == 0 {
		return st >= 200 && st < 400
	}
	for _, e := range exp {
		if e == st {
			return true
		}
	}
	return false
}

func probeErr(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "TIMEOUT"
	}
	switch c := connpath.ClassifyError(err); c {
	case connpath.ErrConnFailed:
		return "HTTP_ERROR"
	default:
		return c
	}
}

func (pr *Prober) tlsConfig(serverName string, out **TLSInfo) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		// Verification is done (and reported) in VerifyConnection, never
		// enforced: the probe compares gateway vs. direct responses.
		InsecureSkipVerify: true, //nolint:gosec // reported, not trusted; no credentials are sent
		VerifyConnection: func(cs tls.ConnectionState) error {
			info := &TLSInfo{Version: tls.VersionName(cs.Version)}
			if len(cs.PeerCertificates) > 0 {
				leaf := cs.PeerCertificates[0]
				info.Subject = leaf.Subject.String()
				info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
				inter := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					inter.AddCert(c)
				}
				if _, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: pr.Roots, Intermediates: inter}); err != nil {
					info.VerifyError = truncate(err.Error(), 200)
				} else {
					info.Verified = true
				}
			}
			*out = info
			return nil
		},
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Describe returns a short description for logs.
func (r *ProbeResult) Describe() string {
	st := 0
	if r.Status != nil {
		st = *r.Status
	}
	return fmt.Sprintf("%s %s -> %d ok=%v %s", r.Method, r.URL, st, r.OK, r.Error)
}
