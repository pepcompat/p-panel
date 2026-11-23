// Package transport is the HTTP(S) client used for enrollment and the mTLS
// Agent Gateway. It speaks the COMPATTANA response envelope.
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

// MaxResponseBytes bounds any response body read from Center.
const MaxResponseBytes = 16 << 20

// APIError is a non-2xx response decoded from the error envelope.
type APIError struct {
	HTTPStatus int
	Code       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("center HTTP %d %s: %s (requestId=%s)", e.HTTPStatus, e.Code, e.Message, e.RequestID)
}

// IsStatus reports whether err is an APIError with the given HTTP status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.HTTPStatus == status
}

// Code returns the error code of an APIError or "".
func Code(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

type envelope struct {
	Success *bool           `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Meta struct {
		RequestID string `json:"requestId"`
	} `json:"meta"`
}

// Client is a JSON-over-HTTPS client.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewUUID returns a random RFC 4122 v4 UUID for X-Request-ID.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Do sends method path with JSON body and decodes envelope.data into out.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Request-ID", NewUUID())
	req.Header.Set("X-Client-Version", version.Version)
	req.Header.Set("X-Agent-Protocol", version.ProtocolVersion)
	req.Header.Set("User-Agent", "ppanel-agent/"+version.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxResponseBytes {
		return errors.New("center response too large")
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{HTTPStatus: resp.StatusCode, RequestID: env.Meta.RequestID, Code: "HTTP_" + fmt.Sprint(resp.StatusCode)}
		if env.Error != nil {
			ae.Code, ae.Message = env.Error.Code, env.Error.Message
		}
		return ae
	}
	if out == nil || resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	data := env.Data
	if env.Success == nil && len(data) == 0 {
		// Tolerate a bare (non-enveloped) JSON body.
		data = raw
	}
	if len(data) == 0 {
		return errors.New("center response missing data")
	}
	return json.Unmarshal(data, out)
}

// CertSource holds the current client certificate; swapped atomically on rotation.
type CertSource struct {
	p atomic.Pointer[tls.Certificate]
}

// Set replaces the current certificate.
func (s *CertSource) Set(c tls.Certificate) { s.p.Store(&c) }

// Get returns the current certificate.
func (s *CertSource) Get() *tls.Certificate { return s.p.Load() }

// MTLSConfig builds a client TLS config pinned to the pPanel CA only (no
// system roots), presenting the certificate from src.
func MTLSConfig(ca *x509.CertPool, src *CertSource) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    ca,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := src.Get()
			if c == nil {
				return nil, errors.New("no client certificate loaded")
			}
			return c, nil
		},
	}
}

// NewHTTPClient builds an http.Client for tlsCfg. timeout should exceed the long-poll wait.
func NewHTTPClient(tlsCfg *tls.Config, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
		Proxy:                 http.ProxyFromEnvironment,
	}
	return &http.Client{Transport: tr, Timeout: timeout + 5*time.Second}
}

// RegistryAuth is a registry credential delivered with job secrets.
type RegistryAuth struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ServerAddress string `json:"serveraddress"`
}

// JobSecrets is the one-time secrets payload of POST /agent/v1/tasks/:jobId/secrets.
// Values must only ever live in memory: never log, persist or return them.
type JobSecrets struct {
	Env          map[string]string `json:"env"`
	RegistryAuth *RegistryAuth     `json:"registryAuth,omitempty"`
	// GitAuth is the git HTTP auth header for image.build / source.inspect with
	// source.auth=true (e.g. "Authorization: Basic …"). Passed to git via env only.
	GitAuth *GitAuth `json:"gitAuth,omitempty"`
}

// GitAuth carries one HTTP header line for git (http.extraHeader).
type GitAuth struct {
	Header string `json:"header"`
}

// FetchJobSecrets performs the one-time secrets fetch for a leased job. The
// Center answers 409 SECRETS_ALREADY_FETCHED on a second call.
func (c *Client) FetchJobSecrets(ctx context.Context, jobID, leaseToken string) (*JobSecrets, error) {
	if jobID == "" || leaseToken == "" {
		return nil, errors.New("secrets fetch needs jobId and leaseToken")
	}
	var out JobSecrets
	path := "/agent/v1/tasks/" + url.PathEscape(jobID) + "/secrets"
	if err := c.Do(ctx, http.MethodPost, path, map[string]string{"leaseToken": leaseToken}, &out); err != nil {
		return nil, err
	}
	if out.Env == nil {
		out.Env = map[string]string{}
	}
	return &out, nil
}
