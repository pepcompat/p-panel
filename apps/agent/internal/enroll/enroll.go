// Package enroll implements one-time agent enrollment (AGENT_PROTOCOL.md §Enrollment).
package enroll

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
	"github.com/ppanel/ppanel/apps/agent/internal/facts"
	"github.com/ppanel/ppanel/apps/agent/internal/provider"
	"github.com/ppanel/ppanel/apps/agent/internal/sshkeys"
	"github.com/ppanel/ppanel/apps/agent/internal/state"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

// InsecureEnv enables plain-HTTP enrollment for local development only.
const InsecureEnv = "PPANEL_DEV_INSECURE_ENROLL"

var tokenRe = regexp.MustCompile(`^ppe_[A-Za-z0-9_-]{16,128}$`)

// Options configure enrollment.
type Options struct {
	CenterURL string
	Token     string
	StateDir  string
	// CAFile optionally pins the CA for the Center API TLS endpoint (else system roots).
	CAFile string
	// Force re-enrollment when an identity already exists.
	Force bool
	// HTTPClient overrides the client (tests).
	HTTPClient *http.Client
	// Provider returns the P9 provider fact (nil func or nil result = null).
	Provider func(ctx context.Context) *provider.Info
	// SSHFacts returns the P10 ssh fact (nil func or nil result = null).
	SSHFacts func() *sshkeys.Facts
}

// Request is the enrollment request body.
type Request struct {
	Token    string      `json:"token"`
	CSRPem   string      `json:"csrPem"`
	Hostname string      `json:"hostname"`
	Facts    facts.Facts `json:"facts"`
}

// Response is the enrollment response data.
type Response struct {
	ServerID             string `json:"serverId"`
	CertificatePem       string `json:"certificatePem"`
	CAPem                string `json:"caPem"`
	GatewayURL           string `json:"gatewayUrl"`
	HeartbeatIntervalSec int    `json:"heartbeatIntervalSec"`
	// GatewayEndpoints (P9) lists every advertised management path; absent
	// from older Centers (gatewayUrl alone = the public path).
	GatewayEndpoints []connpath.Endpoint `json:"gatewayEndpoints,omitempty"`
}

// ValidateCenterURL enforces https unless PPANEL_DEV_INSECURE_ENROLL=1.
func ValidateCenterURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid center URL %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("center URL must not contain credentials, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if os.Getenv(InsecureEnv) != "1" {
			return nil, fmt.Errorf("refusing plain-HTTP enrollment; set %s=1 for local development only", InsecureEnv)
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// Run performs enrollment and persists the identity. The private key is
// generated locally, written 0600 and never sent.
func Run(ctx context.Context, o Options) (*state.Identity, error) {
	u, err := ValidateCenterURL(o.CenterURL)
	if err != nil {
		return nil, err
	}
	if !tokenRe.MatchString(o.Token) {
		return nil, errors.New("enrollment token has an invalid format (expected ppe_...)")
	}
	dir := state.Dir{Path: o.StateDir}
	if dir.Enrolled() && !o.Force {
		return nil, fmt.Errorf("already enrolled (state in %s); use --force to re-enroll", o.StateDir)
	}
	if err := dir.Ensure(); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	key, err := state.GenerateKey()
	if err != nil {
		return nil, err
	}
	host := facts.Hostname()
	csr, err := state.CreateCSR(key, host)
	if err != nil {
		return nil, err
	}
	hc := o.HTTPClient
	if hc == nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("ca file contains no certificates")
			}
			tlsCfg.RootCAs = pool
		}
		hc = transport.NewHTTPClient(tlsCfg, 30*time.Second)
	}
	cl := &transport.Client{BaseURL: u.String(), HTTP: hc}
	req := Request{Token: o.Token, CSRPem: string(csr), Hostname: host,
		Facts: facts.Facts{OS: facts.Collect(), AgentVersion: version.Version}}
	if o.Provider != nil {
		req.Facts.Provider = o.Provider(ctx)
	}
	if o.SSHFacts != nil {
		req.Facts.SSH = o.SSHFacts()
	}
	var resp Response
	if err := cl.Do(ctx, http.MethodPost, "/api/v1/agent/enroll", req, &resp); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if err := verifyResponse(&resp, key); err != nil {
		return nil, err
	}
	// Persist: key first (0600), then cert/CA, identity last (marks completion).
	if err := dir.SaveKey(key); err != nil {
		return nil, err
	}
	if err := dir.WriteFileAtomic(state.CertFile, []byte(resp.CertificatePem), 0o644); err != nil {
		return nil, err
	}
	if err := dir.WriteFileAtomic(state.CAFile, []byte(resp.CAPem), 0o644); err != nil {
		return nil, err
	}
	id := &state.Identity{ServerID: resp.ServerID, GatewayURL: strings.TrimRight(resp.GatewayURL, "/"),
		HeartbeatIntervalSec: resp.HeartbeatIntervalSec, EnrolledAt: time.Now().UTC()}
	// P9: fresh management-path state (replaces any state of a previous enrollment).
	if err := connpath.SaveEnrollment(o.StateDir, id.GatewayURL, resp.GatewayEndpoints); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if err := dir.SaveIdentity(id); err != nil {
		return nil, err
	}
	return id, nil
}

func verifyResponse(r *Response, key crypto.Signer) error {
	if r.ServerID == "" || r.CertificatePem == "" || r.CAPem == "" || r.GatewayURL == "" {
		return errors.New("enroll: incomplete response from center")
	}
	gu, err := url.Parse(r.GatewayURL)
	if err != nil || gu.Scheme != "https" || gu.Host == "" {
		return fmt.Errorf("enroll: gatewayUrl must be https, got %q", r.GatewayURL)
	}
	if len(r.GatewayEndpoints) > 0 {
		if _, err := connpath.ValidateEndpoints(r.GatewayEndpoints); err != nil {
			return fmt.Errorf("enroll: gatewayEndpoints: %w", err)
		}
	}
	leaf, err := state.ParseCert([]byte(r.CertificatePem))
	if err != nil {
		return fmt.Errorf("enroll: certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(r.CAPem)) {
		return errors.New("enroll: caPem has no certificates")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("enroll: issued certificate does not chain to returned CA: %w", err)
	}
	if !publicKeyEqual(leaf.PublicKey, key.Public()) {
		return errors.New("enroll: issued certificate does not match our private key")
	}
	return nil
}

func publicKeyEqual(a, b any) bool {
	type eq interface{ Equal(x crypto.PublicKey) bool }
	ea, ok := a.(eq)
	return ok && ea.Equal(b)
}
