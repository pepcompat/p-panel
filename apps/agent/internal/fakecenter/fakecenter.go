// Package fakecenter is an in-process fake pPanel Center (enrollment API +
// mTLS Agent Gateway) used ONLY by tests. It follows docs/AGENT_PROTOCOL.md.
package fakecenter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewCA creates a self-signed ECDSA P-256 CA.
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: k, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Pool returns a pool containing the CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// ServerCert issues a TLS server cert for localhost/127.0.0.1.
func (ca *CA) ServerCert(t testing.TB) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &k.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// SignCSR verifies a P-256 CSR and issues an agent leaf (Center ignores CSR subject).
func (ca *CA) SignCSR(csrPEM, serverID string, validity time.Duration, notBefore time.Time) ([]byte, *x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("bad csr pem")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}
	pk, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, nil, errors.New("csr must be ECDSA P-256")
	}
	u, _ := url.Parse("ppanel://agent/" + serverID)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "agent:" + serverID},
		NotBefore: notBefore, NotAfter: notBefore.Add(validity), URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pk, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	c, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c, nil
}

// Center is the fake.
type Center struct {
	t        testing.TB
	CA       *CA
	ServerID string
	// LeafValidity / LeafNotBefore control issued certs (rotation tests).
	LeafValidity  time.Duration
	LeafNotBefore func() time.Time

	mu           sync.Mutex
	tokens       map[string]bool // sha256(token) -> used
	EnrollBodies [][]byte
	Heartbeats   []map[string]any
	PeerCNs      []string
	PeerSerials  []string
	Acks         []string
	Results      map[string][]map[string]any
	Rotations    int
	tasks        chan []map[string]any
	AckStatus    int // if non-zero, ack responds with this status
	RenewAfter   *time.Time

	enrollSrv  *http.Server
	EnrollURL  string
	gwSrv      *http.Server
	gwAddr     string
	gwCert     tls.Certificate
	GatewayURL string
}

// New creates a fake center with enrollment (plain HTTP or TLS) and a gateway.
func New(t testing.TB, serverID string) *Center {
	c := &Center{t: t, CA: NewCA(t, "pPanel Test Agent CA"), ServerID: serverID, tokens: map[string]bool{},
		Results: map[string][]map[string]any{}, tasks: make(chan []map[string]any, 100),
		LeafValidity: 7 * 24 * time.Hour, LeafNotBefore: func() time.Time { return time.Now().Add(-time.Minute) }}
	c.gwCert = c.CA.ServerCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.gwAddr = ln.Addr().String()
	c.GatewayURL = "https://" + c.gwAddr
	c.startGatewayOn(ln)
	t.Cleanup(c.Close)
	return c
}

// AddToken registers a one-time enrollment token.
func (c *Center) AddToken(tok string) {
	h := sha256.Sum256([]byte(tok))
	c.mu.Lock()
	c.tokens[string(h[:])] = false
	c.mu.Unlock()
}

// StartEnrollHTTP starts the enrollment API over plain HTTP (dev-insecure path).
func (c *Center) StartEnrollHTTP() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.t.Fatal(err)
	}
	c.enrollSrv = &http.Server{Handler: http.HandlerFunc(c.handleEnroll)}
	go c.enrollSrv.Serve(ln)
	c.EnrollURL = "http://" + ln.Addr().String()
	return c.EnrollURL
}

// StartEnrollTLS starts the enrollment API over TLS (server cert from the test CA).
func (c *Center) StartEnrollTLS() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.t.Fatal(err)
	}
	c.enrollSrv = &http.Server{Handler: http.HandlerFunc(c.handleEnroll),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{c.gwCert}}}
	go c.enrollSrv.Serve(tls.NewListener(ln, c.enrollSrv.TLSConfig))
	c.EnrollURL = "https://" + ln.Addr().String()
	return c.EnrollURL
}

func writeOK(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"success": true, "statusCode": 0, "message": "ok", "data": data, "meta": map[string]any{"requestId": "test"}})
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg}, "meta": map[string]any{"requestId": "test"}})
}

func (c *Center) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/enroll" {
		writeErr(w, 404, "NOT_FOUND", "not found")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		Token, CsrPem, Hostname string
		Facts                   map[string]any
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", err.Error())
		return
	}
	h := sha256.Sum256([]byte(req.Token))
	c.mu.Lock()
	c.EnrollBodies = append(c.EnrollBodies, body)
	used, ok := c.tokens[string(h[:])]
	if !ok || used {
		c.mu.Unlock()
		writeErr(w, 401, "ENROLLMENT_TOKEN_INVALID", "enrollment token invalid")
		return
	}
	c.tokens[string(h[:])] = true
	c.mu.Unlock()
	certPEM, _, err := c.CA.SignCSR(req.CsrPem, c.ServerID, c.LeafValidity, c.LeafNotBefore())
	if err != nil {
		writeErr(w, 422, "CSR_INVALID", err.Error())
		return
	}
	writeOK(w, 201, map[string]any{"serverId": c.ServerID, "certificatePem": string(certPEM), "caPem": string(c.CA.PEM),
		"gatewayUrl": c.GatewayURL, "heartbeatIntervalSec": 15})
}

func (c *Center) startGatewayOn(ln net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/heartbeat", c.handleHeartbeat)
	mux.HandleFunc("/agent/v1/tasks", c.handleTasks)
	mux.HandleFunc("/agent/v1/tasks/", c.handleTaskAction)
	mux.HandleFunc("/agent/v1/certificate/rotate", c.handleRotate)
	cfg := &tls.Config{Certificates: []tls.Certificate{c.gwCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: c.CA.Pool(), MinVersion: tls.VersionTLS12}
	srv := &http.Server{Handler: c.peerCheck(mux), TLSConfig: cfg}
	c.mu.Lock()
	c.gwSrv = srv
	c.mu.Unlock()
	go srv.Serve(tls.NewListener(ln, cfg))
}

func (c *Center) peerCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeErr(w, 401, "AGENT_CERT_REQUIRED", "client cert required")
			return
		}
		if r.Header.Get("X-Agent-Protocol") != "1" {
			writeErr(w, 426, "AGENT_PROTOCOL_UNSUPPORTED", "bad protocol")
			return
		}
		pc := r.TLS.PeerCertificates[0]
		c.mu.Lock()
		c.PeerCNs = append(c.PeerCNs, pc.Subject.CommonName)
		c.PeerSerials = append(c.PeerSerials, pc.SerialNumber.Text(16))
		c.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (c *Center) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb map[string]any
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		writeErr(w, 400, "BAD_REQUEST", err.Error())
		return
	}
	c.mu.Lock()
	c.Heartbeats = append(c.Heartbeats, hb)
	ra := c.RenewAfter
	c.mu.Unlock()
	data := map[string]any{"serverTime": time.Now().UTC().Format(time.RFC3339Nano), "heartbeatIntervalSec": 15}
	if ra != nil {
		data["certRenewAfter"] = ra.UTC().Format(time.RFC3339)
	}
	writeOK(w, 200, data)
}

// Enqueue makes the next long-poll return these grants.
func (c *Center) Enqueue(grants ...map[string]any) { c.tasks <- grants }

func (c *Center) handleTasks(w http.ResponseWriter, r *http.Request) {
	wait := 25 * time.Second
	if v := r.URL.Query().Get("waitSec"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil && d < wait {
			wait = d
		}
	}
	if wait > 300*time.Millisecond {
		wait = 300 * time.Millisecond // keep tests fast
	}
	select {
	case g := <-c.tasks:
		writeOK(w, 200, map[string]any{"tasks": g})
	case <-time.After(wait):
		writeOK(w, 200, map[string]any{"tasks": []any{}})
	case <-r.Context().Done():
	}
}

func (c *Center) handleTaskAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/agent/v1/tasks/")
	jobID, action, _ := strings.Cut(rest, "/")
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch action {
	case "ack":
		c.Acks = append(c.Acks, jobID)
		if c.AckStatus != 0 {
			writeErr(w, c.AckStatus, "TASK_EXPIRED", "expired")
			return
		}
		writeOK(w, 200, map[string]any{"status": "running"})
	case "result":
		c.Results[jobID] = append(c.Results[jobID], body)
		writeOK(w, 200, map[string]any{"accepted": true})
	default:
		writeErr(w, 404, "NOT_FOUND", "nf")
	}
}

func (c *Center) handleRotate(w http.ResponseWriter, r *http.Request) {
	var body struct{ CsrPem string }
	json.NewDecoder(r.Body).Decode(&body)
	certPEM, leaf, err := c.CA.SignCSR(body.CsrPem, c.ServerID, 7*24*time.Hour, time.Now().Add(-time.Minute))
	if err != nil {
		writeErr(w, 422, "CSR_INVALID", err.Error())
		return
	}
	c.mu.Lock()
	c.Rotations++
	c.RenewAfter = nil
	c.mu.Unlock()
	writeOK(w, 200, map[string]any{"certificatePem": string(certPEM), "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339)})
}

// StopGateway closes the gateway (simulated outage).
func (c *Center) StopGateway() {
	c.mu.Lock()
	srv := c.gwSrv
	c.mu.Unlock()
	srv.Close()
}

// StartGateway re-listens on the same address.
func (c *Center) StartGateway() {
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", c.gwAddr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		c.t.Fatal(err)
	}
	c.startGatewayOn(ln)
}

// Snapshot helpers (thread-safe).
func (c *Center) HeartbeatCount() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.Heartbeats) }
func (c *Center) AckCount() int       { c.mu.Lock(); defer c.mu.Unlock(); return len(c.Acks) }
func (c *Center) RotationCount() int  { c.mu.Lock(); defer c.mu.Unlock(); return c.Rotations }
func (c *Center) ResultsFor(id string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.Results[id]...)
}
func (c *Center) LastPeer() (cn, serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.PeerCNs) == 0 {
		return "", ""
	}
	return c.PeerCNs[len(c.PeerCNs)-1], c.PeerSerials[len(c.PeerSerials)-1]
}

// Close shuts everything down.
func (c *Center) Close() {
	c.mu.Lock()
	gw, en := c.gwSrv, c.enrollSrv
	c.mu.Unlock()
	if gw != nil {
		gw.Close()
	}
	if en != nil {
		en.Close()
	}
}

// Grant builds a TaskGrant map.
func (c *Center) Grant(jobID, typ string, params any, expiresIn time.Duration) map[string]any {
	now := time.Now().UTC()
	return map[string]any{"jobId": jobID, "type": typ, "params": params, "idempotencyKey": "idem-" + jobID,
		"issuedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(expiresIn).Format(time.RFC3339Nano),
		"leaseToken": "lease-" + jobID, "desiredVersion": nil, "serverId": c.ServerID}
}

// HeartbeatsCopy returns received heartbeat bodies.
func (c *Center) HeartbeatsCopy() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.Heartbeats...)
}
