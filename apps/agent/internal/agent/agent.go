// Package agent implements the post-enrollment run loop: mTLS heartbeat,
// long-poll task grants, ack, typed dispatch, result delivery and certificate
// rotation (docs/AGENT_PROTOCOL.md).
//
// Invariant: connectivity problems never touch workloads. The only code path
// that can affect the host is a typed handler invoked for a validated grant.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/connpath"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/logship"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/netaddr"
	"github.com/ppanel/ppanel/apps/agent/internal/provider"
	"github.com/ppanel/ppanel/apps/agent/internal/state"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

// Options configure an Agent. Zero values get production defaults.
type Options struct {
	Config     *config.Config
	Registry   *jobs.Registry
	Host       *host.Env
	Sampler    *metrics.Sampler
	Logger     *slog.Logger
	BackoffMin time.Duration // default 1s
	BackoffMax time.Duration // default 60s
	// MinPollGap throttles a gateway that answers long-polls instantly (default 1s).
	MinPollGap time.Duration
	// HeartbeatInterval overrides the interval (tests); 0 = config/Center.
	HeartbeatInterval time.Duration
	// MaxConcurrentJobs bounds parallel handler executions (default 4).
	MaxConcurrentJobs int
	// Now overrides the clock (tests).
	Now func() time.Time
	// Containers reports managed containers in the heartbeat (P5); nil = omitted.
	Containers *logship.Collector
	// Logs is the P5 log pipeline (shipped over the gateway); nil = disabled.
	Logs *logship.Pipeline
	// Provider returns the P9 provider fact (DigitalOcean metadata); nil =
	// the heartbeat carries no provider field.
	Provider func(ctx context.Context) *provider.Info
	// ProviderRefresh is how often Provider is re-read (default 10 min).
	ProviderRefresh time.Duration
	// ProbeInterval is the P9 endpoint probe cadence (default 60 s).
	ProbeInterval time.Duration
	// Prober overrides the endpoint prober (tests).
	Prober func(ctx context.Context, ep connpath.Endpoint) connpath.ProbeResult
}

// Agent is a running agent instance.
type Agent struct {
	o        Options
	cfg      *config.Config
	log      *slog.Logger
	dir      state.Dir
	id       *state.Identity
	reg      *jobs.Registry
	cache    *jobs.Cache
	outbox   *Outbox
	certs    transport.CertSource
	leaf     atomic.Pointer[x509.Certificate]
	ca       *x509.CertPool
	client   *transport.Client
	hc       *http.Client
	sem      chan struct{}
	wg       sync.WaitGroup
	seq      atomic.Uint64
	hbEvery  atomic.Int64 // nanoseconds
	renewAt  atomic.Pointer[time.Time]
	skew     atomic.Int64 // serverTime - localTime, ns
	running  sync.Map     // jobId -> struct{}
	lastRot  atomic.Int64 // unix nanos of last rotation attempt
	capsMu   sync.Mutex
	caps     []string
	capsAt   time.Time
	hbOK     atomic.Uint64
	hbFail   atomic.Uint64
	executed atomic.Uint64
	conn     *connpath.Manager
	prov     atomic.Pointer[json.RawMessage]
}

// New loads identity/TLS from cfg.StateDir and prepares the agent.
func New(o Options) (*Agent, error) {
	if o.Config == nil || o.Registry == nil || o.Host == nil {
		return nil, errors.New("agent: Config, Registry and Host are required")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Sampler == nil {
		o.Sampler = &metrics.Sampler{}
	}
	if o.BackoffMin <= 0 {
		o.BackoffMin = time.Second
	}
	if o.BackoffMax <= 0 {
		o.BackoffMax = 60 * time.Second
	}
	if o.MinPollGap <= 0 {
		o.MinPollGap = time.Second
	}
	if o.MaxConcurrentJobs <= 0 {
		o.MaxConcurrentJobs = 4
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	a := &Agent{o: o, cfg: o.Config, log: o.Logger, dir: state.Dir{Path: o.Config.StateDir}, reg: o.Registry,
		outbox: NewOutbox(o.Config.MaxBufferedResults), sem: make(chan struct{}, o.MaxConcurrentJobs)}
	if err := RecoverRotation(a.dir); err != nil {
		return nil, err
	}
	id, err := a.dir.LoadIdentity()
	if err != nil {
		return nil, fmt.Errorf("not enrolled (%v); run `ppanel-agent enroll` first", err)
	}
	gu, err := url.Parse(id.GatewayURL)
	if err != nil || gu.Scheme != "https" {
		return nil, fmt.Errorf("identity gatewayUrl must be https: %q", id.GatewayURL)
	}
	a.id = id
	kp, pool, leaf, err := a.dir.LoadTLS()
	if err != nil {
		return nil, err
	}
	a.ca = pool
	a.certs.Set(kp)
	a.leaf.Store(leaf)
	if id.CertRenewAfter != nil {
		t := *id.CertRenewAfter
		a.renewAt.Store(&t)
	}
	a.cache, err = jobs.OpenCache(a.dir.FilePath(state.JobCacheFile), jobs.DefaultCacheSize)
	if err != nil {
		return nil, err
	}
	a.reportInterrupted()
	if o.ProbeInterval <= 0 {
		o.ProbeInterval = 60 * time.Second
	}
	if o.ProviderRefresh <= 0 {
		o.ProviderRefresh = 10 * time.Minute
	}
	a.o = o
	pollTimeout := time.Duration(o.Config.PollWaitSec+10) * time.Second
	mtls := transport.MTLSConfig(pool, &a.certs)
	a.hc = transport.NewHTTPClient(mtls, pollTimeout)
	probe := o.Prober
	if probe == nil {
		probe = (&connpath.Prober{TLS: func() *tls.Config { return mtls }}).Probe
	}
	// P9: management paths (connection.json; falls back to gatewayUrl = public).
	a.conn, err = connpath.Load(connpath.Options{StateDir: o.Config.StateDir, FallbackURL: id.GatewayURL, Probe: probe,
		Log: o.Logger.With("component", "connection")})
	if err != nil {
		return nil, err
	}
	a.conn.SetOnSwitch(func(string, string) { a.hc.CloseIdleConnections() })
	a.client = &transport.Client{HTTP: a.hc, Base: a.conn.BaseURL, Observe: a.conn.Observe}
	iv := time.Duration(o.Config.HeartbeatIntervalSec) * time.Second
	if id.HeartbeatIntervalSec > 0 {
		iv = time.Duration(id.HeartbeatIntervalSec) * time.Second
	}
	if o.HeartbeatInterval > 0 {
		iv = o.HeartbeatInterval
	}
	a.hbEvery.Store(int64(iv))
	return a, nil
}

// FetchJobSecrets performs the one-time secrets fetch for the job running in
// ctx (jobId + leaseToken attached by execute). Used by container.run_candidate.
func (a *Agent) FetchJobSecrets(ctx context.Context) (*transport.JobSecrets, error) {
	return a.client.FetchJobSecrets(ctx, jobs.JobID(ctx), jobs.LeaseToken(ctx))
}

// ServerID returns the enrolled server id.
func (a *Agent) ServerID() string { return a.id.ServerID }

// Conn returns the P9 management-path manager.
func (a *Agent) Conn() *connpath.Manager { return a.conn }

func (a *Agent) refreshProvider(ctx context.Context) {
	if a.o.Provider == nil {
		return
	}
	b, err := json.Marshal(a.o.Provider(ctx))
	if err != nil {
		return
	}
	raw := json.RawMessage(b)
	a.prov.Store(&raw)
}

func (a *Agent) providerLoop(ctx context.Context) {
	for sleep(ctx, a.o.ProviderRefresh) {
		a.refreshProvider(ctx)
	}
}

// Stats is a snapshot of counters (tests/diagnostics).
type Stats struct {
	HeartbeatsOK, HeartbeatsFailed, Executed uint64
	OutboxLen                                int
	OutboxDropped                            uint64
}

// Stats returns counters.
func (a *Agent) Stats() Stats {
	return Stats{a.hbOK.Load(), a.hbFail.Load(), a.executed.Load(), a.outbox.Len(), a.outbox.Dropped()}
}

func (a *Agent) now() time.Time { return a.o.Now().Add(time.Duration(a.skew.Load())) }

// Run blocks until ctx is cancelled. In-flight handlers get a grace period.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent starting", "serverId", a.id.ServerID, "gateway", a.id.GatewayURL, "version", version.Version,
		"handlers", a.reg.Types(), "endpoints", len(a.conn.Endpoints()), "policy", a.conn.Policy())
	// P9: provider facts and a first endpoint probe before the first heartbeat
	// (both bounded: 2 s metadata timeout, 5 s probe timeout, run in parallel).
	var pre sync.WaitGroup
	pre.Add(2)
	go func() { defer pre.Done(); a.refreshProvider(ctx) }()
	go func() { defer pre.Done(); a.conn.ProbeAll(ctx) }()
	pre.Wait()
	var loops sync.WaitGroup
	loopsFns := []func(context.Context){a.heartbeatLoop, a.pollLoop, a.resultLoop,
		func(ctx context.Context) { a.conn.Run(ctx, a.o.ProbeInterval) }}
	if a.o.Provider != nil {
		loopsFns = append(loopsFns, a.providerLoop)
	}
	if a.o.Logs != nil {
		loopsFns = append(loopsFns, func(ctx context.Context) { a.o.Logs.Run(ctx, a.SendLogs) })
	}
	for _, f := range loopsFns {
		loops.Add(1)
		go func(f func(context.Context)) { defer loops.Done(); f(ctx) }(f)
	}
	<-ctx.Done()
	loops.Wait()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		a.log.Warn("shutdown: in-flight jobs still running after grace period")
	}
	a.hc.CloseIdleConnections()
	a.log.Info("agent stopped")
	return nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// fatalish errors where retrying fast is pointless: back off to the max.
func (a *Agent) delayFor(err error, b *Backoff) time.Duration {
	switch transport.Code(err) {
	case "AGENT_CERT_REVOKED", "AGENT_PROTOCOL_UNSUPPORTED":
		return b.Max
	}
	return b.Next()
}

// ---------------- heartbeat ----------------

// HeartbeatRequest is the heartbeat body.
type HeartbeatRequest struct {
	Seq           uint64            `json:"seq"`
	SentAt        string            `json:"sentAt"`
	AgentVersion  string            `json:"agentVersion"`
	Metrics       metrics.Snapshot  `json:"metrics"`
	Addresses     []netaddr.Address `json:"addresses"`
	Capabilities  []string          `json:"capabilities"`
	RunningJobIDs []string          `json:"runningJobIds"`
	// P5 (omitted when unknown/disabled)
	Containers  *[]logship.ContainerStat `json:"containers,omitempty"`
	LogShipping *logship.ShippingStatus  `json:"logShipping,omitempty"`
	// P9: management-path probe report and provider fact (null = absent).
	Connection *connpath.Report `json:"connection,omitempty"`
	Provider   json.RawMessage  `json:"provider,omitempty"`
}

// SendLogs POSTs one gzip batch to /agent/v1/logs over the mTLS gateway.
func (a *Agent) SendLogs(ctx context.Context, gz []byte) error {
	return a.client.PostGzip(ctx, "/agent/v1/logs", gz, nil)
}

// HeartbeatResponse is the heartbeat response data.
type HeartbeatResponse struct {
	ServerTime           *time.Time `json:"serverTime"`
	HeartbeatIntervalSec int        `json:"heartbeatIntervalSec"`
	CertRenewAfter       *time.Time `json:"certRenewAfter"`
	// Connection (P9) is the server's policy and advertised endpoints.
	Connection *connpath.Block `json:"connection"`
}

func (a *Agent) capabilities() []string {
	a.capsMu.Lock()
	defer a.capsMu.Unlock()
	if a.caps == nil || time.Since(a.capsAt) > 5*time.Minute {
		a.caps = a.o.Host.Capabilities()
		a.capsAt = time.Now()
	}
	return append([]string(nil), a.caps...)
}

func (a *Agent) runningIDs() []string {
	ids := []string{}
	a.running.Range(func(k, _ any) bool { ids = append(ids, k.(string)); return true })
	sort.Strings(ids)
	return ids
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	b := &Backoff{Min: a.o.BackoffMin, Max: a.o.BackoffMax}
	for ctx.Err() == nil {
		err := a.heartbeat(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.hbFail.Add(1)
			d := a.delayFor(err, b)
			a.log.Warn("heartbeat failed", "error", err.Error(), "retryIn", d.String(), "attempt", b.Attempts())
			if !sleep(ctx, d) {
				return
			}
			continue
		}
		if b.Attempts() > 0 {
			a.log.Info("heartbeat recovered", "afterAttempts", b.Attempts())
		}
		b.Reset()
		a.hbOK.Add(1)
		a.maybeRotate(ctx)
		if !sleep(ctx, time.Duration(a.hbEvery.Load())) {
			return
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context) error {
	req := HeartbeatRequest{
		Seq: a.seq.Add(1), SentAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: version.Version,
		Metrics: a.o.Sampler.Sample(), Addresses: netaddr.Detect(), Capabilities: a.capabilities(),
		RunningJobIDs: a.runningIDs(),
	}
	// Encode empty collections as [] (never null) and whole-second uptime, per the protocol.
	if req.Addresses == nil {
		req.Addresses = []netaddr.Address{}
	}
	if req.Capabilities == nil {
		req.Capabilities = []string{}
	}
	if req.RunningJobIDs == nil {
		req.RunningJobIDs = []string{}
	}
	if a.o.Containers != nil {
		req.Containers = a.o.Containers.Collect(ctx)
	}
	if a.o.Logs != nil {
		req.LogShipping = a.o.Logs.Status()
	}
	req.Connection = a.conn.Report()
	if p := a.prov.Load(); p != nil {
		req.Provider = *p
	}
	if u := req.Metrics.UptimeSec; u != nil {
		v := math.Floor(*u)
		req.Metrics.UptimeSec = &v
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var resp HeartbeatResponse
	if err := a.client.Do(ctx, http.MethodPost, "/agent/v1/heartbeat", req, &resp); err != nil {
		return err
	}
	if resp.HeartbeatIntervalSec >= 5 && resp.HeartbeatIntervalSec <= 300 && a.o.HeartbeatInterval == 0 {
		a.hbEvery.Store(int64(time.Duration(resp.HeartbeatIntervalSec) * time.Second))
	}
	if resp.ServerTime != nil {
		a.skew.Store(int64(resp.ServerTime.Sub(a.o.Now())))
	}
	if resp.CertRenewAfter != nil {
		t := *resp.CertRenewAfter
		a.renewAt.Store(&t)
	}
	a.conn.Apply(resp.Connection)
	return nil
}

// ---------------- certificate rotation ----------------

type rotateRequest struct {
	CSRPem string `json:"csrPem"`
}

type rotateResponse struct {
	CertificatePem string    `json:"certificatePem"`
	NotAfter       time.Time `json:"notAfter"`
}

func (a *Agent) maybeRotate(ctx context.Context) {
	leaf := a.leaf.Load()
	if !state.RenewDue(leaf, a.renewAt.Load(), a.now()) {
		return
	}
	// at most one attempt per 10 minutes
	if last := a.lastRot.Load(); last != 0 && time.Since(time.Unix(0, last)) < 10*time.Minute {
		return
	}
	a.lastRot.Store(time.Now().UnixNano())
	if err := a.Rotate(ctx); err != nil {
		a.log.Error("certificate rotation failed; will retry", "error", err.Error(), "notAfter", leaf.NotAfter)
	}
}

// Rotate obtains a new certificate for a freshly generated key.
func (a *Agent) Rotate(ctx context.Context) error {
	key, err := state.GenerateKey()
	if err != nil {
		return err
	}
	csr, err := state.CreateCSR(key, a.id.ServerID)
	if err != nil {
		return err
	}
	var resp rotateResponse
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.client.Do(ctx, http.MethodPost, "/agent/v1/certificate/rotate", rotateRequest{CSRPem: string(csr)}, &resp); err != nil {
		return err
	}
	leaf, err := state.ParseCert([]byte(resp.CertificatePem))
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.ca, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("rotated certificate does not chain to pinned CA: %w", err)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return errors.New("rotated certificate does not match new key")
	}
	keyPEM, err := state.EncodeKey(key)
	if err != nil {
		return err
	}
	// two-phase persist: *.new then rename key, rename cert (RecoverRotation completes a crash in between)
	if err := a.dir.WriteFileAtomic(state.KeyFile+".new", keyPEM, 0o600); err != nil {
		return err
	}
	if err := a.dir.WriteFileAtomic(state.CertFile+".new", []byte(resp.CertificatePem), 0o644); err != nil {
		return err
	}
	if err := RecoverRotation(a.dir); err != nil {
		return err
	}
	kp, err := tls.X509KeyPair([]byte(resp.CertificatePem), keyPEM)
	if err != nil {
		return err
	}
	kp.Leaf = leaf
	a.certs.Set(kp)
	a.leaf.Store(leaf)
	a.renewAt.Store(nil)
	a.id.CertRenewAfter = nil
	_ = a.dir.SaveIdentity(a.id)
	a.hc.CloseIdleConnections()
	a.log.Info("certificate rotated", "serial", leaf.SerialNumber.Text(16), "notAfter", leaf.NotAfter)
	return nil
}

// RecoverRotation completes an interrupted two-phase key/cert swap.
func RecoverRotation(d state.Dir) error {
	keyNew, certNew := d.FilePath(state.KeyFile+".new"), d.FilePath(state.CertFile+".new")
	hasKey, hasCert := exists(keyNew), exists(certNew)
	switch {
	case hasKey && hasCert:
		if err := rename(keyNew, d.FilePath(state.KeyFile)); err != nil {
			return err
		}
		return rename(certNew, d.FilePath(state.CertFile))
	case hasCert && !hasKey:
		// key already swapped; finish with the cert
		return rename(certNew, d.FilePath(state.CertFile))
	case hasKey && !hasCert:
		// cert never written: discard the orphan key, keep the old pair
		return remove(keyNew)
	}
	return nil
}

// ---------------- task polling & dispatch ----------------

type tasksResponse struct {
	Tasks []*jobs.Grant `json:"tasks"`
}

func (a *Agent) pollLoop(ctx context.Context) {
	b := &Backoff{Min: a.o.BackoffMin, Max: a.o.BackoffMax}
	for ctx.Err() == nil {
		start := time.Now()
		var resp tasksResponse
		err := a.client.Do(ctx, http.MethodGet, fmt.Sprintf("/agent/v1/tasks?waitSec=%d", a.cfg.PollWaitSec), nil, &resp)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d := a.delayFor(err, b)
			a.log.Warn("task poll failed", "error", err.Error(), "retryIn", d.String())
			if !sleep(ctx, d) {
				return
			}
			continue
		}
		b.Reset()
		if len(resp.Tasks) > 50 {
			a.log.Warn("gateway returned oversized task batch; truncating", "count", len(resp.Tasks))
			resp.Tasks = resp.Tasks[:50]
		}
		for _, g := range resp.Tasks {
			if g == nil {
				continue
			}
			a.dispatch(ctx, g)
		}
		if len(resp.Tasks) == 0 {
			if gap := a.o.MinPollGap - time.Since(start); gap > 0 && !sleep(ctx, gap) {
				return
			}
		}
	}
}

// reportInterrupted posts AGENT_INTERRUPTED for every job a previous agent
// process started but never completed (it died mid-job). The result carries
// the lease token persisted at start; if the lease is already gone the Center
// answers 409 TASK_EXPIRED and resultLoop drops it. Entries without a token
// (written by older agents) are left for ReplayResult on re-delivery.
func (a *Agent) reportInterrupted() {
	for _, e := range a.cache.Interrupted() {
		if e.LeaseToken == "" {
			continue
		}
		r := &jobs.Result{JobID: e.JobID, LeaseToken: e.LeaseToken, Status: "failed",
			Error: jobs.Errorf(jobs.AgentInterrupted, "the agent stopped while this job was running (started %s); it did not complete and will not be re-executed",
				e.At.UTC().Format(time.RFC3339))}
		if err := a.cache.Complete(r); err != nil {
			a.log.Error("persist interrupted-job result failed", "jobId", e.JobID, "error", err.Error())
		}
		a.log.Warn("reporting job interrupted by an agent restart", "jobId", e.JobID, "startedAt", e.At)
		a.outbox.Push(r)
	}
}

// dispatch handles one grant; execution happens asynchronously (bounded).
func (a *Agent) dispatch(ctx context.Context, g *jobs.Grant) {
	log := a.log.With("jobId", g.JobID, "type", g.Type)
	if g.JobID == "" {
		log.Warn("ignoring grant without jobId")
		return
	}
	if _, busy := a.running.Load(g.JobID); busy {
		log.Info("grant for in-flight job ignored")
		return
	}
	// 1. never re-execute a known jobId
	if e, ok := a.cache.Lookup(g.JobID); ok {
		log.Info("duplicate jobId: replaying cached result, not executing", "state", e.State)
		a.outbox.Push(e.ReplayResult(g.JobID, g.LeaseToken))
		return
	}
	// 2. validate before any side effect
	h, params, rej := a.reg.Validate(g, a.id.ServerID, a.now())
	if rej != nil {
		log.Warn("grant rejected", "code", rej.Code, "reason", rej.Message)
		r := &jobs.Result{JobID: g.JobID, LeaseToken: g.LeaseToken, Status: "failed", Output: nil, Error: rej}
		if err := a.cache.Complete(r); err != nil {
			log.Error("persist rejection failed", "error", err.Error())
		}
		a.outbox.Push(r)
		return
	}
	// 3. ack (lease confirmation); on any failure do not execute
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := a.client.Do(actx, http.MethodPost, "/agent/v1/tasks/"+url.PathEscape(g.JobID)+"/ack", map[string]string{"leaseToken": g.LeaseToken}, nil)
	cancel()
	if err != nil {
		log.Warn("ack failed; job not executed", "error", err.Error(), "code", transport.Code(err))
		return
	}
	// 4. durably mark started BEFORE executing (crash => never re-run)
	fresh, err := a.cache.MarkStarted(g.JobID, g.LeaseToken)
	if err != nil {
		// The job is acked (running on the Center): answer now instead of
		// leaving it to the lease timeout, so operators see the real cause.
		diskFull := errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
		log.Error("cannot persist job start to the state dir; job not executed, reporting failure", "error", err.Error(), "diskFull", diskFull)
		je := jobs.Errorf(jobs.AgentStateWriteFailed, "agent could not record the job start in its state dir (%v); the job was not executed", err)
		je.Details = map[string]any{"stateDir": a.cfg.StateDir, "diskFull": diskFull}
		a.outbox.Push(&jobs.Result{JobID: g.JobID, LeaseToken: g.LeaseToken, Status: "failed", Error: je})
		return
	}
	if !fresh {
		log.Error("job already known; not executing")
		return
	}
	a.running.Store(g.JobID, struct{}{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.running.Delete(g.JobID)
		select {
		case a.sem <- struct{}{}:
		case <-ctx.Done():
			// shutting down before start: record as interrupted, never run later
			r := &jobs.Result{JobID: g.JobID, LeaseToken: g.LeaseToken, Status: "failed",
				Error: jobs.Errorf(jobs.AgentInterrupted, "agent shutting down before job start")}
			_ = a.cache.Complete(r)
			a.outbox.Push(r)
			return
		}
		defer func() { <-a.sem }()
		r := a.execute(h, params, g, log)
		if err := a.cache.Complete(r); err != nil {
			log.Error("persist result failed", "error", err.Error())
		}
		a.outbox.Push(r)
	}()
}

func (a *Agent) execute(h jobs.Handler, params any, g *jobs.Grant, log *slog.Logger) (res *jobs.Result) {
	// Handlers are NOT tied to the agent lifecycle context: a reconnect or
	// shutdown must not abort a half-done restart. Only the handler timeout applies.
	ctx, cancel := context.WithTimeout(jobs.WithLeaseToken(jobs.WithJobID(context.Background(), g.JobID), g.LeaseToken), h.Timeout())
	defer cancel()
	start := time.Now()
	a.executed.Add(1)
	defer func() {
		if p := recover(); p != nil {
			log.Error("handler panic", "panic", fmt.Sprint(p))
			res = &jobs.Result{JobID: g.JobID, LeaseToken: g.LeaseToken, Status: "failed", Error: jobs.Errorf(jobs.HandlerFailed, "handler panic")}
		}
	}()
	log.Info("executing job", "mutating", h.Mutating())
	out, err := h.Run(ctx, params)
	r := &jobs.Result{JobID: g.JobID, LeaseToken: g.LeaseToken}
	switch {
	case err == nil:
		r.Status, r.Output = "succeeded", out
	default:
		r.Status = "failed"
		var je *jobs.Error
		switch {
		case errors.As(err, &je):
			r.Error = je
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			r.Error = jobs.Errorf(jobs.HandlerTimeout, "handler exceeded %s", h.Timeout())
		default:
			r.Error = jobs.Errorf(jobs.HandlerFailed, "%v", err)
		}
	}
	log.Info("job finished", "status", r.Status, "durationMs", time.Since(start).Milliseconds())
	return r
}

// ---------------- result delivery ----------------

func (a *Agent) resultLoop(ctx context.Context) {
	b := &Backoff{Min: a.o.BackoffMin, Max: a.o.BackoffMax}
	for ctx.Err() == nil {
		r := a.outbox.Peek()
		if r == nil {
			select {
			case <-ctx.Done():
				return
			case <-a.outbox.Notify():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.client.Do(rctx, http.MethodPost, "/agent/v1/tasks/"+url.PathEscape(r.JobID)+"/result", r, nil)
		cancel()
		if err == nil {
			a.outbox.Remove(r)
			b.Reset()
			continue
		}
		if ctx.Err() != nil {
			return
		}
		var ae *transport.APIError
		if errors.As(err, &ae) && ae.HTTPStatus >= 400 && ae.HTTPStatus < 500 &&
			ae.HTTPStatus != 401 && ae.HTTPStatus != 408 && ae.HTTPStatus != 425 && ae.HTTPStatus != 426 && ae.HTTPStatus != 429 {
			// permanent rejection (unknown job / lease mismatch): drop, it stays in the local cache
			a.log.Warn("result rejected by center; dropping", "jobId", r.JobID, "code", ae.Code, "status", ae.HTTPStatus)
			a.outbox.Remove(r)
			continue
		}
		d := a.delayFor(err, b)
		a.log.Warn("result delivery failed", "jobId", r.JobID, "error", err.Error(), "retryIn", d.String(), "queued", a.outbox.Len())
		if !sleep(ctx, d) {
			return
		}
	}
}
