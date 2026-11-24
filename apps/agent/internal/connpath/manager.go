package connpath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/safefs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// ErrNoPath is returned by BaseURL when the policy allows no reachable,
// non-forbidden endpoint (for example private_only without a private endpoint).
var ErrNoPath = errors.New("no management path allowed by the connection policy")

// ForbiddenRetryInterval: when EVERY allowed endpoint was answered with
// CONNECTION_PATH_NOT_ALLOWED and no new policy arrived, the first one is
// retried at most this often (the Center audits such requests once per 10 min).
// Paths the policy does not allow are never retried.
const ForbiddenRetryInterval = 10 * time.Minute

// persisted is <stateDir>/connection.json (0600).
type persisted struct {
	Version   int        `json:"version"`
	Policy    string     `json:"policy"` // "" = none received yet
	Endpoints []Endpoint `json:"endpoints"`
	// Forbidden maps a path answered with 403 CONNECTION_PATH_NOT_ALLOWED to
	// the policy the agent knew at that time ("" = unknown).
	Forbidden map[string]string `json:"forbidden,omitempty"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// Report is the heartbeat request `connection` block.
type Report struct {
	Policy     string        `json:"policy,omitempty"`
	ActivePath *string       `json:"activePath"`
	Endpoints  []ProbeResult `json:"endpoints"`
}

// Options configure a Manager.
type Options struct {
	StateDir string
	// FallbackURL is the enrollment gatewayUrl, used as the single public
	// endpoint when connection.json is absent (agents enrolled before P9).
	FallbackURL string
	Probe       func(ctx context.Context, ep Endpoint) ProbeResult
	Log         *slog.Logger
	Now         func() time.Time
}

// Manager holds the connection state. All methods are safe for concurrent use.
type Manager struct {
	o        Options
	mu       sync.Mutex
	st       persisted
	health   map[string]ProbeResult // by URL
	active   *Endpoint
	resortAt time.Time
	onSwitch func(from, to string)
}

// Load reads connection.json (or derives the state from FallbackURL).
// A missing or unreadable file never stops the agent.
func Load(o Options) (*Manager, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Manager{o: o, health: map[string]ProbeResult{}}
	st, err := readState(o.StateDir)
	switch {
	case err == nil:
		m.st = *st
	case errors.Is(err, fs.ErrNotExist):
		fb, ferr := fallback(o.FallbackURL)
		if ferr != nil {
			return nil, ferr
		}
		m.st = *fb
	default:
		o.Log.Warn("connection state unreadable; using the enrollment gateway url", "error", err.Error())
		fb, ferr := fallback(o.FallbackURL)
		if ferr != nil {
			return nil, ferr
		}
		m.st = *fb
	}
	if m.st.Forbidden == nil {
		m.st.Forbidden = map[string]string{}
	}
	m.reselectLocked()
	return m, nil
}

func fallback(gatewayURL string) (*persisted, error) {
	u, err := NormalizeURL(gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("identity gatewayUrl: %w", err)
	}
	return &persisted{Version: stateVersion1, Endpoints: []Endpoint{{Path: PathPublic, URL: u}}, Forbidden: map[string]string{}}, nil
}

// SaveEnrollment writes a fresh connection.json after enrollment: the
// advertised gatewayEndpoints (or gatewayUrl as the public endpoint), no
// policy yet, nothing forbidden. Invalid endpoints are an error.
func SaveEnrollment(stateDir, gatewayURL string, eps []Endpoint) error {
	st, err := fallback(gatewayURL)
	if err != nil {
		return err
	}
	if len(eps) > 0 {
		v, err := ValidateEndpoints(eps)
		if err != nil {
			return fmt.Errorf("gatewayEndpoints: %w", err)
		}
		st.Endpoints = v
	}
	st.UpdatedAt = time.Now().UTC()
	return writeState(stateDir, st)
}

func readState(stateDir string) (*persisted, error) {
	rdir, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return nil, err
	}
	b, _, err := safefs.ReadFileNoFollow(filepath.Join(rdir, FileName), maxFileBytes)
	if err != nil {
		return nil, err
	}
	var st persisted
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	if st.Policy != PolicyUnknown && !ValidPolicy(st.Policy) {
		return nil, fmt.Errorf("%s: unknown policy %q", FileName, st.Policy)
	}
	eps, err := ValidateEndpoints(st.Endpoints)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	st.Endpoints = eps
	for p := range st.Forbidden {
		if !ValidPath(p) {
			delete(st.Forbidden, p)
		}
	}
	return &st, nil
}

func writeState(stateDir string, st *persisted) error {
	rdir, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return err
	}
	st.Version = stateVersion1
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	d, err := safefs.OpenDir(rdir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.WriteFileAtomic(FileName, b, 0o600, 0, 0, false)
}

func (m *Manager) persistLocked() {
	m.st.UpdatedAt = m.o.Now().UTC()
	cp := m.st
	if err := writeState(m.o.StateDir, &cp); err != nil {
		m.o.Log.Error("persisting connection state failed", "error", err.Error())
	}
}

// SetOnSwitch registers a callback invoked (outside the lock) when the active
// endpoint changes.
func (m *Manager) SetOnSwitch(f func(from, to string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onSwitch = f
}

func effective(policy string) string {
	if policy == PolicyUnknown {
		return PolicyPublicPreferred
	}
	return policy
}

// reselectLocked picks the active endpoint: the first endpoint in dial order
// that is not forbidden and probed healthy; else the first not yet probed;
// else the one after the current active (rotation, so alternatives keep being
// tried). Returns the previous and new URL when the choice changed.
func (m *Manager) reselectLocked() (string, string, bool) {
	prev := ""
	if m.active != nil {
		prev = m.active.URL
	}
	cands := Order(effective(m.st.Policy), m.st.Endpoints)
	var usable []Endpoint
	for _, c := range cands {
		if _, f := m.st.Forbidden[c.Path]; f {
			continue
		}
		// the Center's last ping said this path is not allowed for us
		if h, ok := m.health[c.URL]; ok && h.PolicyAllows != nil && !*h.PolicyAllows {
			continue
		}
		usable = append(usable, c)
	}
	var pick *Endpoint
	switch {
	case len(usable) == 0:
		if len(cands) > 0 && (m.resortAt.IsZero() || m.o.Now().Sub(m.resortAt) >= ForbiddenRetryInterval) {
			c := cands[0]
			pick = &c
			m.resortAt = m.o.Now()
			m.o.Log.Warn("every allowed management path was refused by the Center; retrying the first one", "path", c.Path, "url", c.URL)
		}
	default:
		for i := range usable {
			if h, ok := m.health[usable[i].URL]; ok && h.OK {
				pick = &usable[i]
				break
			}
		}
		if pick == nil {
			for i := range usable {
				if _, ok := m.health[usable[i].URL]; !ok {
					pick = &usable[i]
					break
				}
			}
		}
		if pick == nil {
			idx := 0
			for i := range usable {
				if usable[i].URL == prev {
					idx = (i + 1) % len(usable)
					break
				}
			}
			pick = &usable[idx]
		}
	}
	m.active = pick
	next := ""
	if pick != nil {
		next = pick.URL
	}
	return prev, next, prev != next
}

func (m *Manager) switched(prev, next string, changed bool) {
	if !changed {
		return
	}
	m.mu.Lock()
	f := m.onSwitch
	path := ""
	if m.active != nil {
		path = m.active.Path
	}
	m.mu.Unlock()
	if next == "" {
		m.o.Log.Error("no management path available (fail closed)", "previous", prev)
	} else {
		m.o.Log.Info("management path selected", "path", path, "url", next, "previous", prev)
	}
	if f != nil {
		f(prev, next)
	}
}

// BaseURL returns the gateway base URL to use now, or ErrNoPath.
func (m *Manager) BaseURL() (string, error) {
	m.mu.Lock()
	if m.active == nil {
		prev, next, ch := m.reselectLocked()
		m.mu.Unlock()
		m.switched(prev, next, ch)
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	if m.active == nil {
		return "", ErrNoPath
	}
	return m.active.URL, nil
}

func (m *Manager) endpointByURL(u string) (Endpoint, bool) {
	for _, e := range m.st.Endpoints {
		if e.URL == u {
			return e, true
		}
	}
	return Endpoint{}, false
}

// Observe is the transport hook: called after every gateway request with the
// base URL used. A 403 CONNECTION_PATH_NOT_ALLOWED marks the path forbidden;
// a network-level failure marks the endpoint unhealthy. Both re-select.
func (m *Manager) Observe(ctx context.Context, base string, err error) {
	// A request that was started on a path that is no longer active (e.g. a
	// long-poll in flight during a switch) has just returned its connection to
	// the pool: let the owner drop it, so no idle keep-alive connection lingers
	// on a path the policy no longer uses.
	m.mu.Lock()
	stale := m.onSwitch != nil && (m.active == nil || m.active.URL != base)
	f, cur := m.onSwitch, ""
	if m.active != nil {
		cur = m.active.URL
	}
	m.mu.Unlock()
	if stale {
		f(base, cur)
	}
	if err == nil || errors.Is(err, ErrNoPath) || errors.Is(err, context.Canceled) || errors.Is(err, transport.ErrBadResponse) {
		return
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	var ae *transport.APIError
	if errors.As(err, &ae) {
		if ae.HTTPStatus == 403 && ae.Code == CodePathNotAllowed {
			m.Forbid(base)
		}
		return
	}
	m.mu.Lock()
	ep, ok := m.endpointByURL(base)
	if !ok {
		m.mu.Unlock()
		return
	}
	m.health[base] = ProbeResult{Path: ep.Path, URL: ep.URL, CheckedAt: m.o.Now().UTC().Format(time.RFC3339Nano), Error: ClassifyError(err)}
	prev, next, ch := m.reselectLocked()
	m.mu.Unlock()
	m.switched(prev, next, ch)
}

// Forbid marks the path of the endpoint at base as forbidden by the Center
// until a different policy that allows it is received.
func (m *Manager) Forbid(base string) {
	m.mu.Lock()
	ep, ok := m.endpointByURL(base)
	if !ok {
		m.mu.Unlock()
		return
	}
	if _, already := m.st.Forbidden[ep.Path]; !already {
		m.st.Forbidden[ep.Path] = m.st.Policy
		m.persistLocked()
		m.o.Log.Warn("Center refused this management path (CONNECTION_PATH_NOT_ALLOWED); not retrying it until a new policy allows it",
			"path", ep.Path, "url", ep.URL, "policy", m.st.Policy)
	}
	prev, next, ch := m.reselectLocked()
	m.mu.Unlock()
	m.switched(prev, next, ch)
}

// Apply applies a heartbeat response `connection` block. An invalid block is
// ignored (the last good state is kept). An empty endpoint list keeps the
// current endpoints. Returns true when the stored state changed.
func (m *Manager) Apply(b *Block) bool {
	if b == nil {
		return false
	}
	if !ValidPolicy(b.Policy) {
		m.o.Log.Warn("ignoring connection block with unknown policy", "policy", b.Policy)
		return false
	}
	var eps []Endpoint
	if len(b.Endpoints) > 0 {
		v, err := ValidateEndpoints(b.Endpoints)
		if err != nil {
			m.o.Log.Warn("ignoring connection block with invalid endpoints", "error", err.Error())
			return false
		}
		eps = v
	}
	m.mu.Lock()
	changed := false
	if b.Policy != m.st.Policy {
		m.o.Log.Info("connection policy received", "policy", b.Policy, "previous", m.st.Policy)
		changed = true
	}
	if eps != nil && !sameEndpoints(eps, m.st.Endpoints) {
		m.st.Endpoints = eps
		m.resortAt = time.Time{}
		changed = true
	}
	for path, at := range m.st.Forbidden {
		if b.Policy != at && Allows(b.Policy, path) {
			delete(m.st.Forbidden, path)
			m.o.Log.Info("management path allowed again by the new policy", "path", path, "policy", b.Policy)
			changed = true
		}
	}
	m.st.Policy = b.Policy
	if changed {
		m.persistLocked()
	}
	prev, next, ch := m.reselectLocked()
	m.mu.Unlock()
	m.switched(prev, next, ch)
	return changed
}

func sameEndpoints(a, b []Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Endpoints returns the advertised endpoints.
func (m *Manager) Endpoints() []Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Endpoint(nil), m.st.Endpoints...)
}

// Policy returns the last received policy ("" = none yet).
func (m *Manager) Policy() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Policy
}

// Forbidden returns the paths currently marked forbidden.
func (m *Manager) Forbidden() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, p := range []string{PathPublic, PathPrivate} {
		if _, ok := m.st.Forbidden[p]; ok {
			out = append(out, p)
		}
	}
	return out
}

// probeTargets returns the endpoints the policy allows probing.
func (m *Manager) probeTargets() []Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Endpoint
	for _, e := range m.st.Endpoints {
		if Probeable(m.st.Policy, e.Path) {
			out = append(out, e)
		}
	}
	return out
}

// ProbeNow probes every probeable endpoint concurrently and returns the
// results (in advertised order) without changing the selection.
func (m *Manager) ProbeNow(ctx context.Context) []ProbeResult {
	targets := m.probeTargets()
	out := make([]ProbeResult, len(targets))
	if m.o.Probe == nil {
		return out[:0]
	}
	var wg sync.WaitGroup
	for i, e := range targets {
		wg.Add(1)
		go func(i int, e Endpoint) {
			defer wg.Done()
			out[i] = m.o.Probe(ctx, e)
		}(i, e)
	}
	wg.Wait()
	return out
}

// ProbeAll probes, records the results and re-selects the active endpoint
// (fail-back to a preferred path once it is healthy again).
func (m *Manager) ProbeAll(ctx context.Context) {
	res := m.ProbeNow(ctx)
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	keep := map[string]bool{}
	for _, r := range res {
		m.health[r.URL] = r
		keep[r.URL] = true
	}
	// forget health of endpoints no longer advertised / no longer probeable
	for u := range m.health {
		if _, ok := m.endpointByURL(u); !ok {
			delete(m.health, u)
		} else if !keep[u] {
			if ep, _ := m.endpointByURL(u); !Probeable(m.st.Policy, ep.Path) {
				delete(m.health, u)
			}
		}
	}
	prev, next, ch := m.reselectLocked()
	m.mu.Unlock()
	m.switched(prev, next, ch)
}

// Run probes every interval until ctx is done.
func (m *Manager) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.ProbeAll(ctx)
		}
	}
}

// Report returns the heartbeat `connection` block: the active path and the
// latest probe result of every probed endpoint (advertised order).
func (m *Manager) Report() *Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := &Report{Policy: m.st.Policy, Endpoints: []ProbeResult{}}
	if m.active != nil {
		p := m.active.Path
		r.ActivePath = &p
	}
	for _, e := range m.st.Endpoints {
		if h, ok := m.health[e.URL]; ok && Probeable(m.st.Policy, e.Path) {
			r.Endpoints = append(r.Endpoints, h)
		}
	}
	return r
}

// Active returns the active endpoint, if any.
func (m *Manager) Active() (Endpoint, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return Endpoint{}, false
	}
	return *m.active, true
}
