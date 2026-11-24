// Package jobs implements TaskGrant validation, the typed handler registry
// (allowlist) and the persisted completed-job cache.
package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Rejection / failure codes posted in result.error.code.
const (
	RejectedExpired       = "REJECTED_EXPIRED"
	RejectedUnknownType   = "REJECTED_UNKNOWN_TYPE"
	RejectedWrongServer   = "REJECTED_WRONG_SERVER"
	RejectedInvalidParams = "REJECTED_INVALID_PARAMS"
	RejectedInvalidGrant  = "REJECTED_INVALID_GRANT"
	RejectedNotOwned      = "REJECTED_NOT_OWNED"
	HandlerFailed         = "HANDLER_FAILED"
	HandlerTimeout        = "HANDLER_TIMEOUT"
	AgentInterrupted      = "AGENT_INTERRUPTED"
	// AgentStateWriteFailed: the agent acked the job but could not persist
	// the job start to its state dir (e.g. disk full); the job was NOT run.
	AgentStateWriteFailed = "AGENT_STATE_WRITE_FAILED"
)

// ClockSkew is the tolerance applied to expiresAt.
const ClockSkew = 30 * time.Second

// Grant is a TaskGrant as delivered by the gateway.
type Grant struct {
	JobID          string          `json:"jobId"`
	Type           string          `json:"type"`
	Params         json.RawMessage `json:"params"`
	IdempotencyKey string          `json:"idempotencyKey"`
	IssuedAt       time.Time       `json:"issuedAt"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	LeaseToken     string          `json:"leaseToken"`
	DesiredVersion *int            `json:"desiredVersion"`
	ServerID       string          `json:"serverId"`
}

// Error is a structured job error (result.error).
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds a job Error.
func Errorf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Result is the body posted to /agent/v1/tasks/:jobId/result (plus leaseToken).
type Result struct {
	JobID      string `json:"-"`
	LeaseToken string `json:"leaseToken"`
	Status     string `json:"status"` // succeeded|failed
	Output     any    `json:"output"`
	Error      *Error `json:"error,omitempty"`
}

// Handler is a typed, allowlisted job handler. There is deliberately no
// generic "run command" handler.
type Handler interface {
	Type() string
	Mutating() bool
	Timeout() time.Duration
	// Decode strictly validates params (unknown fields rejected).
	Decode(raw json.RawMessage) (any, error)
	Run(ctx context.Context, params any) (any, error)
}

// Registry is the allowlist of handlers by type.
type Registry struct {
	mu sync.RWMutex
	h  map[string]Handler
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{h: map[string]Handler{}} }

// Register adds a handler; duplicate types panic (programming error).
func (r *Registry) Register(h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.h[h.Type()]; dup {
		panic("duplicate handler " + h.Type())
	}
	r.h[h.Type()] = h
}

// Get returns the handler for type t.
func (r *Registry) Get(t string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.h[t]
	return h, ok
}

// Types lists registered types.
func (r *Registry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.h))
	for t := range r.h {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Validate checks a grant before any side effect. It returns the decoded
// params and handler, or a rejection error.
func (r *Registry) Validate(g *Grant, serverID string, now time.Time) (Handler, any, *Error) {
	if g.JobID == "" || g.LeaseToken == "" || g.ExpiresAt.IsZero() {
		return nil, nil, Errorf(RejectedInvalidGrant, "grant missing jobId/leaseToken/expiresAt")
	}
	if !jobIDRe.MatchString(g.JobID) || len(g.LeaseToken) > MaxLeaseTokenBytes || !printable(g.LeaseToken) || len(g.Type) > 64 {
		return nil, nil, Errorf(RejectedInvalidGrant, "grant jobId/leaseToken/type malformed")
	}
	if g.ServerID != serverID {
		return nil, nil, Errorf(RejectedWrongServer, "grant is for a different server")
	}
	if g.ExpiresAt.Add(ClockSkew).Before(now) {
		return nil, nil, Errorf(RejectedExpired, "grant expired at %s", g.ExpiresAt.UTC().Format(time.RFC3339))
	}
	h, ok := r.Get(g.Type)
	if !ok {
		return nil, nil, Errorf(RejectedUnknownType, "job type %q is not allowlisted on this agent", g.Type)
	}
	raw := g.Params
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	shapeErr := CheckParamsShape(raw)
	if shapeErr != nil && shapeErr != errNUL {
		return nil, nil, Errorf(RejectedInvalidParams, "%v", shapeErr)
	}
	p, err := h.Decode(raw)
	if err != nil {
		var je *Error
		if errors.As(err, &je) {
			return nil, nil, je
		}
		return nil, nil, Errorf(RejectedInvalidParams, "%v", err)
	}
	// typed decoders report NUL with their own code first; anything they let
	// through is still refused here
	if shapeErr != nil {
		return nil, nil, Errorf(RejectedInvalidParams, "%v", shapeErr)
	}
	if pf, ok := h.(Preflighter); ok {
		if err := pf.Preflight(p); err != nil {
			var je *Error
			if errors.As(err, &je) {
				return nil, nil, je
			}
			return nil, nil, Errorf(RejectedInvalidParams, "%v", err)
		}
	}
	return h, p, nil
}

// Grant-level bounds applied to EVERY job type before its typed decoder runs.
const (
	// MaxParamsBytes bounds the raw params JSON (nginx.apply's 20 x 256 KiB
	// files with JSON escaping fit; the transport caps the whole response at 16 MiB).
	MaxParamsBytes = 12 << 20
	// MaxParamsDepth bounds JSON nesting (no job schema nests deeper than ~6).
	MaxParamsDepth = 32
	// MaxParamsNodes bounds the number of JSON values (giant arrays/objects).
	MaxParamsNodes = 200000
	// MaxLeaseTokenBytes bounds the lease token echoed back to the gateway.
	MaxLeaseTokenBytes = 1024
)

var jobIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var errNUL = errors.New("params must not contain NUL characters")

// CheckParamsShape enforces the type-independent params bounds: size, a JSON
// object at the top, nesting depth, total value count, and no NUL character
// in any string or key (no job field legitimately carries NUL; typed
// decoders re-check their own fields).
func CheckParamsShape(raw json.RawMessage) error {
	if len(raw) > MaxParamsBytes {
		return fmt.Errorf("params larger than %d bytes", MaxParamsBytes)
	}
	t := bytes.Trim(raw, " \t\r\n") // JSON whitespace only (not \v, \f, U+0085, ...)
	if len(t) == 0 || t[0] != '{' || !json.Valid(t) {
		return errors.New("params must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	depth, nodes := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if depth != 0 || nodes == 0 {
				return errors.New("params: unexpected end of JSON")
			}
			break
		}
		if err != nil {
			return fmt.Errorf("params: %v", err)
		}
		nodes++
		if nodes > MaxParamsNodes {
			return fmt.Errorf("params has more than %d values", MaxParamsNodes)
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth > MaxParamsDepth {
					return fmt.Errorf("params nested deeper than %d", MaxParamsDepth)
				}
			} else {
				depth--
			}
		case string:
			if strings.IndexByte(v, 0) >= 0 {
				return errNUL
			}
		}
		if depth == 0 {
			if _, err := dec.Token(); err != io.EOF {
				return errors.New("trailing data after params object")
			}
			break
		}
	}
	return nil
}

// Preflighter is optionally implemented by handlers to reject a grant before
// ack/execution (e.g. local authority boundaries such as owned units).
type Preflighter interface {
	Preflight(params any) error
}

// DecodeStrict decodes a JSON object into dst rejecting unknown fields,
// non-object input and trailing data.
func DecodeStrict(raw json.RawMessage, dst any) error {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return errors.New("params must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after params object")
	}
	return nil
}

type jobIDKey struct{}

// WithJobID attaches the executing grant's jobId to ctx (used by handlers that
// key on-disk artifacts by job, e.g. nginx.validate backups).
func WithJobID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, jobIDKey{}, id)
}

// JobID returns the jobId attached by WithJobID, or "".
func JobID(ctx context.Context) string {
	s, _ := ctx.Value(jobIDKey{}).(string)
	return s
}

type leaseKey struct{}

// WithLeaseToken attaches the executing grant's lease token to ctx (needed by
// handlers that call back into the gateway for the same job, e.g. the
// container.run_candidate one-time secrets fetch).
func WithLeaseToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, leaseKey{}, token)
}

// LeaseToken returns the lease token attached by WithLeaseToken, or "".
func LeaseToken(ctx context.Context) string {
	s, _ := ctx.Value(leaseKey{}).(string)
	return s
}
