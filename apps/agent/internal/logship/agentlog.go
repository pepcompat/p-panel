package logship

import (
	"bytes"
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

// AgentSink receives the agent's own JSON log records (level ≥ info) through
// a bounded channel; it never blocks the logger (overflow is counted).
type AgentSink struct {
	ch      chan agentRec
	dropped atomic.Uint64
	red     atomic.Pointer[redact.Redactor]
}

type agentRec struct {
	t    time.Time
	line string // already sanitized (redacted while job secrets are still registered)
}

// NewAgentSink returns a sink with a bounded queue.
func NewAgentSink() *AgentSink { return &AgentSink{ch: make(chan agentRec, agentChanEntries)} }

// Write implements io.Writer for a slog.JSONHandler (one record per call).
func (s *AgentSink) Write(p []byte) (int, error) {
	select {
	case s.ch <- agentRec{t: time.Now(), line: Sanitize(s.red.Load(), bytes.TrimRight(p, "\n"))}:
	default:
		s.dropped.Add(1)
	}
	return len(p), nil
}

// TeeHandler forwards every record to Base and records ≥ Info (JSON) to Ship.
type TeeHandler struct {
	Base slog.Handler
	Ship slog.Handler
}

// NewTee builds a tee: base unchanged; ship formats JSON into sink.
func NewTee(base slog.Handler, sink *AgentSink, opts *slog.HandlerOptions) *TeeHandler {
	o := slog.HandlerOptions{Level: slog.LevelInfo}
	if opts != nil {
		o.ReplaceAttr = opts.ReplaceAttr
	}
	return &TeeHandler{Base: base, Ship: slog.NewJSONHandler(sink, &o)}
}

// Enabled implements slog.Handler.
func (h *TeeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.Base.Enabled(ctx, l) || h.Ship.Enabled(ctx, l)
}

// Handle implements slog.Handler.
func (h *TeeHandler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.Base.Enabled(ctx, r.Level) {
		err = h.Base.Handle(ctx, r.Clone())
	}
	if h.Ship.Enabled(ctx, r.Level) {
		_ = h.Ship.Handle(ctx, r)
	}
	return err
}

// WithAttrs implements slog.Handler.
func (h *TeeHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &TeeHandler{Base: h.Base.WithAttrs(as), Ship: h.Ship.WithAttrs(as)}
}

// WithGroup implements slog.Handler.
func (h *TeeHandler) WithGroup(name string) slog.Handler {
	return &TeeHandler{Base: h.Base.WithGroup(name), Ship: h.Ship.WithGroup(name)}
}
