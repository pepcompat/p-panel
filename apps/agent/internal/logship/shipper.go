package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// SendFunc POSTs a gzip-compressed batch to /agent/v1/logs. Errors should be
// *transport.APIError for HTTP failures (status + RetryAfter).
type SendFunc func(ctx context.Context, gz []byte) error

// batchMeta is persisted with the in-flight batch so a restart resends the
// identical body (same batchId → Center dedupes).
type batchMeta struct {
	BatchID         string `json:"batchId"`
	Seq             uint64 `json:"seq"`
	Entries         int    `json:"entries"`
	DroppedReported uint64 `json:"droppedReported"`
	GzLen           int    `json:"gzLen"`
}

type inflight struct {
	batchMeta
	gz []byte
}

type shipState struct {
	NextSeq uint64 `json:"nextSeq"`
}

// ShipperOptions configures a Shipper.
type ShipperOptions struct {
	Buffer     *Buffer
	StateDir   string // inflight.bin + ship.json
	Send       SendFunc
	Interval   time.Duration // default 2s
	MaxEntries int           // per batch, default 1000 (≤ 5000)
	BackoffMin time.Duration // default 1s
	BackoffMax time.Duration // default 60s
	// MaxRetryAfter caps an honoured Retry-After (default 10 min).
	MaxRetryAfter time.Duration
	Log           *slog.Logger
	Now           func() time.Time
	// Sleep is overridable for tests (default: timer honouring ctx).
	Sleep func(ctx context.Context, d time.Duration) bool
}

// Shipper turns buffered entries into batches and delivers them, one batch in
// flight at a time.
type Shipper struct {
	o       ShipperOptions
	st      shipState
	mu      sync.Mutex
	cur     *inflight
	lastOK  atomic.Pointer[time.Time]
	sent    atomic.Uint64
	retries atomic.Uint64
	authErr atomic.Bool
	// waits records every delay the shipper chose (tests/diagnostics), bounded.
	waitsMu sync.Mutex
	waits   []time.Duration
}

// NewShipper loads persisted shipper state (sequence, in-flight batch).
func NewShipper(o ShipperOptions) *Shipper {
	if o.Interval <= 0 {
		o.Interval = 2 * time.Second
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 1000
	}
	if o.MaxEntries > MaxBatchEntries {
		o.MaxEntries = MaxBatchEntries
	}
	if o.BackoffMin <= 0 {
		o.BackoffMin = time.Second
	}
	if o.BackoffMax <= 0 {
		o.BackoffMax = 60 * time.Second
	}
	if o.MaxRetryAfter <= 0 {
		o.MaxRetryAfter = 10 * time.Minute
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	s := &Shipper{o: o}
	if raw, err := os.ReadFile(s.statePath()); err == nil {
		_ = json.Unmarshal(raw, &s.st)
	}
	if s.st.NextSeq == 0 {
		s.st.NextSeq = 1
	}
	s.cur = s.loadInflight()
	return s
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Shipper) statePath() string    { return s.o.StateDir + "/ship.json" }
func (s *Shipper) inflightPath() string { return s.o.StateDir + "/inflight.bin" }

func (s *Shipper) loadInflight() *inflight {
	raw, err := os.ReadFile(s.inflightPath())
	if err != nil {
		return nil
	}
	i := bytes.IndexByte(raw, '\n')
	if i < 0 {
		_ = os.Remove(s.inflightPath())
		return nil
	}
	var m batchMeta
	if json.Unmarshal(raw[:i], &m) != nil || m.BatchID == "" || len(raw)-i-1 != m.GzLen {
		_ = os.Remove(s.inflightPath())
		return nil
	}
	return &inflight{batchMeta: m, gz: raw[i+1:]}
}

// LastShippedAt returns the time of the last accepted batch (nil = never).
func (s *Shipper) LastShippedAt() *time.Time { return s.lastOK.Load() }

// SentBatches counts accepted batches.
func (s *Shipper) SentBatches() uint64 { return s.sent.Load() }

// Waits returns the recorded delays (tests).
func (s *Shipper) Waits() []time.Duration {
	s.waitsMu.Lock()
	defer s.waitsMu.Unlock()
	return append([]time.Duration(nil), s.waits...)
}

// InFlight returns the batchId/seq/entry count of the in-flight batch (tests).
func (s *Shipper) InFlight() (id string, seq uint64, entries int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return "", 0, 0, false
	}
	return s.cur.BatchID, s.cur.Seq, s.cur.Entries, true
}

func (s *Shipper) wait(ctx context.Context, d time.Duration) bool {
	s.waitsMu.Lock()
	if len(s.waits) < 1000 {
		s.waits = append(s.waits, d)
	}
	s.waitsMu.Unlock()
	return s.o.Sleep(ctx, d)
}

// batchHead is everything but entries; entries are spliced in raw.
type batchHead struct {
	BatchID string `json:"batchId"`
	Seq     uint64 `json:"seq"`
	SentAt  string `json:"sentAt"`
	Dropped struct {
		Entries uint64  `json:"entries"`
		Since   *string `json:"since"`
	} `json:"dropped"`
}

// encodeBatch builds the gzip body; it shrinks the entry count until the
// compressed body fits MaxBatchGzip.
func encodeBatch(h batchHead, lines [][]byte) ([]byte, int, error) {
	n := len(lines)
	for {
		var raw bytes.Buffer
		raw.WriteString(`{"batchId":`)
		writeJSON(&raw, h.BatchID)
		raw.WriteString(`,"seq":`)
		writeJSON(&raw, h.Seq)
		raw.WriteString(`,"sentAt":`)
		writeJSON(&raw, h.SentAt)
		raw.WriteString(`,"entries":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				raw.WriteByte(',')
			}
			raw.Write(lines[i])
		}
		raw.WriteString(`],"dropped":`)
		writeJSON(&raw, h.Dropped)
		raw.WriteByte('}')
		var gz bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
		if _, err := zw.Write(raw.Bytes()); err != nil {
			return nil, 0, err
		}
		if err := zw.Close(); err != nil {
			return nil, 0, err
		}
		if gz.Len() <= MaxBatchGzip || n <= 1 {
			if gz.Len() > MaxBatchGzip {
				return nil, 0, errors.New("logship: single entry exceeds batch size")
			}
			return gz.Bytes(), n, nil
		}
		n /= 2
	}
}

func writeJSON(b *bytes.Buffer, v any) {
	raw, _ := json.Marshal(v)
	b.Write(raw)
}

// next returns the in-flight batch, building one from the buffer if needed.
func (s *Shipper) next() (*inflight, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		return s.cur, nil
	}
	taken, err := s.o.Buffer.Take(s.o.MaxEntries, MaxBatchRaw)
	if err != nil && len(taken) == 0 {
		return nil, err
	}
	if len(taken) == 0 {
		s.o.Buffer.Release()
		return nil, nil
	}
	lines := make([][]byte, len(taken))
	for i, t := range taken {
		lines[i] = t.Line
	}
	h := batchHead{BatchID: transport.NewUUID(), Seq: s.st.NextSeq, SentAt: FormatTS(s.o.Now())}
	h.Dropped.Entries, h.Dropped.Since = s.o.Buffer.DroppedPending()
	gz, n, err := encodeBatch(h, lines)
	if err != nil {
		// cannot happen with 16 KiB lines; skip the offending entry rather than wedge
		s.o.Log.Error("log batch encode failed; skipping entry", "error", err.Error())
		s.o.Buffer.AddDropped(1)
		return nil, s.o.Buffer.Commit(taken[0].End, 0)
	}
	cur := &inflight{batchMeta: batchMeta{BatchID: h.BatchID, Seq: h.Seq, Entries: n, DroppedReported: h.Dropped.Entries, GzLen: len(gz)}, gz: gz}
	// persist the batch, then the sequence, then consume from the buffer
	meta, _ := json.Marshal(&cur.batchMeta)
	if err := writeAtomic(s.inflightPath(), append(append(meta, '\n'), gz...), true); err != nil {
		s.o.Buffer.Release()
		return nil, err
	}
	s.st.NextSeq++
	if raw, err := json.Marshal(&s.st); err == nil {
		_ = writeAtomic(s.statePath(), raw, false)
	}
	// drops reported in this batch are acknowledged only when it is accepted
	if err := s.o.Buffer.Commit(taken[n-1].End, 0); err != nil {
		return nil, err
	}
	s.cur = cur
	return cur, nil
}

func (s *Shipper) done(cur *inflight) {
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	_ = os.Remove(s.inflightPath())
	s.o.Buffer.ackDropped(cur.DroppedReported)
	now := s.o.Now()
	s.lastOK.Store(&now)
	s.sent.Add(1)
}

// Run ships until ctx is cancelled.
func (s *Shipper) Run(ctx context.Context) {
	backoff := s.o.BackoffMin
	tick := time.NewTicker(s.o.Interval)
	defer tick.Stop()
	for ctx.Err() == nil {
		cur, err := s.next()
		if err != nil {
			s.o.Log.Warn("log batch build failed", "error", err.Error())
		}
		if cur == nil {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			case <-s.o.Buffer.Notify():
			}
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = s.o.Send(sctx, cur.gz)
		cancel()
		if err == nil {
			s.done(cur)
			backoff = s.o.BackoffMin
			if s.authErr.Swap(false) {
				s.o.Log.Info("log shipping resumed")
			}
			// more pending? ship right away; else wait for the cadence
			if s.o.Buffer.Stats().Pending >= int64(s.o.MaxEntries) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			case <-s.o.Buffer.Notify():
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		s.retries.Add(1)
		var ae *transport.APIError
		var d time.Duration
		switch {
		case errors.As(err, &ae) && ae.HTTPStatus == 429:
			// Center backpressure: keep the batch, honour Retry-After
			d = ae.RetryAfter
			if d <= 0 {
				d, backoff = backoff, nextBackoff(backoff, s.o.BackoffMax)
			}
			if d > s.o.MaxRetryAfter {
				d = s.o.MaxRetryAfter
			}
		case errors.As(err, &ae) && (ae.HTTPStatus == 401 || ae.HTTPStatus == 403):
			if !s.authErr.Swap(true) {
				s.o.Log.Error("log shipping refused by center; backing off at max", "status", ae.HTTPStatus, "code", ae.Code)
			}
			d = s.o.BackoffMax
		case errors.As(err, &ae) && (ae.HTTPStatus == 400 || ae.HTTPStatus == 413 || ae.HTTPStatus == 422):
			// permanent rejection of this batch: drop it (counted) so shipping cannot wedge
			s.o.Log.Error("log batch rejected by center; dropping it", "status", ae.HTTPStatus, "code", ae.Code,
				"entries", cur.Entries, "batchId", cur.BatchID)
			s.mu.Lock()
			s.cur = nil
			s.mu.Unlock()
			_ = os.Remove(s.inflightPath())
			s.o.Buffer.AddDropped(uint64(cur.Entries))
			continue
		default:
			d, backoff = backoff, nextBackoff(backoff, s.o.BackoffMax)
		}
		if !s.wait(ctx, d) {
			return
		}
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n > max {
		n = max
	}
	return n
}
