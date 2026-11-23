package logship

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

// Options configures a Pipeline.
type Options struct {
	Logs config.LogsConfig
	// StateDir is <stateDir>/logs (positions.json, cursor.json, inflight.bin, ship.json, buffer/).
	StateDir string
	Docker   *docker.Client // nil disables the container source
	Redactor *redact.Redactor
	Sink     *AgentSink // nil disables the agent source
	Log      *slog.Logger
	// PollInterval for file tailers (default 1s); ScanInterval for container discovery (default 5s).
	PollInterval time.Duration
	ScanInterval time.Duration
	// SegmentBytes overrides the buffer segment size (tests).
	SegmentBytes int64
	// Backoff bounds for the shipper (defaults 1s/60s).
	BackoffMin, BackoffMax time.Duration
	Now                    func() time.Time
}

// Pipeline wires sources → redaction → buffer → shipper.
type Pipeline struct {
	o         Options
	buf       *Buffer
	pos       *Positions
	tailers   []*Tailer
	followers *Followers
	shipper   *Shipper
	lastWarn  atomic.Int64
	running   atomic.Bool
}

// ShippingStatus is heartbeat logShipping.
type ShippingStatus struct {
	BufferedBytes  int64   `json:"bufferedBytes"`
	BufferCapBytes int64   `json:"bufferCapBytes"`
	DroppedEntries uint64  `json:"droppedEntries"`
	LastShippedAt  *string `json:"lastShippedAt"`
}

// New opens the buffer and positions. Sources start with Run.
func New(o Options) (*Pipeline, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Redactor == nil {
		o.Redactor = redact.New()
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.ScanInterval <= 0 {
		o.ScanInterval = 5 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	p := &Pipeline{o: o}
	buf, err := OpenBuffer(BufferOptions{Dir: filepath.Join(o.StateDir, "buffer"), StateFile: filepath.Join(o.StateDir, "cursor.json"),
		CapBytes: o.Logs.BufferCapBytes, SegmentBytes: o.SegmentBytes, NotifyAt: o.Logs.MaxBatchEntries, Now: o.Now})
	if err != nil {
		return nil, err
	}
	buf.onDrop = p.warnDrop
	p.buf = buf
	p.pos = OpenPositions(filepath.Join(o.StateDir, "positions.json"))
	for _, s := range o.Logs.Sources {
		switch s.Source {
		case SourceNginxAccess, SourceNginxError:
			p.tailers = append(p.tailers, NewTailer(s.Source, s.Path, p.pos, true))
		}
	}
	if o.Logs.HasLogSource(SourceContainer) && o.Docker != nil {
		p.followers = &Followers{Docker: o.Docker, Buffer: buf, Pos: p.pos, Redactor: o.Redactor, Log: o.Log}
	}
	if !o.Logs.HasLogSource(SourceAgent) {
		p.o.Sink = nil
	}
	if p.o.Sink != nil {
		p.o.Sink.red.Store(o.Redactor)
	}
	p.shipper = NewShipper(ShipperOptions{Buffer: buf, StateDir: o.StateDir, Interval: time.Duration(o.Logs.ShipIntervalMs) * time.Millisecond,
		MaxEntries: o.Logs.MaxBatchEntries, BackoffMin: o.BackoffMin, BackoffMax: o.BackoffMax, Log: o.Log, Now: o.Now})
	return p, nil
}

func (p *Pipeline) warnDrop(n uint64) {
	now := time.Now().UnixNano()
	if last := p.lastWarn.Load(); last != 0 && now-last < int64(time.Minute) {
		return
	}
	p.lastWarn.Store(now)
	st := p.buf.Stats()
	p.o.Log.Warn("log buffer full: dropped oldest entries", "dropped", n, "droppedTotal", st.DroppedTotal, "capBytes", st.Cap)
}

// Buffer exposes the buffer (tests/diagnostics).
func (p *Pipeline) Buffer() *Buffer { return p.buf }

// Shipper exposes the shipper (tests/diagnostics).
func (p *Pipeline) Shipper() *Shipper { return p.shipper }

// Redactor returns the redactor (job secrets registry).
func (p *Pipeline) Redactor() *redact.Redactor { return p.o.Redactor }

// Status is the heartbeat logShipping object.
func (p *Pipeline) Status() *ShippingStatus {
	st := p.buf.Stats()
	s := &ShippingStatus{BufferedBytes: st.Bytes, BufferCapBytes: st.Cap, DroppedEntries: st.DroppedTotal}
	if t := p.shipper.LastShippedAt(); t != nil {
		v := FormatTS(*t)
		s.LastShippedAt = &v
	}
	return s
}

// PollOnce runs one tailer pass (tests / Run).
func (p *Pipeline) PollOnce() {
	for _, t := range p.tailers {
		var es []Entry
		now := FormatTS(p.o.Now())
		pos, ok := t.Poll(func(raw []byte) {
			line := Sanitize(p.o.Redactor, raw)
			es = append(es, Entry{TS: now, Source: t.Source, File: strp(t.Path), Level: DetectLevel(t.Source, "", line), Line: line})
		})
		if !ok {
			continue
		}
		if err := p.buf.Append(es...); err != nil {
			p.o.Log.Warn("log buffer append failed", "file", t.Path, "error", err.Error())
			continue // position not advanced: lines are re-read next poll
		}
		p.pos.SetFile(t.Path, pos)
	}
	if err := p.pos.Save(); err != nil {
		p.o.Log.Warn("saving log positions failed", "error", err.Error())
	}
}

// Run starts all sources and the shipper; blocks until ctx is cancelled.
func (p *Pipeline) Run(ctx context.Context, send SendFunc) {
	if !p.running.CompareAndSwap(false, true) {
		return
	}
	p.shipper.o.Send = send
	var wg sync.WaitGroup
	start := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	start(func() { p.shipper.Run(ctx) })
	start(func() {
		t := time.NewTicker(p.o.PollInterval)
		defer t.Stop()
		for {
			p.PollOnce()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
	if p.followers != nil {
		start(func() {
			t := time.NewTicker(p.o.ScanInterval)
			defer t.Stop()
			for {
				sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if ms, err := ManagedContainers(sctx, p.o.Docker); err == nil {
					p.followers.Sync(ctx, ms)
				}
				cancel()
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		})
	}
	if p.o.Sink != nil {
		start(func() { p.drainAgent(ctx) })
	}
	<-ctx.Done()
	wg.Wait()
	if p.followers != nil {
		p.followers.Stop()
	}
	for _, t := range p.tailers {
		t.Close()
	}
	_ = p.pos.Save()
	_ = p.buf.Close()
}

func (p *Pipeline) drainAgent(ctx context.Context) {
	s := p.o.Sink
	flushDrops := func() {
		if n := s.dropped.Swap(0); n > 0 {
			p.buf.AddDropped(n)
		}
	}
	for {
		select {
		case <-ctx.Done():
			flushDrops()
			return
		case r := <-s.ch:
			_ = p.buf.Append(Entry{TS: FormatTS(r.t), Source: SourceAgent, Level: DetectLevel(SourceAgent, "", r.line), Line: r.line})
			flushDrops()
		}
	}
}
