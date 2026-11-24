package logship

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/redact"
)

// Followers keeps one log follower per running managed container.
type Followers struct {
	Docker   *docker.Client
	Buffer   *Buffer
	Pos      *Positions
	Redactor *redact.Redactor
	Log      *slog.Logger
	// StartSince is used for containers without a saved position (default:
	// creation time of Followers, i.e. agent start → no historic flood).
	StartSince time.Time
	// Retry is the reconnect delay after a follow stream ends (default 2s).
	Retry time.Duration

	mu     sync.Mutex
	active map[string]*follow
	wg     sync.WaitGroup
}

type follow struct {
	m      Managed
	cancel context.CancelFunc
}

// Sync starts followers for running managed containers and stops the others.
func (f *Followers) Sync(ctx context.Context, ms []Managed) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active == nil {
		f.active = map[string]*follow{}
	}
	if f.StartSince.IsZero() {
		f.StartSince = time.Now()
	}
	want := map[string]Managed{}
	known := map[string]bool{}
	for _, m := range ms {
		known[m.ID] = true
		if m.State == "running" {
			want[m.ID] = m
		}
	}
	for id, fw := range f.active {
		if _, ok := want[id]; !ok {
			fw.cancel()
			delete(f.active, id)
		}
	}
	for id, m := range want {
		if _, ok := f.active[id]; ok {
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		fw := &follow{m: m, cancel: cancel}
		f.active[id] = fw
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.run(cctx, fw.m) }()
	}
	f.Pos.PruneContainers(known)
}

// Active returns the number of running followers.
func (f *Followers) Active() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.active)
}

// Stop cancels all followers and waits.
func (f *Followers) Stop() {
	f.mu.Lock()
	for id, fw := range f.active {
		fw.cancel()
		delete(f.active, id)
	}
	f.mu.Unlock()
	f.wg.Wait()
}

func (f *Followers) run(ctx context.Context, m Managed) {
	retry := f.Retry
	if retry <= 0 {
		retry = 2 * time.Second
	}
	tty := false
	if hi, err := f.Docker.Inspect(ctx, m.ID); err == nil {
		tty = hi.Config.Tty
	}
	for ctx.Err() == nil {
		since := f.Pos.Container(m.ID)
		if since.IsZero() {
			since = f.StartSince.Add(-time.Nanosecond)
		}
		err := f.Docker.FollowLogs(ctx, m.ID, docker.SinceParam(since), tty, func(l docker.LogLine) {
			ts := l.TS
			if ts.IsZero() {
				ts = time.Now()
			}
			line := Sanitize(f.Redactor, l.Line)
			e := Entry{TS: FormatTS(ts), Source: SourceContainer, App: strp(m.App), Service: strp(m.Service),
				Container: strp(m.Name), Stream: strp(l.Stream), Level: DetectLevel(SourceContainer, l.Stream, line), Line: line}
			if err := f.Buffer.Append(e); err != nil {
				f.Buffer.AddDropped(1) // not buffered: count it instead of losing it silently
			} else if !l.TS.IsZero() {
				f.Pos.SetContainer(m.ID, l.TS)
			}
		})
		if err != nil && ctx.Err() == nil && f.Log != nil {
			f.Log.Debug("container log follow ended", "container", m.Name, "error", err.Error())
		}
		if !sleepCtx(ctx, retry) {
			return
		}
	}
}
