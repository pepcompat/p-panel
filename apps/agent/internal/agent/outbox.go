package agent

import (
	"sync"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Outbox is a bounded FIFO of results awaiting delivery. When full, the
// oldest result is dropped (it is still in the on-disk completed-job cache, so
// a re-delivered grant gets the cached result instead of re-execution).
type Outbox struct {
	mu      sync.Mutex
	max     int
	items   []*jobs.Result
	dropped uint64
	notify  chan struct{}
}

// NewOutbox creates an outbox with capacity max.
func NewOutbox(max int) *Outbox {
	if max < 1 {
		max = 1
	}
	return &Outbox{max: max, notify: make(chan struct{}, 1)}
}

// Push enqueues r, evicting the oldest entry when full. Returns true if an entry was dropped.
func (o *Outbox) Push(r *jobs.Result) bool {
	o.mu.Lock()
	dropped := false
	if len(o.items) >= o.max {
		o.items[0] = nil
		o.items = o.items[1:]
		o.dropped++
		dropped = true
	}
	o.items = append(o.items, r)
	o.mu.Unlock()
	select {
	case o.notify <- struct{}{}:
	default:
	}
	return dropped
}

// Peek returns the head without removing it.
func (o *Outbox) Peek() *jobs.Result {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.items) == 0 {
		return nil
	}
	return o.items[0]
}

// Remove removes r if it is still the head.
func (o *Outbox) Remove(r *jobs.Result) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.items) > 0 && o.items[0] == r {
		o.items[0] = nil
		o.items = o.items[1:]
	}
}

// Len returns the number of queued results.
func (o *Outbox) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.items)
}

// Dropped returns the number of evicted results.
func (o *Outbox) Dropped() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dropped
}

// Notify fires when something is pushed.
func (o *Outbox) Notify() <-chan struct{} { return o.notify }
