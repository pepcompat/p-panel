package agent

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Backoff is exponential backoff with jitter, bounded to [Min, Max].
type Backoff struct {
	Min, Max time.Duration
	mu       sync.Mutex
	attempt  int
}

// Next returns the next delay: base = min(Max, Min*2^attempt), result is
// uniformly jittered in [base/2, base] and never exceeds Max or drops below Min.
func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	base := b.Min
	for i := 0; i < b.attempt && base < b.Max; i++ {
		base *= 2
	}
	if base > b.Max {
		base = b.Max
	}
	if b.attempt < 64 {
		b.attempt++
	}
	half := base / 2
	d := half + time.Duration(rand.Int64N(int64(half)+1))
	if d < b.Min {
		d = b.Min
	}
	if d > b.Max {
		d = b.Max
	}
	return d
}

// Reset restarts the sequence after a success.
func (b *Backoff) Reset() {
	b.mu.Lock()
	b.attempt = 0
	b.mu.Unlock()
}

// Attempts returns consecutive failures.
func (b *Backoff) Attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempt
}
