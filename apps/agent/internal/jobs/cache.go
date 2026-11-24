package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultCacheSize is the protocol-mandated number of remembered jobIds.
const DefaultCacheSize = 1000

// MaxCachedOutputBytes bounds the stored output per job; larger outputs are
// replaced with a truncation marker (status/error are always kept).
const MaxCachedOutputBytes = 8 << 10

// Entry is one remembered job.
type Entry struct {
	JobID  string          `json:"jobId"`
	State  string          `json:"state"` // started|completed
	Status string          `json:"status,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
	Error  *Error          `json:"error,omitempty"`
	At     time.Time       `json:"at"`
	// LeaseToken is kept only while State is "started" so that a job cut short
	// by an agent crash can be reported as AGENT_INTERRUPTED after restart
	// (the result endpoint requires the lease token). Cleared on Complete.
	LeaseToken string `json:"leaseToken,omitempty"`
}

// Cache is a bounded, on-disk set of started/completed jobIds. A jobId seen
// here is never executed again.
type Cache struct {
	mu      sync.Mutex
	path    string
	max     int
	order   []string
	entries map[string]*Entry
}

type cacheFile struct {
	Version int      `json:"version"`
	Entries []*Entry `json:"entries"`
}

// OpenCache loads (or creates) the cache at path.
func OpenCache(path string, max int) (*Cache, error) {
	if max <= 0 {
		max = DefaultCacheSize
	}
	c := &Cache{path: path, max: max, entries: map[string]*Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var f cacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		// Fail closed: a corrupt cache could cause re-execution.
		return nil, fmt.Errorf("completed-job cache %s is corrupt: %w", path, err)
	}
	for _, e := range f.Entries {
		if e == nil || e.JobID == "" {
			continue
		}
		if _, dup := c.entries[e.JobID]; !dup {
			c.order = append(c.order, e.JobID)
		}
		c.entries[e.JobID] = e
	}
	c.trimLocked()
	return c, nil
}

// Lookup returns the entry for jobID.
func (c *Cache) Lookup(jobID string) (*Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[jobID]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

// MarkStarted durably records that jobID is about to execute (with its lease
// token, see Interrupted). It returns false if jobID is already known (caller
// must not execute).
func (c *Cache) MarkStarted(jobID, leaseToken string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[jobID]; ok {
		return false, nil
	}
	c.entries[jobID] = &Entry{JobID: jobID, State: "started", At: time.Now().UTC(), LeaseToken: leaseToken}
	c.order = append(c.order, jobID)
	c.trimLocked()
	if err := c.saveLocked(); err != nil {
		// roll back so the in-memory view matches disk; do not execute.
		delete(c.entries, jobID)
		c.order = c.order[:len(c.order)-1]
		return false, err
	}
	return true, nil
}

// Complete records the final result for jobID.
func (c *Cache) Complete(r *Result) error {
	out, err := json.Marshal(r.Output)
	if err != nil {
		out = []byte(`null`)
	}
	if len(out) > MaxCachedOutputBytes {
		out = []byte(fmt.Sprintf(`{"truncated":true,"originalBytes":%d}`, len(out)))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[r.JobID]; !ok {
		c.order = append(c.order, r.JobID)
	}
	c.entries[r.JobID] = &Entry{JobID: r.JobID, State: "completed", Status: r.Status, Output: out, Error: r.Error, At: time.Now().UTC()}
	c.trimLocked()
	return c.saveLocked()
}

// Interrupted returns (copies of) the jobs recorded as started but never
// completed, oldest first: at agent start these are jobs a previous process
// was running when it died.
func (c *Cache) Interrupted() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Entry
	for _, id := range c.order {
		if e := c.entries[id]; e != nil && e.State != "completed" {
			out = append(out, *e)
		}
	}
	return out
}

// Len returns the number of remembered jobs.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.order)
}

func (c *Cache) trimLocked() {
	for len(c.order) > c.max {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
}

func (c *Cache) saveLocked() error {
	f := cacheFile{Version: 1, Entries: make([]*Entry, 0, len(c.order))}
	for _, id := range c.order {
		f.Entries = append(f.Entries, c.entries[id])
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, ".jobcache-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, c.path)
}

// ReplayResult converts a cached entry into a result to post instead of executing.
func (e *Entry) ReplayResult(jobID, leaseToken string) *Result {
	if e.State != "completed" {
		return &Result{JobID: jobID, LeaseToken: leaseToken, Status: "failed",
			Output: map[string]any{"replayed": true},
			Error:  Errorf(AgentInterrupted, "job started before an agent restart and was not completed; it will not be re-executed")}
	}
	var out any = json.RawMessage(e.Output)
	if len(e.Output) == 0 {
		out = nil
	}
	return &Result{JobID: jobID, LeaseToken: leaseToken, Status: e.Status, Output: out, Error: e.Error}
}
