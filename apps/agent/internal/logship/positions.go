package logship

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// FilePos is the persisted read position of a tailed file.
type FilePos struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
	Off int64  `json:"off"`
	// Fp is a hash of the file's first FpLen bytes (FpLen ≤ FingerprintBytes);
	// it identifies the file across copytruncate and restarts.
	Fp    uint64 `json:"fp,omitempty"`
	FpLen int64  `json:"fpLen,omitempty"`
}

// Positions persists file offsets and container last-timestamps
// (<stateDir>/logs/positions.json), written atomically.
type Positions struct {
	mu    sync.Mutex
	path  string
	dirty bool
	data  struct {
		Files      map[string]FilePos `json:"files"`
		Containers map[string]string  `json:"containers"` // id -> last ts (RFC3339Nano)
		// Stamps is the last timestamp (unix ns) given to a line of a tailed
		// file; new lines always get a later one.
		Stamps map[string]int64 `json:"stamps,omitempty"`
	}
}

// OpenPositions loads path (missing/corrupt → empty).
func OpenPositions(path string) *Positions {
	p := &Positions{path: path}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &p.data)
	}
	if p.data.Files == nil {
		p.data.Files = map[string]FilePos{}
	}
	if p.data.Containers == nil {
		p.data.Containers = map[string]string{}
	}
	if p.data.Stamps == nil {
		p.data.Stamps = map[string]int64{}
	}
	return p
}

// File returns the saved position for path.
func (p *Positions) File(path string) (FilePos, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fp, ok := p.data.Files[path]
	return fp, ok
}

// SetFile records a position (persisted by Save).
func (p *Positions) SetFile(path string, fp FilePos) {
	p.mu.Lock()
	if p.data.Files[path] != fp {
		p.data.Files[path] = fp
		p.dirty = true
	}
	p.mu.Unlock()
}

// Stamp returns the last line timestamp (unix ns) of a tailed file (0 = none).
func (p *Positions) Stamp(path string) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.data.Stamps[path]
}

// SetStamp records the last line timestamp of a tailed file (persisted by Save).
func (p *Positions) SetStamp(path string, ns int64) {
	p.mu.Lock()
	if p.data.Stamps[path] != ns {
		p.data.Stamps[path] = ns
		p.dirty = true
	}
	p.mu.Unlock()
}

// Container returns the last shipped timestamp of a container.
func (p *Positions) Container(id string) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, _ := time.Parse(time.RFC3339Nano, p.data.Containers[id])
	return t
}

// SetContainer records the last timestamp of a container.
func (p *Positions) SetContainer(id string, t time.Time) {
	p.mu.Lock()
	p.data.Containers[id] = t.UTC().Format(time.RFC3339Nano)
	p.dirty = true
	p.mu.Unlock()
}

// PruneContainers forgets containers not in keep.
func (p *Positions) PruneContainers(keep map[string]bool) {
	p.mu.Lock()
	for id := range p.data.Containers {
		if !keep[id] {
			delete(p.data.Containers, id)
			p.dirty = true
		}
	}
	p.mu.Unlock()
}

// Save writes the file if anything changed.
func (p *Positions) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.dirty {
		return nil
	}
	raw, err := json.Marshal(&p.data)
	if err != nil {
		return err
	}
	if err := writeAtomic(p.path, raw, true); err != nil {
		return err
	}
	p.dirty = false
	return nil
}
