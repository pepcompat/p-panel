package logship

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cursor is a read position in the segment buffer.
type Cursor struct {
	Seg uint64 `json:"seg"`
	Off int64  `json:"off"`
	N   int64  `json:"n"` // entries consumed in Seg
}

func (c Cursor) before(o Cursor) bool {
	return c.Seg < o.Seg || (c.Seg == o.Seg && c.Off < o.Off)
}

type segment struct {
	id      uint64
	size    int64
	entries int64
}

// bufferState is persisted in <logs>/cursor.json.
type bufferState struct {
	Cursor         Cursor  `json:"cursor"`
	DroppedTotal   uint64  `json:"droppedTotal"`
	DroppedPending uint64  `json:"droppedPending"`
	DroppedSince   *string `json:"droppedSince"`
}

// Buffer is a bounded, append-only on-disk queue of JSON-encoded entries made
// of segment files seg-<id>.jsonl. When appending would exceed the cap, the
// oldest segments are deleted and their unshipped entries counted as dropped.
type Buffer struct {
	mu        sync.Mutex
	dir       string
	stateFile string
	cap       int64
	segMax    int64
	segs      []*segment // oldest first; last is the append target
	active    *os.File
	total     int64
	cur       Cursor
	reserved  *Cursor // end of entries taken for the in-flight batch, not yet committed
	st        bufferState
	notify    chan struct{}
	threshold int64
	now       func() time.Time
	// onDrop is called (outside the lock) after a drop; used for a rate-limited warning.
	onDrop func(n uint64)
}

// BufferOptions configures OpenBuffer.
type BufferOptions struct {
	Dir       string // segment directory (created 0700)
	StateFile string // cursor/dropped counters (atomic JSON)
	CapBytes  int64
	// SegmentBytes defaults to clamp(cap/16, 64 KiB, 4 MiB).
	SegmentBytes int64
	// NotifyAt signals Notify() once this many entries are pending.
	NotifyAt int
	Now      func() time.Time
}

func segName(id uint64) string { return fmt.Sprintf("seg-%020d.jsonl", id) }

// OpenBuffer opens (or recovers) a buffer.
func OpenBuffer(o BufferOptions) (*Buffer, error) {
	if o.CapBytes <= 0 {
		return nil, errors.New("logship: buffer cap must be > 0")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	seg := o.SegmentBytes
	if seg <= 0 {
		seg = o.CapBytes / 16
		if seg < defaultSegMin {
			seg = defaultSegMin
		}
		if seg > defaultSegMax {
			seg = defaultSegMax
		}
	}
	if seg > o.CapBytes {
		seg = o.CapBytes
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NotifyAt <= 0 {
		o.NotifyAt = 1000
	}
	b := &Buffer{dir: o.Dir, stateFile: o.StateFile, cap: o.CapBytes, segMax: seg, notify: make(chan struct{}, 1),
		threshold: int64(o.NotifyAt), now: o.Now}
	if err := b.recover(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Buffer) recover() error {
	des, err := os.ReadDir(b.dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		n := de.Name()
		if !strings.HasPrefix(n, "seg-") || !strings.HasSuffix(n, ".jsonl") {
			if strings.HasPrefix(n, ".") { // stale temp
				_ = os.Remove(filepath.Join(b.dir, n))
			}
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(n, "seg-"), ".jsonl"), 10, 64)
		if err != nil {
			continue
		}
		s, err := scanSegment(filepath.Join(b.dir, n))
		if err != nil {
			return err
		}
		s.id = id
		b.segs = append(b.segs, s)
		b.total += s.size
	}
	sort.Slice(b.segs, func(i, j int) bool { return b.segs[i].id < b.segs[j].id })
	if raw, err := os.ReadFile(b.stateFile); err == nil {
		_ = json.Unmarshal(raw, &b.st)
	}
	b.cur = b.st.Cursor
	if len(b.segs) == 0 {
		next := b.cur.Seg + 1
		b.segs = []*segment{{id: next}}
		b.cur = Cursor{Seg: next}
	} else if b.cur.Seg < b.segs[0].id || b.find(b.cur.Seg) == nil {
		b.cur = Cursor{Seg: b.segs[0].id}
	} else if s := b.find(b.cur.Seg); b.cur.Off > s.size {
		b.cur = Cursor{Seg: s.id, Off: s.size, N: s.entries}
	}
	return b.openActive()
}

// scanSegment counts complete lines and truncates a torn final line.
func scanSegment(path string) (*segment, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := &segment{}
	buf := make([]byte, 64<<10)
	var off, lastNL int64 = 0, 0
	for {
		n, err := f.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				s.entries++
				lastNL = off + int64(i) + 1
			}
		}
		off += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if lastNL != off {
		if err := f.Truncate(lastNL); err != nil {
			return nil, err
		}
	}
	s.size = lastNL
	return s, nil
}

func (b *Buffer) find(id uint64) *segment {
	for _, s := range b.segs {
		if s.id == id {
			return s
		}
	}
	return nil
}

func (b *Buffer) openActive() error {
	last := b.segs[len(b.segs)-1]
	f, err := os.OpenFile(filepath.Join(b.dir, segName(last.id)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if b.active != nil {
		b.active.Close()
	}
	b.active = f
	return nil
}

// Notify fires when at least NotifyAt entries are pending.
func (b *Buffer) Notify() <-chan struct{} { return b.notify }

// Append redacted entries. Never blocks on the network; drops oldest
// segments when the cap would be exceeded.
func (b *Buffer) Append(es ...Entry) error {
	if len(es) == 0 {
		return nil
	}
	var dropped uint64
	var werr error
	b.mu.Lock()
	for i := range es {
		line, err := json.Marshal(&es[i])
		if err != nil {
			continue
		}
		line = append(line, '\n')
		n := int64(len(line))
		act := b.segs[len(b.segs)-1]
		if act.size > 0 && act.size+n > b.segMax {
			if err := b.rotateLocked(); err != nil {
				werr = err
				break
			}
			act = b.segs[len(b.segs)-1]
		}
		for b.total+n > b.cap && len(b.segs) > 1 {
			dropped += b.dropOldestLocked()
		}
		if _, err := b.active.Write(line); err != nil {
			werr = err
			break
		}
		act.size += n
		act.entries++
		b.total += n
	}
	pending := b.pendingLocked()
	if dropped > 0 {
		b.st.DroppedTotal += dropped
		b.st.DroppedPending += dropped
		if b.st.DroppedSince == nil {
			s := FormatTS(b.now())
			b.st.DroppedSince = &s
		}
		_ = b.saveLocked()
	}
	onDrop := b.onDrop
	b.mu.Unlock()
	if pending >= b.threshold {
		select {
		case b.notify <- struct{}{}:
		default:
		}
	}
	if dropped > 0 && onDrop != nil {
		onDrop(dropped)
	}
	return werr
}

func (b *Buffer) rotateLocked() error {
	last := b.segs[len(b.segs)-1]
	b.segs = append(b.segs, &segment{id: last.id + 1})
	return b.openActive()
}

// dropOldestLocked deletes the oldest segment and returns how many of its
// entries were neither shipped nor reserved for the in-flight batch.
func (b *Buffer) dropOldestLocked() uint64 {
	s := b.segs[0]
	start := int64(0)
	if b.cur.Seg == s.id {
		start = b.cur.N
	} else if b.cur.Seg > s.id {
		start = s.entries
	}
	if r := b.reserved; r != nil {
		if r.Seg > s.id {
			start = s.entries
		} else if r.Seg == s.id && r.N > start {
			start = r.N
		}
	}
	_ = os.Remove(filepath.Join(b.dir, segName(s.id)))
	b.total -= s.size
	b.segs = b.segs[1:]
	if b.cur.Seg <= s.id {
		b.cur = Cursor{Seg: b.segs[0].id}
	}
	if d := s.entries - start; d > 0 {
		return uint64(d)
	}
	return 0
}

func (b *Buffer) pendingLocked() int64 {
	var n int64
	for _, s := range b.segs {
		switch {
		case s.id < b.cur.Seg:
		case s.id == b.cur.Seg:
			n += s.entries - b.cur.N
		default:
			n += s.entries
		}
	}
	return n
}

// Taken is one entry read for a batch and the cursor just after it.
type Taken struct {
	Line []byte // JSON object, no newline
	End  Cursor
}

// Take reads up to maxEntries / maxBytes of pending entries without consuming
// them and reserves them (drops no longer count them). Call Commit after the
// batch is durably handed off, or Release to un-reserve.
func (b *Buffer) Take(maxEntries int, maxBytes int64) ([]Taken, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Taken
	var size int64
	pos := b.cur
	for _, s := range b.segs {
		if s.id < pos.Seg {
			continue
		}
		if s.id > pos.Seg {
			pos = Cursor{Seg: s.id}
		}
		if pos.Off >= s.size {
			continue
		}
		f, err := os.Open(filepath.Join(b.dir, segName(s.id)))
		if err != nil {
			return out, err
		}
		data := make([]byte, s.size-pos.Off)
		_, err = f.ReadAt(data, pos.Off)
		f.Close()
		if err != nil {
			return out, err
		}
		for len(data) > 0 && len(out) < maxEntries {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				break
			}
			if len(out) > 0 && size+int64(i) > maxBytes {
				b.reserve(out)
				return out, nil
			}
			pos.Off += int64(i) + 1
			pos.N++
			size += int64(i) + 1
			out = append(out, Taken{Line: data[:i:i], End: pos})
			data = data[i+1:]
		}
		if len(out) >= maxEntries {
			break
		}
	}
	b.reserve(out)
	return out, nil
}

func (b *Buffer) reserve(out []Taken) {
	if len(out) > 0 {
		e := out[len(out)-1].End
		b.reserved = &e
	}
}

// Release clears a reservation without consuming.
func (b *Buffer) Release() {
	b.mu.Lock()
	b.reserved = nil
	b.mu.Unlock()
}

// Commit consumes everything up to end, deletes fully consumed segments and
// persists the cursor. droppedReported is subtracted from the pending drop
// counter (it was carried by the committed batch).
func (b *Buffer) Commit(end Cursor, droppedReported uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reserved = nil
	if b.cur.before(end) {
		b.cur = end
	}
	for len(b.segs) > 1 && b.segs[0].id < b.cur.Seg {
		b.removeFirstLocked()
	}
	// fully consumed non-active head segment
	if len(b.segs) > 1 && b.segs[0].id == b.cur.Seg && b.cur.Off >= b.segs[0].size {
		b.removeFirstLocked()
		b.cur = Cursor{Seg: b.segs[0].id}
	}
	b.ackDroppedLocked(droppedReported)
	return b.saveLocked()
}

func (b *Buffer) removeFirstLocked() {
	s := b.segs[0]
	_ = os.Remove(filepath.Join(b.dir, segName(s.id)))
	b.total -= s.size
	b.segs = b.segs[1:]
}

// ackDroppedLocked subtracts reported drops.
func (b *Buffer) ackDroppedLocked(n uint64) {
	if n == 0 {
		return
	}
	if n >= b.st.DroppedPending {
		b.st.DroppedPending = 0
		b.st.DroppedSince = nil
	} else {
		b.st.DroppedPending -= n
	}
}

// AddDropped counts entries lost outside the segment cap (e.g. agent log
// channel overflow or a batch the Center permanently rejected).
func (b *Buffer) AddDropped(n uint64) {
	if n == 0 {
		return
	}
	b.mu.Lock()
	b.st.DroppedTotal += n
	b.st.DroppedPending += n
	if b.st.DroppedSince == nil {
		s := FormatTS(b.now())
		b.st.DroppedSince = &s
	}
	_ = b.saveLocked()
	b.mu.Unlock()
}

// DroppedPending returns drops not yet reported in a batch (and since when).
func (b *Buffer) DroppedPending() (uint64, *string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st.DroppedSince == nil {
		return b.st.DroppedPending, nil
	}
	s := *b.st.DroppedSince
	return b.st.DroppedPending, &s
}

// BufferStats is a snapshot.
type BufferStats struct {
	Bytes          int64
	Cap            int64
	Segments       int
	Pending        int64
	DroppedTotal   uint64
	DroppedPending uint64
}

// Stats returns a snapshot.
func (b *Buffer) Stats() BufferStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return BufferStats{Bytes: b.total, Cap: b.cap, Segments: len(b.segs), Pending: b.pendingLocked(),
		DroppedTotal: b.st.DroppedTotal, DroppedPending: b.st.DroppedPending}
}

// SegmentBytes is the segment size in use.
func (b *Buffer) SegmentBytes() int64 { return b.segMax }

func (b *Buffer) saveLocked() error {
	if b.stateFile == "" {
		return nil
	}
	b.st.Cursor = b.cur
	raw, err := json.Marshal(&b.st)
	if err != nil {
		return err
	}
	return writeAtomic(b.stateFile, raw, false)
}

// Close flushes state and closes the active segment.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.saveLocked()
	if b.active != nil {
		b.active.Close()
		b.active = nil
	}
	return err
}

// writeAtomic writes via temp file + rename (0600) in the same directory.
func writeAtomic(path string, data []byte, sync bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if sync {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (b *Buffer) ackDropped(n uint64) {
	if n == 0 {
		return
	}
	b.mu.Lock()
	b.ackDroppedLocked(n)
	_ = b.saveLocked()
	b.mu.Unlock()
}
