package logship

import (
	"bytes"
	"errors"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// FingerprintBytes is how much of a file's head identifies it across
// copytruncate / restarts.
const FingerprintBytes = 256

// DefaultReadLimit bounds bytes read per source per poll (the tailer falls
// behind instead of flooding; its position keeps the place).
const DefaultReadLimit = 4 << 20

// Tailer follows one log file with inode/offset tracking. It handles rename
// rotation (drains the old file, then the new one from 0) and copytruncate
// (recovers lines written before the truncate from <path>.1 when its head
// fingerprint matches), including rotations that happened while the agent was
// stopped. Not safe for concurrent use.
type Tailer struct {
	Source string
	Path   string
	pos    *Positions
	// ReadLimit per poll (default DefaultReadLimit).
	ReadLimit int64

	f        *os.File
	cur      FilePos
	skipping bool // discarding the rest of an overlong line
	opened   bool // a position exists (first open done)
	atEnd    bool // first open without a saved position starts at EOF

	// snap is the state at the start of the last Poll (see Rewind).
	snap tailSnap
	// openStart is where the last first-open (no saved position) started.
	openStart *FilePos
	// resume overrides the saved position at the next open (set by Rewind
	// when the file it rewinds into was closed during the failed Poll).
	resume *FilePos
}

type tailSnap struct {
	f        *os.File
	cur      FilePos
	skipping bool
	atEnd    bool
}

// NewTailer returns a tailer. startAtEnd: when no position is saved and the
// file already exists at the first poll, skip its existing content.
func NewTailer(source, path string, pos *Positions, startAtEnd bool) *Tailer {
	return &Tailer{Source: source, Path: path, pos: pos, ReadLimit: DefaultReadLimit, atEnd: startAtEnd}
}

func statID(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // Dev is int32 on darwin
	}
	return 0, 0
}

// fingerprint hashes the first n bytes (0 when the file is shorter).
func fingerprint(f *os.File, n int64) uint64 {
	if n <= 0 {
		return 0
	}
	b := make([]byte, n)
	m, _ := f.ReadAt(b, 0)
	if int64(m) < n {
		return 0
	}
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64() | 1 // never 0
}

// updateFp (re)computes the head fingerprint over min(Off, FingerprintBytes).
func (t *Tailer) updateFp(f *os.File) {
	n := t.cur.Off
	if n > FingerprintBytes {
		n = FingerprintBytes
	}
	if n > t.cur.FpLen {
		t.cur.Fp, t.cur.FpLen = fingerprint(f, n), n
	}
}

// Close releases the open file.
func (t *Tailer) Close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// Poll reads newly appended complete lines and calls emit for each (raw bytes,
// not yet sanitized). It returns the position to persist AFTER the emitted
// lines are durably buffered (call Commit with it).
func (t *Tailer) Poll(emit func([]byte)) (FilePos, bool) {
	t.snap = tailSnap{f: t.f, cur: t.cur, skipping: t.skipping, atEnd: t.atEnd}
	t.openStart = nil
	limit := t.ReadLimit
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	if t.f == nil {
		if !t.open(emit, &limit) {
			return t.cur, false
		}
	} else if fi, err := t.f.Stat(); err == nil && t.truncated(fi.Size()) {
		// copytruncate: recover lines copied to <path>.1, then restart at 0
		t.recoverCopy(emit, &limit)
		t.cur.Off, t.cur.Fp, t.cur.FpLen, t.skipping = 0, 0, 0, false
	}
	// 1. read what was appended to the open file
	t.read(t.f, emit, false, &limit)
	if limit <= 0 {
		return t.cur, true
	}
	// 2. detect rename rotation
	fi, err := os.Stat(t.Path)
	if err != nil {
		return t.cur, true // renamed, new file not created yet: keep the old fd
	}
	if dev, ino := statID(fi); dev != t.cur.Dev || ino != t.cur.Ino {
		// drain the old file (including a trailing partial line)
		t.read(t.f, emit, true, &limit)
		if limit <= 0 {
			return t.cur, true
		}
		t.Close()
		nf, err := os.Open(t.Path)
		if err != nil {
			return t.cur, true
		}
		t.f = nf
		nfi, err := nf.Stat()
		if err != nil {
			return t.cur, true
		}
		t.cur.Dev, t.cur.Ino = statID(nfi)
		t.cur.Off, t.cur.Fp, t.cur.FpLen, t.skipping = 0, 0, 0, false
		t.read(t.f, emit, false, &limit)
	}
	return t.cur, true
}

// Rewind undoes the last Poll: the lines it emitted were not durably buffered
// (e.g. disk full), so the next Poll must emit them again. If that Poll
// rotated to a new file or opened the file for the first time, the new handle
// is closed and the next Poll re-opens through the normal restart logic,
// resuming from the pre-Poll position (draining <path>.1 after a rotation).
func (t *Tailer) Rewind() {
	s := t.snap
	if t.f != s.f {
		t.Close()
		switch {
		case s.f != nil:
			// rotated during the failed Poll: the old fd is gone; resume it via <path>.1
			r := s.cur
			t.resume = &r
		case t.openStart != nil:
			// first open without a saved position: start from the same place again
			r := *t.openStart
			t.resume = &r
		}
	}
	t.cur, t.skipping, t.atEnd = s.cur, s.skipping, s.atEnd
}

// savedPos is the position to resume from at open: a pending Rewind target,
// else the committed position.
func (t *Tailer) savedPos() (FilePos, bool) {
	if t.resume != nil {
		return *t.resume, true
	}
	return t.pos.File(t.Path)
}

// truncated reports copytruncate on the open file: shrunk, or rewritten past
// our offset with a different head.
func (t *Tailer) truncated(size int64) bool {
	if size < t.cur.Off {
		return true
	}
	if t.cur.Fp != 0 && fingerprint(t.f, t.cur.FpLen) != t.cur.Fp {
		return true
	}
	return false
}

// recoverCopy reads <path>.1 from our old offset when its head matches the
// file we were reading (the lines copied away before truncation).
func (t *Tailer) recoverCopy(emit func([]byte), limit *int64) {
	if t.cur.Fp == 0 {
		return
	}
	old, err := os.Open(t.Path + ".1")
	if err != nil {
		return
	}
	defer old.Close()
	if fingerprint(old, t.cur.FpLen) != t.cur.Fp {
		return
	}
	saved := t.cur
	t.readAt(old, emit, true, limit)
	t.cur = saved
}

// open opens the file at startup or after it appeared, honouring the saved
// position (and draining <path>.1 if the file rotated while we were down).
func (t *Tailer) open(emit func([]byte), limit *int64) bool {
	f, err := os.Open(t.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// a file created later is new: read it from the start
			if _, ok := t.savedPos(); !ok {
				t.atEnd = false
			}
		}
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return false
	}
	dev, ino := statID(fi)
	saved, ok := t.savedPos()
	t.resume = nil
	t.f = f
	switch {
	case ok && saved.Dev == dev && saved.Ino == ino:
		t.cur = saved
		if t.truncated(fi.Size()) {
			t.recoverCopy(emit, limit)
			t.cur.Off, t.cur.Fp, t.cur.FpLen = 0, 0, 0
		}
	case ok:
		// rotated while stopped: drain the renamed file if it is the one we knew
		if old, err := os.Open(t.Path + ".1"); err == nil {
			if ofi, err := old.Stat(); err == nil {
				od, oi := statID(ofi)
				if od == saved.Dev && oi == saved.Ino {
					t.cur = saved
					t.readAt(old, emit, true, limit)
				}
			}
			old.Close()
		}
		t.cur = FilePos{Dev: dev, Ino: ino}
	default:
		t.cur = FilePos{Dev: dev, Ino: ino}
		if t.atEnd {
			t.cur.Off = fi.Size()
			// do not start mid-line
			if t.cur.Off > 0 {
				t.cur.Off = lastNewline(f, t.cur.Off)
			}
			t.updateFp(f)
		}
		st := t.cur
		t.openStart = &st
	}
	t.atEnd = false
	return true
}

func lastNewline(f *os.File, size int64) int64 {
	start := size - MaxRawLine
	if start < 0 {
		start = 0
	}
	b := make([]byte, size-start)
	n, _ := f.ReadAt(b, start)
	if i := bytes.LastIndexByte(b[:n], '\n'); i >= 0 {
		return start + int64(i) + 1
	}
	return size
}

func (t *Tailer) read(f *os.File, emit func([]byte), final bool, limit *int64) {
	t.readAt(f, emit, final, limit)
	t.updateFp(f)
}

// readAt consumes complete lines from t.cur.Off. final=true also emits a
// trailing partial line (file is done: rotated away).
func (t *Tailer) readAt(f *os.File, emit func([]byte), final bool, limit *int64) {
	chunk := make([]byte, 64<<10)
	var pending []byte
	readPos := t.cur.Off
	for *limit > 0 {
		n, err := f.ReadAt(chunk, readPos)
		if n > 0 {
			readPos += int64(n)
			*limit -= int64(n)
			pending = append(pending, chunk[:n]...)
			for {
				i := bytes.IndexByte(pending, '\n')
				if i < 0 {
					break
				}
				if t.skipping {
					t.skipping = false
				} else {
					emit(pending[:i])
				}
				t.cur.Off += int64(i) + 1
				pending = pending[i+1:]
			}
			if len(pending) >= MaxRawLine {
				if !t.skipping {
					emit(pending)
				}
				t.skipping = true
				t.cur.Off += int64(len(pending))
				pending = nil
			}
			if len(pending) == 0 {
				pending = pending[:0:0]
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && final && len(pending) > 0 {
				if !t.skipping {
					emit(pending)
				}
				t.cur.Off += int64(len(pending))
				t.skipping = false
			}
			return
		}
	}
}
