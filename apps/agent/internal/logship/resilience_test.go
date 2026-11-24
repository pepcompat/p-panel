package logship

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
)

// diskFull makes every buffer write fail with ENOSPC after writing half of
// the record (a torn line, like a real short write on a full disk).
func diskFull(b *Buffer, full *bool) {
	b.writeFn = func(f *os.File, p []byte) (int, error) {
		if *full {
			n, _ := f.Write(p[:len(p)/2])
			return n, syscall.ENOSPC
		}
		return f.Write(p)
	}
}

func filePipelineNow(t *testing.T, state string, now func() time.Time, srcs ...config.LogSource) *Pipeline {
	t.Helper()
	cfg := testLogsCfg(64<<20, 1000)
	cfg.Sources = srcs
	p, err := New(Options{Logs: cfg, StateDir: state, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func parseTS(t *testing.T, s string) int64 {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v.UnixNano()
}

// F-1: identical lines read in one pass (and across passes / restarts with a
// frozen or backwards clock) must get unique, strictly increasing timestamps,
// otherwise Loki silently de-duplicates them.
func TestPollOnceUniqueMonotonicTimestamps(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	log := filepath.Join(dir, "access.log")
	appendLines(t, log)
	frozen := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	clock := frozen
	now := func() time.Time { return clock }
	src := config.LogSource{Source: SourceNginxAccess, Path: log}
	p := filePipelineNow(t, state, now, src)
	p.PollOnce()
	same := `127.0.0.1 - - "GET /health HTTP/1.1" 200 2`
	appendLines(t, log, same, same, same, same, same)
	p.PollOnce()
	appendLines(t, log, same, same, same)
	p.PollOnce() // same wall clock as the previous pass
	got := drain(t, p)
	stopPipeline(p)
	clock = frozen.Add(-time.Hour) // clock stepped back across a restart
	p = filePipelineNow(t, state, now, src)
	appendLines(t, log, same, same)
	p.PollOnce()
	got = append(got, drain(t, p)...)
	stopPipeline(p)
	if len(got) != 10 {
		t.Fatalf("got %d entries", len(got))
	}
	var last int64
	for i, e := range got {
		ts := parseTS(t, e.TS)
		if ts <= last {
			t.Fatalf("entry %d ts %s not after previous", i, e.TS)
		}
		last = ts
	}
	if parseTS(t, got[0].TS) != frozen.UnixNano() {
		t.Fatalf("first ts %s, want the poll time", got[0].TS)
	}
}

// F-10: lines read while the buffer cannot be written (disk full) are not
// lost: the tail position does not advance, and the lines are buffered
// exactly once (no torn record, no duplicate) once space is back.
func TestPollOnceAppendFailureRewinds(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	log := filepath.Join(dir, "access.log")
	appendLines(t, log)
	src := config.LogSource{Source: SourceNginxAccess, Path: log}
	p := filePipeline(t, state, src)
	full := false
	diskFull(p.buf, &full)
	p.PollOnce()
	appendLines(t, log, "A1", "A2")
	p.PollOnce()
	expect(t, drain(t, p), "A1", "A2")

	full = true
	appendLines(t, log, "B1", "B2", "B3")
	p.PollOnce()
	appendLines(t, log, "B4")
	p.PollOnce()
	if st := p.buf.Stats(); st.Pending != 0 || st.PendingBytes != 0 {
		t.Fatalf("failed appends left data in the buffer: %+v", st)
	}
	if fp, _ := p.pos.File(log); fp.Off != int64(len("A1\nA2\n")) {
		t.Fatalf("position advanced past unbuffered lines: %d", fp.Off)
	}
	full = false
	p.PollOnce()
	expect(t, drain(t, p), "B1", "B2", "B3", "B4")
	if st := p.buf.Stats(); st.DroppedTotal != 0 {
		t.Fatalf("nothing was lost, dropped=%d", st.DroppedTotal)
	}
	stopPipeline(p)
}

// F-10: a rename rotation inside a failed pass, and a restart while still
// failing, still deliver every line once.
func TestPollOnceAppendFailureAcrossRotationAndRestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	log := filepath.Join(dir, "access.log")
	appendLines(t, log)
	src := config.LogSource{Source: SourceNginxAccess, Path: log}
	p := filePipeline(t, state, src)
	full := false
	diskFull(p.buf, &full)
	p.PollOnce()
	full = true
	appendLines(t, log, "R1", "R2")
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	appendLines(t, log, "R3")
	p.PollOnce() // drains old + opens new: fails
	appendLines(t, log, "R4")
	p.PollOnce() // still failing
	full = false
	p.PollOnce()
	expect(t, drain(t, p), "R1", "R2", "R3", "R4")
	full = true
	appendLines(t, log, "S1")
	p.PollOnce()
	stopPipeline(p)
	p = filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p), "S1")
	stopPipeline(p)
}

// First open without a saved position (start at EOF) failing must not skip
// lines written before the retry.
func TestPollOnceFirstOpenFailureKeepsStart(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "access.log")
	appendLines(t, log, "OLD (skipped)")
	p := filePipeline(t, filepath.Join(dir, "state"), config.LogSource{Source: SourceNginxAccess, Path: log})
	full := true
	diskFull(p.buf, &full)
	appendLines(t, log, "N1")
	appendLines(t, log, "N1b")
	p.PollOnce() // first open starts at EOF (after N1); nothing to append
	// a line between a failed first pass and the retry
	appendLines(t, log, "N2")
	full = false
	p.PollOnce()
	got := lines(drain(t, p))
	// the first open starts at EOF (OLD and N1 existed already); N2 must be there
	if len(got) != 1 || got[0] != "N2" {
		t.Fatalf("got %v", got)
	}
	stopPipeline(p)
}

// Append is all-or-nothing even when the failure happens after a segment
// rotation in the middle of a batch.
func TestBufferAppendRollbackAcrossSegments(t *testing.T) {
	d := t.TempDir()
	b, err := OpenBuffer(BufferOptions{Dir: filepath.Join(d, "buffer"), StateFile: filepath.Join(d, "cursor.json"), CapBytes: 1 << 20, SegmentBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for i := 0; i < 3; i++ {
		if err := b.Append(entry(i, 50)); err != nil {
			t.Fatal(err)
		}
	}
	before := b.Stats()
	writes := 0
	b.writeFn = func(f *os.File, p []byte) (int, error) {
		writes++
		if writes > 20 {
			n, _ := f.Write(p[:10])
			return n, syscall.ENOSPC
		}
		return f.Write(p)
	}
	var batch []Entry
	for i := 0; i < 40; i++ {
		batch = append(batch, entry(100+i, 50))
	}
	if err := b.Append(batch...); err == nil {
		t.Fatal("want error")
	}
	after := b.Stats()
	if after.Pending != before.Pending || after.Bytes != before.Bytes || after.Segments != before.Segments {
		t.Fatalf("not rolled back: before %+v after %+v", before, after)
	}
	if size, _ := dirSize(t, filepath.Join(d, "buffer")); size != before.Bytes {
		t.Fatalf("on-disk %d != %d (torn bytes left)", size, before.Bytes)
	}
	b.writeFn = nil
	if err := b.Append(entry(999, 5)); err != nil {
		t.Fatal(err)
	}
	tk, err := b.Take(1000, 1<<30)
	if err != nil || len(tk) != 4 {
		t.Fatalf("take %d %v", len(tk), err)
	}
	for _, x := range tk {
		var e Entry
		if err := json.Unmarshal(x.Line, &e); err != nil {
			t.Fatalf("corrupt record %q: %v", x.Line, err)
		}
	}
}

// F-2: bufferedBytes is the unshipped backlog, not the on-disk size.
func TestStatusBufferedBytesIsPendingOnly(t *testing.T) {
	dir := t.TempDir()
	p := filePipeline(t, filepath.Join(dir, "state"))
	for i := 0; i < 10; i++ {
		if err := p.buf.Append(entry(i, 20)); err != nil {
			t.Fatal(err)
		}
	}
	if s := p.Status(); s.BufferedBytes <= 0 || s.BufferedBytes != p.buf.Stats().Bytes {
		t.Fatalf("pending %d", s.BufferedBytes)
	}
	drain(t, p)
	if s := p.Status(); s.BufferedBytes != 0 || p.buf.Stats().Bytes == 0 {
		t.Fatalf("after shipping: buffered %d (disk %d)", s.BufferedBytes, p.buf.Stats().Bytes)
	}
	stopPipeline(p)
}

// Agent records that cannot be buffered exist nowhere else: they are counted
// as dropped instead of vanishing.
func TestAgentSinkAppendFailureCounted(t *testing.T) {
	dir := t.TempDir()
	cfg := testLogsCfg(4<<20, 1000)
	sink := NewAgentSink()
	p, err := New(Options{Logs: cfg, StateDir: filepath.Join(dir, "state"), Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	full := true
	diskFull(p.buf, &full)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.drainAgent(ctx); close(done) }()
	sink.ch <- agentRec{t: time.Now(), line: "x"}
	sink.ch <- agentRec{t: time.Now(), line: "y"}
	waitFor(t, "2 drops", 2*time.Second, func() bool { return p.buf.Stats().DroppedTotal == 2 })
	cancel()
	<-done
	p.buf.Close()
}
