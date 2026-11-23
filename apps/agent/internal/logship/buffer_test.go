package logship

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dirSize(t *testing.T, dir string) (total int64, files int) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		fi, err := de.Info()
		if err == nil && !fi.IsDir() {
			total += fi.Size()
			files++
		}
	}
	return
}

func entry(i int, pad int) Entry {
	return Entry{TS: FormatTS(time.Now()), Source: SourceAgent, Line: fmt.Sprintf("line-%06d %s", i, strings.Repeat("x", pad))}
}

func TestBufferTakeCommitAndRecover(t *testing.T) {
	d := t.TempDir()
	open := func() *Buffer {
		b, err := OpenBuffer(BufferOptions{Dir: filepath.Join(d, "buffer"), StateFile: filepath.Join(d, "cursor.json"), CapBytes: 1 << 20, SegmentBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := open()
	for i := 0; i < 100; i++ {
		if err := b.Append(entry(i, 50)); err != nil {
			t.Fatal(err)
		}
	}
	if st := b.Stats(); st.Pending != 100 || st.Segments < 2 {
		t.Fatalf("stats %+v", st)
	}
	tk, err := b.Take(30, 1<<20)
	if err != nil || len(tk) != 30 || !strings.Contains(string(tk[29].Line), "line-000029") {
		t.Fatalf("take: %v %d", err, len(tk))
	}
	if err := b.Commit(tk[29].End, 0); err != nil {
		t.Fatal(err)
	}
	b.Close()
	// torn write at the end of the active segment is truncated on recovery
	segs, _ := filepath.Glob(filepath.Join(d, "buffer", "seg-*.jsonl"))
	f, _ := os.OpenFile(segs[len(segs)-1], os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"ts":"partial`)
	f.Close()
	b = open()
	defer b.Close()
	if st := b.Stats(); st.Pending != 70 {
		t.Fatalf("after reopen pending=%d want 70", st.Pending)
	}
	tk, _ = b.Take(1000, 1<<20)
	if len(tk) != 70 || !strings.Contains(string(tk[0].Line), "line-000030") {
		t.Fatalf("resume: %d %s", len(tk), tk[0].Line)
	}
	b.Commit(tk[len(tk)-1].End, 0)
	if st := b.Stats(); st.Pending != 0 || st.Segments != 1 {
		t.Fatalf("after full commit %+v", st)
	}
}

func TestBufferTakeRespectsByteBudget(t *testing.T) {
	b, err := OpenBuffer(BufferOptions{Dir: t.TempDir(), CapBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		b.Append(entry(i, 1000))
	}
	tk, _ := b.Take(1000, 10_000)
	if len(tk) == 0 || len(tk) > 10 {
		t.Fatalf("byte budget ignored: %d", len(tk))
	}
}

// P5-T04 (agent side): Center down, generate far more than the cap. On-disk
// size stays ≤ cap + one segment, drops are counted, memory stays bounded,
// and the in-flight batch is retained (never dropped while retrying).
func TestBufferCapWithCenterDown(t *testing.T) {
	d := t.TempDir()
	const capBytes = 1 << 20
	p, err := New(Options{Logs: testLogsCfg(capBytes, 1000), StateDir: d, BackoffMin: time.Millisecond, BackoffMax: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	segBytes := p.Buffer().SegmentBytes()
	var calls atomic.Int64
	down := func(ctx context.Context, gz []byte) error {
		calls.Add(1)
		return errors.New("dial tcp: connection refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, down); close(done) }()

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	var generated int64
	for i := 0; generated < 8*capBytes; i++ {
		e := entry(i, 400)
		generated += int64(len(e.Line)) + 100
		if err := p.Buffer().Append(e); err != nil {
			t.Fatal(err)
		}
		if i%2000 == 0 {
			size, _ := dirSize(t, filepath.Join(d, "buffer"))
			if size > capBytes+segBytes {
				t.Fatalf("on-disk %d > cap %d + segment %d", size, capBytes, segBytes)
			}
		}
	}
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	size, files := dirSize(t, filepath.Join(d, "buffer"))
	st := p.Status()
	t.Logf("generated≈%d B, on-disk=%d B in %d segments (cap %d, seg %d), droppedEntries=%d, bufferedBytes=%d, send attempts=%d, heap Δ=%d KiB",
		generated, size, files, capBytes, segBytes, st.DroppedEntries, st.BufferedBytes, calls.Load(), (int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/1024)
	if size > capBytes+segBytes {
		t.Fatalf("on-disk %d > cap+segment", size)
	}
	if st.DroppedEntries == 0 {
		t.Fatal("droppedEntries must be > 0")
	}
	if st.BufferedBytes > capBytes || st.BufferCapBytes != capBytes {
		t.Fatalf("status %+v", st)
	}
	if growth := int64(m1.HeapAlloc) - int64(m0.HeapAlloc); growth > 16<<20 {
		t.Fatalf("heap grew %d bytes for %d generated: memory not bounded", growth, generated)
	}
	cancel()
	<-done
	// the in-flight batch is retained on disk for the next attempt
	if _, err := os.Stat(filepath.Join(d, "inflight.bin")); err != nil {
		t.Fatalf("in-flight batch not retained: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(d, "inflight.bin")); fi.Size() > MaxBatchGzip+1024 {
		t.Fatalf("in-flight batch too big: %d", fi.Size())
	}
	dp, since := p.Buffer().DroppedPending()
	if dp == 0 || since == nil {
		t.Fatalf("dropped pending %d since %v", dp, since)
	}
}
