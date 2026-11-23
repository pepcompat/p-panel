package logship

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
)

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
}

func copyTruncate(t *testing.T, path string) {
	t.Helper()
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	dst, _ := os.Create(path + ".1")
	io.Copy(dst, src)
	src.Close()
	dst.Close()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
}

func cl(prefix string, i int) string {
	return fmt.Sprintf("%s%03d %s", prefix, i, strings.Repeat("-", 90)) // ~100 bytes
}

func filePipeline(t *testing.T, state string, srcs ...config.LogSource) *Pipeline {
	t.Helper()
	cfg := testLogsCfg(64<<20, 1000)
	cfg.Sources = srcs
	p, err := New(Options{Logs: cfg, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// drain returns (and consumes) all buffered entries.
func drain(t *testing.T, p *Pipeline) []Entry {
	t.Helper()
	tk, err := p.Buffer().Take(1<<30, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	var out []Entry
	for _, x := range tk {
		var e Entry
		if err := json.Unmarshal(x.Line, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	if len(tk) > 0 {
		p.Buffer().Commit(tk[len(tk)-1].End, 0)
	}
	return out
}

func stopPipeline(p *Pipeline) {
	for _, t := range p.tailers {
		t.Close()
	}
	p.pos.Save()
	p.buf.Close()
}

func lines(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, strings.Fields(e.Line)[0])
	}
	return out
}

func expect(t *testing.T, got []Entry, want ...string) {
	t.Helper()
	g := strings.Join(lines(got), ",")
	if w := strings.Join(want, ","); g != w {
		t.Fatalf("got  [%s]\nwant [%s]", g, w)
	}
}

func TestTailerRenameRotationAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	log := filepath.Join(dir, "access.log")
	appendLines(t, log, "OLD1 existing before first start (skipped)")
	src := config.LogSource{Source: SourceNginxAccess, Path: log}
	p := filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p))
	appendLines(t, log, "L1 GET /?api_key=sk_live_abc123456 200", "L2", "L3")
	p.PollOnce()
	got := drain(t, p)
	expect(t, got, "L1", "L2", "L3")
	if got[0].Line != "L1 GET /?api_key=[REDACTED] 200" || got[0].Source != SourceNginxAccess || *got[0].File != log || got[0].Level != nil {
		t.Fatalf("entry %+v", got[0])
	}
	appendLines(t, log, "L4")
	stopPipeline(p)
	// rotated by rename while the agent is stopped
	appendLines(t, log, "L5")
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	appendLines(t, log, "L6", "L7")
	p = filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p), "L4", "L5", "L6", "L7")
	// rotated by rename while running (old file has an unpolled line)
	appendLines(t, log, "L8")
	p.PollOnce()
	appendLines(t, log, "L9")
	os.Rename(log, log+".1")
	p.PollOnce() // new file not created yet: keeps reading the old fd
	appendLines(t, log, "L10")
	p.PollOnce()
	p.PollOnce()
	expect(t, drain(t, p), "L8", "L9", "L10")
	stopPipeline(p)
	// restart without changes: no duplicates
	p = filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p))
	appendLines(t, log, "L11")
	p.PollOnce()
	expect(t, drain(t, p), "L11")
	stopPipeline(p)
}

func TestTailerCopyTruncateAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	log := filepath.Join(dir, "error.log")
	for i := 1; i <= 3; i++ {
		appendLines(t, log, cl("C", i))
	}
	src := config.LogSource{Source: SourceNginxError, Path: log}
	p := filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p)) // existing content skipped on first start
	appendLines(t, log, cl("C", 4), cl("C", 5), "2026/11/23 10:00:00 [error] 7#7: C006 upstream timed out")
	p.PollOnce()
	got := drain(t, p)
	expect(t, got, "C004", "C005", "2026/11/23")
	if got[2].Level == nil || *got[2].Level != "error" {
		t.Fatalf("nginx error level: %+v", got[2].Level)
	}
	// copytruncate while running, with unread lines copied away
	appendLines(t, log, cl("C", 7), cl("C", 8))
	copyTruncate(t, log)
	appendLines(t, log, cl("D", 9))
	p.PollOnce()
	expect(t, drain(t, p), "C007", "C008", "D009")
	// copytruncate while stopped; the new file grows past the old offset
	appendLines(t, log, cl("D", 10))
	p.PollOnce()
	expect(t, drain(t, p), "D010")
	appendLines(t, log, cl("D", 11))
	stopPipeline(p)
	appendLines(t, log, cl("D", 12))
	copyTruncate(t, log)
	var want []string
	want = append(want, "D011", "D012")
	for i := 13; i <= 20; i++ {
		appendLines(t, log, cl("E", i))
		want = append(want, fmt.Sprintf("E%03d", i))
	}
	p = filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p), want...)
	stopPipeline(p)
	p = filePipeline(t, state, src)
	p.PollOnce()
	expect(t, drain(t, p))
	stopPipeline(p)
}

func TestTailerFileCreatedLaterAndLongLines(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "late.log")
	p := filePipeline(t, filepath.Join(dir, "state"), config.LogSource{Source: SourceNginxAccess, Path: log})
	p.PollOnce()
	appendLines(t, log, "A1", strings.Repeat("z", 100<<10), "A3")
	p.PollOnce()
	got := drain(t, p)
	if len(got) != 3 || got[0].Line != "A1" || got[2].Line != "A3" {
		t.Fatalf("got %d entries: %v", len(got), lines(got))
	}
	if len(got[1].Line) > MaxLineBytes || !strings.HasSuffix(got[1].Line, TruncSuffix) {
		t.Fatalf("long line len=%d", len(got[1].Line))
	}
	stopPipeline(p)
}
