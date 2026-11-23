package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func frameOf(stream byte, s string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func TestDemuxLines(t *testing.T) {
	var in bytes.Buffer
	in.Write(frameOf(1, "2026-11-23T10:00:00.000000001Z hel"))
	in.Write(frameOf(2, "2026-11-23T10:00:00.5Z err line\n"))
	in.Write(frameOf(1, "lo\n2026-11-23T10:00:01Z second\r\n"))
	in.Write(frameOf(1, "no-ts partial"))
	var got []LogLine
	if err := DemuxLines(&in, false, func(l LogLine) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%d lines: %+v", len(got), got)
	}
	if got[0].Stream != "stderr" || string(got[0].Line) != "err line" || got[0].TS.Nanosecond() != 500000000 {
		t.Fatalf("0: %+v", got[0])
	}
	if got[1].Stream != "stdout" || string(got[1].Line) != "hello" || got[1].TS.Nanosecond() != 1 {
		t.Fatalf("1: %+v %q", got[1], got[1].Line)
	}
	if string(got[2].Line) != "second" || string(got[3].Line) != "no-ts partial" || !got[3].TS.IsZero() {
		t.Fatalf("2/3: %q %q", got[2].Line, got[3].Line)
	}
	// raw (tty) stream
	got = nil
	DemuxLines(strings.NewReader("2026-11-23T10:00:00Z a\r\n2026-11-23T10:00:00Z b\n"), true, func(l LogLine) { got = append(got, l) })
	if len(got) != 2 || got[0].Stream != "" || string(got[1].Line) != "b" {
		t.Fatalf("raw %+v", got)
	}
}

func TestSinceParamAndCPU(t *testing.T) {
	ts := time.Date(2026, 11, 23, 10, 0, 0, 3_000_000, time.UTC)
	if s := SinceParam(ts); s != "1795428000.003000001" {
		t.Fatal(s)
	}
	if SinceParam(time.Time{}) != "" {
		t.Fatal("zero")
	}
	var a, b CPUStats
	a.SystemUsage, a.CPUUsage.TotalUsage = 1000, 100
	b.SystemUsage, b.CPUUsage.TotalUsage, b.OnlineCPUs = 2000, 150, 4
	if p, ok := CPUPercent(a, b); !ok || p != 20 {
		t.Fatal(p, ok)
	}
	if _, ok := CPUPercent(CPUStats{}, b); ok {
		t.Fatal("no previous sample must be unknown")
	}
}

func TestTelemetryCallsValidateIDAndStayGET(t *testing.T) {
	c := New("/nonexistent.sock")
	if _, err := c.ContainerStats(context.Background(), "../../exec"); err == nil {
		t.Fatal("bad id accepted")
	}
	if err := c.FollowLogs(context.Background(), "abc/../x", "", false, func(LogLine) {}); err == nil {
		t.Fatal("bad id accepted")
	}
	// the stream client is GET-only too
	if _, ok := c.stream.Transport.(getOnly); !ok {
		t.Fatal("stream transport must be getOnly")
	}
}
