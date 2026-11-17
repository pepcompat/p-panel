package metrics

import (
	"strings"
	"testing"
)

func TestParseProcStat(t *testing.T) {
	a, ok := ParseProcStat(strings.NewReader("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n"))
	if !ok || a.Total != 1000 || a.Idle != 800 {
		t.Fatalf("got %+v %v", a, ok)
	}
	b, _ := ParseProcStat(strings.NewReader("cpu  200 0 200 1300 100 0 0 0 0 0\n"))
	pct, ok := CPUPercent(a, b)
	if !ok || pct != 25 {
		t.Fatalf("pct=%v ok=%v", pct, ok)
	}
	if _, ok := CPUPercent(b, a); ok {
		t.Fatal("expected not ok for non-monotonic sample")
	}
}

func TestParseMeminfo(t *testing.T) {
	total, avail, ok := ParseMeminfo(strings.NewReader("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n"))
	if !ok || total != 1000*1024 || avail != 400*1024 {
		t.Fatalf("%d %d %v", total, avail, ok)
	}
	_, avail, _ = ParseMeminfo(strings.NewReader("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 50 kB\n"))
	if avail != 200*1024 {
		t.Fatalf("fallback avail %d", avail)
	}
}

func TestParseLoadavgAndNetDev(t *testing.T) {
	l1, l5, l15, ok := ParseLoadavg("0.50 0.25 0.10 1/100 1234\n")
	if !ok || l1 != 0.5 || l5 != 0.25 || l15 != 0.1 {
		t.Fatal("loadavg")
	}
	nd := "Inter-|   Receive\n face |bytes\n  eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n    lo: 5 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n"
	c := ParseNetDev(strings.NewReader(nd))
	if len(c) != 2 || c[0].Interface != "eth0" || c[0].RxBytes != 100 || c[0].TxBytes != 200 {
		t.Fatalf("%+v", c)
	}
}

func TestSampleDegradesGracefully(t *testing.T) {
	var s Sampler
	_ = s.Sample()
	snap := s.Sample()
	if snap.DiskPct == nil {
		t.Fatal("disk usage should be available on all supported platforms")
	}
	d := s.Detailed()
	if d.CPUCount < 1 || d.Disks == nil || d.NetCounters == nil {
		t.Fatalf("detail %+v", d)
	}
}
