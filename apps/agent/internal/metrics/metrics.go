// Package metrics samples host CPU/memory/disk/load/uptime and network counters.
//
// Linux reads /proc directly (no cgo, no external deps). Other platforms
// (darwin for local development) degrade gracefully: unknown values are nil
// and omitted from JSON rather than reported as zero.
package metrics

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Snapshot is the heartbeat metrics payload. Nil = unknown (omitted).
type Snapshot struct {
	CPUPct    *float64 `json:"cpuPct,omitempty"`
	MemPct    *float64 `json:"memPct,omitempty"`
	DiskPct   *float64 `json:"diskPct,omitempty"`
	Load1     *float64 `json:"load1,omitempty"`
	UptimeSec *float64 `json:"uptimeSec,omitempty"`
}

// Detail is the richer inventory view.
type Detail struct {
	Snapshot
	CPUCount    int          `json:"cpuCount"`
	MemTotalB   uint64       `json:"memTotalBytes,omitempty"`
	MemAvailB   uint64       `json:"memAvailableBytes,omitempty"`
	Load5       *float64     `json:"load5,omitempty"`
	Load15      *float64     `json:"load15,omitempty"`
	Disks       []DiskUsage  `json:"disks"`
	NetCounters []NetCounter `json:"netCounters"`
}

// DiskUsage is filesystem usage for one mountpoint.
type DiskUsage struct {
	Mount      string  `json:"mount"`
	TotalBytes uint64  `json:"totalBytes"`
	FreeBytes  uint64  `json:"freeBytes"`
	UsedPct    float64 `json:"usedPct"`
}

// NetCounter is cumulative interface byte counters.
type NetCounter struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
}

// CPUTimes is an aggregate /proc/stat cpu line.
type CPUTimes struct{ Idle, Total uint64 }

// Sampler keeps the previous CPU sample to compute utilisation deltas.
type Sampler struct {
	mu   sync.Mutex
	prev *CPUTimes
}

func f64(v float64) *float64 { return &v }

// Sample returns a heartbeat snapshot.
func (s *Sampler) Sample() Snapshot {
	var out Snapshot
	if cur, ok := readCPUTimes(); ok {
		s.mu.Lock()
		if s.prev != nil {
			if pct, ok := CPUPercent(*s.prev, cur); ok {
				out.CPUPct = f64(pct)
			}
		}
		s.prev = &cur
		s.mu.Unlock()
	}
	if total, avail, ok := readMem(); ok && total > 0 {
		out.MemPct = f64(round1(float64(total-avail) / float64(total) * 100))
	}
	if d, ok := DiskUsageOf("/"); ok {
		out.DiskPct = f64(d.UsedPct)
	}
	if l1, _, _, ok := readLoad(); ok {
		out.Load1 = f64(l1)
	}
	if up, ok := readUptime(); ok {
		out.UptimeSec = f64(up)
	}
	return out
}

// Detailed returns a full inventory snapshot.
func (s *Sampler) Detailed() Detail {
	d := Detail{Snapshot: s.Sample(), CPUCount: cpuCount()}
	if total, avail, ok := readMem(); ok {
		d.MemTotalB, d.MemAvailB = total, avail
	}
	if _, l5, l15, ok := readLoad(); ok {
		d.Load5, d.Load15 = f64(l5), f64(l15)
	}
	for _, m := range mountPoints() {
		if u, ok := DiskUsageOf(m); ok {
			d.Disks = append(d.Disks, u)
		}
	}
	d.NetCounters = readNetCounters()
	if d.Disks == nil {
		d.Disks = []DiskUsage{}
	}
	if d.NetCounters == nil {
		d.NetCounters = []NetCounter{}
	}
	return d
}

// DiskUsageOf returns statfs usage for a path.
func DiskUsageOf(path string) (DiskUsage, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return DiskUsage{}, false
	}
	bs := uint64(st.Bsize)
	total := uint64(st.Blocks) * bs
	free := uint64(st.Bavail) * bs
	used := total - uint64(st.Bfree)*bs
	pct := 0.0
	if used+free > 0 {
		pct = round1(float64(used) / float64(used+free) * 100)
	}
	return DiskUsage{Mount: path, TotalBytes: total, FreeBytes: free, UsedPct: pct}, true
}

// CPUPercent computes busy% between two samples.
func CPUPercent(prev, cur CPUTimes) (float64, bool) {
	if cur.Total <= prev.Total {
		return 0, false
	}
	dt := float64(cur.Total - prev.Total)
	di := float64(cur.Idle - prev.Idle)
	if cur.Idle < prev.Idle {
		di = 0
	}
	return round1((dt - di) / dt * 100), true
}

// ParseProcStat parses the aggregate "cpu" line of /proc/stat.
func ParseProcStat(r io.Reader) (CPUTimes, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var t CPUTimes
		for i, v := range f[1:] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return CPUTimes{}, false
			}
			// user nice system idle iowait irq softirq steal guest guest_nice
			if i >= 8 { // guest time is already included in user/nice
				break
			}
			t.Total += n
			if i == 3 || i == 4 {
				t.Idle += n
			}
		}
		return t, true
	}
	return CPUTimes{}, false
}

// ParseMeminfo returns MemTotal and MemAvailable in bytes.
func ParseMeminfo(r io.Reader) (total, avail uint64, ok bool) {
	sc := bufio.NewScanner(r)
	var free, buffers, cached uint64
	haveAvail := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		n *= 1024
		switch f[0] {
		case "MemTotal:":
			total = n
		case "MemAvailable:":
			avail, haveAvail = n, true
		case "MemFree:":
			free = n
		case "Buffers:":
			buffers = n
		case "Cached:":
			cached = n
		}
	}
	if !haveAvail {
		avail = free + buffers + cached
	}
	if avail > total {
		avail = total
	}
	return total, avail, total > 0
}

// ParseLoadavg parses /proc/loadavg.
func ParseLoadavg(s string) (l1, l5, l15 float64, ok bool) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return 0, 0, 0, false
	}
	var err1, err2, err3 error
	l1, err1 = strconv.ParseFloat(f[0], 64)
	l5, err2 = strconv.ParseFloat(f[1], 64)
	l15, err3 = strconv.ParseFloat(f[2], 64)
	return l1, l5, l15, err1 == nil && err2 == nil && err3 == nil
}

// ParseNetDev parses /proc/net/dev.
func ParseNetDev(r io.Reader) []NetCounter {
	var out []NetCounter
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		out = append(out, NetCounter{Interface: strings.TrimSpace(name), RxBytes: rx, TxBytes: tx})
	}
	return out
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
