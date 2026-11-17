//go:build darwin

package metrics

import (
	"encoding/binary"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// darwin is a development platform only: CPU% is not sampled (nil).
func readCPUTimes() (CPUTimes, bool) { return CPUTimes{}, false }

func readMem() (uint64, uint64, bool) {
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0, 0, false
	}
	// Available memory needs host_statistics (mach); report total only.
	return total, total, false
}

func readLoad() (float64, float64, float64, bool) {
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil || len(raw) < 16 {
		return 0, 0, 0, false
	}
	// struct loadavg { fixpt_t ldavg[3]; long fscale; }
	scale := float64(binary.LittleEndian.Uint64(raw[len(raw)-8:]))
	if scale == 0 {
		return 0, 0, 0, false
	}
	l := func(i int) float64 { return float64(binary.LittleEndian.Uint32(raw[i*4:])) / scale }
	return round2(l(0)), round2(l(1)), round2(l(2)), true
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

func readUptime() (float64, bool) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0, false
	}
	return time.Since(time.Unix(tv.Unix())).Seconds(), true
}

func readNetCounters() []NetCounter { return nil }
func cpuCount() int                 { return runtime.NumCPU() }
func mountPoints() []string         { return []string{"/"} }
