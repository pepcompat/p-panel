//go:build linux

package metrics

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func readCPUTimes() (CPUTimes, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return CPUTimes{}, false
	}
	defer f.Close()
	return ParseProcStat(f)
}

func readMem() (uint64, uint64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	return ParseMeminfo(f)
}

func readLoad() (float64, float64, float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	return ParseLoadavg(string(b))
}

func readUptime() (float64, bool) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}

func readNetCounters() []NetCounter {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()
	return ParseNetDev(f)
}

func cpuCount() int { return runtime.NumCPU() }

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "vfat": true, "f2fs": true}

func mountPoints() []string {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return []string{"/"}
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < 64 {
		p := strings.Fields(sc.Text())
		if len(p) < 3 || !realFS[p[2]] || seen[p[1]] {
			continue
		}
		seen[p[1]] = true
		out = append(out, p[1])
	}
	if len(out) == 0 {
		out = []string{"/"}
	}
	return out
}
