package netdiag

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Route is one kernel routing table entry (read-only, from /proc/net).
type Route struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Iface   string `json:"iface"`
	Metric  int64  `json:"metric"`
}

// MaxRoutes bounds the reported routes.
const MaxRoutes = 512

// ParseIPv4Routes parses /proc/net/route (little-endian hex fields).
func ParseIPv4Routes(r io.Reader) []Route {
	out := []Route{}
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		dst, ok1 := hexIPv4(f[1])
		gw, ok2 := hexIPv4(f[2])
		mask, ok3 := hexIPv4(f[7])
		metric, err := strconv.ParseInt(f[6], 10, 64)
		if !ok1 || !ok2 || !ok3 || err != nil {
			continue
		}
		bits := 0
		m := mask.As4()
		for _, b := range m {
			for i := 7; i >= 0; i-- {
				if b&(1<<i) != 0 {
					bits++
				}
			}
		}
		pfx, err := dst.Prefix(bits)
		if err != nil {
			continue
		}
		out = append(out, Route{Dst: pfx.String(), Gateway: gw.String(), Iface: f[0], Metric: metric})
		if len(out) >= MaxRoutes {
			break
		}
	}
	return out
}

func hexIPv4(s string) (netip.Addr, bool) {
	if len(s) != 8 {
		return netip.Addr{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	var a [4]byte
	binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
	return netip.AddrFrom4(a), true
}

// ParseIPv6Routes parses /proc/net/ipv6_route.
func ParseIPv6Routes(r io.Reader) []Route {
	out := []Route{}
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		dst, ok1 := hexIPv6(f[0])
		plen, err1 := strconv.ParseUint(f[1], 16, 8)
		gw, ok2 := hexIPv6(f[4])
		metric, err2 := strconv.ParseInt(f[5], 16, 64)
		if !ok1 || !ok2 || err1 != nil || err2 != nil || plen > 128 {
			continue
		}
		pfx, err := dst.Prefix(int(plen))
		if err != nil {
			continue
		}
		out = append(out, Route{Dst: pfx.String(), Gateway: gw.String(), Iface: f[9], Metric: metric})
		if len(out) >= MaxRoutes {
			break
		}
	}
	return out
}

func hexIPv6(s string) (netip.Addr, bool) {
	if len(s) != 32 {
		return netip.Addr{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a), true
}
