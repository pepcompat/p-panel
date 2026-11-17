package host

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Listener is a listening TCP socket with (best-effort) owning process.
type Listener struct {
	Proto   string `json:"proto"` // tcp|tcp6
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	inode   string
}

// ListeningPorts reads /proc/net/tcp{,6} and maps socket inodes to processes.
// Linux only; returns an error elsewhere.
func (e *Env) ListeningPorts() ([]Listener, error) {
	var out []Listener
	found := false
	for _, p := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(e.proc(), "net", p))
		if err != nil {
			continue
		}
		found = true
		out = append(out, ParseProcNetTCP(io.LimitReader(f, 8<<20), p)...)
		f.Close()
	}
	if !found {
		return nil, fmt.Errorf("%s/net/tcp not available on this platform", e.proc())
	}
	e.mapInodes(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Address < out[j].Address
	})
	if out == nil {
		out = []Listener{}
	}
	return out, nil
}

// ParseProcNetTCP returns LISTEN (state 0A) sockets.
func ParseProcNetTCP(r io.Reader, proto string) []Listener {
	var out []Listener
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		host, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		addr, ok := decodeProcAddr(host)
		if !ok {
			continue
		}
		out = append(out, Listener{Proto: proto, Address: addr, Port: int(port), inode: f[9]})
	}
	return out
}

// decodeProcAddr decodes the little-endian-per-32-bit-word hex address.
func decodeProcAddr(h string) (string, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", false
	}
	return a.Unmap().String(), true
}

func (e *Env) mapInodes(ls []Listener) {
	want := map[string]int{}
	for i, l := range ls {
		want["socket:["+l.inode+"]"] = i
	}
	pids, _ := filepath.Glob(filepath.Join(e.proc(), "[0-9]*"))
	if len(pids) > 20000 {
		pids = pids[:20000]
	}
	for _, pd := range pids {
		fds, err := os.ReadDir(filepath.Join(pd, "fd"))
		if err != nil {
			continue // not permitted / exited
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(pd, "fd", fd.Name()))
			if err != nil {
				continue
			}
			if i, ok := want[link]; ok && ls[i].PID == 0 {
				pid, _ := strconv.Atoi(filepath.Base(pd))
				ls[i].PID = pid
				if comm, err := os.ReadFile(filepath.Join(pd, "comm")); err == nil {
					ls[i].Process = strings.TrimSpace(string(comm))
				}
			}
		}
	}
}
