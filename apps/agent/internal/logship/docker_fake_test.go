package logship

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCtr struct {
	ID, Name, State, Health string
	Labels                  map[string]string
	Restarts                int
	Tty                     bool
	// Logs are (ts, stream, line); served with timestamps, filtered by since.
	Logs []fakeLog
	// CPU stats served by /stats (cumulative).
	CPUTotal, SysTotal uint64
	MemUsage, MemCache uint64
}

type fakeLog struct {
	TS     time.Time
	Stream byte // 1 stdout, 2 stderr
	Line   string
}

// fakeEngine is a minimal GET-only Docker Engine for telemetry tests.
type fakeEngine struct {
	mu      sync.Mutex
	Socket  string
	ctrs    map[string]*fakeCtr
	calls   []string
	methods map[string]int
	follow  map[string]chan struct{} // closes the stream for id
	srv     *http.Server
}

func newFakeEngine(t *testing.T) *fakeEngine {
	dir, err := os.MkdirTemp("/tmp", "pls")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fe := &fakeEngine{Socket: sock, ctrs: map[string]*fakeCtr{}, methods: map[string]int{}, follow: map[string]chan struct{}{}}
	fe.srv = &http.Server{Handler: http.HandlerFunc(fe.serve)}
	go fe.srv.Serve(ln)
	t.Cleanup(func() { fe.srv.Close(); os.RemoveAll(dir) })
	return fe
}

func (fe *fakeEngine) add(c *fakeCtr) {
	fe.mu.Lock()
	fe.ctrs[c.ID] = c
	fe.mu.Unlock()
}

func (fe *fakeEngine) callsSnapshot() []string {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	return append([]string(nil), fe.calls...)
}

func jsonW(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (fe *fakeEngine) serve(w http.ResponseWriter, r *http.Request) {
	fe.mu.Lock()
	fe.calls = append(fe.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	fe.methods[r.Method]++
	fe.mu.Unlock()
	p := r.URL.Path
	if p == "/containers/json" {
		fe.mu.Lock()
		out := []map[string]any{}
		for _, c := range fe.ctrs {
			out = append(out, map[string]any{"Id": c.ID, "Names": []string{"/" + c.Name}, "Image": "img", "State": c.State, "Status": c.State, "Labels": c.Labels})
		}
		fe.mu.Unlock()
		jsonW(w, out)
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "/containers/"), "/")
	fe.mu.Lock()
	c := fe.ctrs[parts[0]]
	fe.mu.Unlock()
	if c == nil || len(parts) != 2 {
		http.Error(w, `{"message":"no such container"}`, 404)
		return
	}
	switch parts[1] {
	case "json":
		fe.mu.Lock()
		st := map[string]any{"Status": c.State}
		if c.Health != "" {
			st["Health"] = map[string]any{"Status": c.Health}
		}
		v := map[string]any{"Id": c.ID, "Name": "/" + c.Name, "State": st, "RestartCount": c.Restarts,
			"Config": map[string]any{"Labels": c.Labels, "Tty": c.Tty, "Env": []string{"SECRET=nope"}}}
		fe.mu.Unlock()
		jsonW(w, v)
	case "stats":
		fe.mu.Lock()
		c.CPUTotal += 50_000_000
		c.SysTotal += 1_000_000_000
		v := map[string]any{"read": time.Now(), "cpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": c.CPUTotal}, "system_cpu_usage": c.SysTotal, "online_cpus": 2},
			"precpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": 0}, "system_cpu_usage": 0},
			"memory_stats": map[string]any{"usage": c.MemUsage, "limit": 536870912, "stats": map[string]any{"inactive_file": c.MemCache}}}
		fe.mu.Unlock()
		jsonW(w, v)
	case "logs":
		fe.logs(w, r, c)
	default:
		http.Error(w, "unsupported", 404)
	}
}

func (fe *fakeEngine) logs(w http.ResponseWriter, r *http.Request, c *fakeCtr) {
	q := r.URL.Query()
	var since time.Time
	if s := q.Get("since"); s != "" {
		sec, frac, _ := strings.Cut(s, ".")
		si, _ := strconv.ParseInt(sec, 10, 64)
		ns, _ := strconv.ParseInt((frac + "000000000")[:9], 10, 64)
		since = time.Unix(si, ns)
	}
	w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
	fe.mu.Lock()
	logs := append([]fakeLog(nil), c.Logs...)
	ch := fe.follow[c.ID]
	if ch == nil {
		ch = make(chan struct{})
		fe.follow[c.ID] = ch
	}
	fe.mu.Unlock()
	for _, l := range logs {
		if !since.IsZero() && l.TS.Before(since) {
			continue
		}
		payload := l.TS.UTC().Format(time.RFC3339Nano) + " " + l.Line + "\n"
		if c.Tty {
			w.Write([]byte(payload))
			continue
		}
		// split one line across two frames to exercise reassembly
		half := len(payload) / 2
		for _, part := range []string{payload[:half], payload[half:]} {
			h := make([]byte, 8)
			h[0] = l.Stream
			binary.BigEndian.PutUint32(h[4:], uint32(len(part)))
			w.Write(h)
			w.Write([]byte(part))
		}
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if q.Get("follow") == "1" {
		select {
		case <-ch:
		case <-r.Context().Done():
		}
	}
}

// endStream ends the current follow stream of id (container "stopped").
func (fe *fakeEngine) endStream(id string) {
	fe.mu.Lock()
	if ch := fe.follow[id]; ch != nil {
		close(ch)
		delete(fe.follow, id)
	}
	fe.mu.Unlock()
}
