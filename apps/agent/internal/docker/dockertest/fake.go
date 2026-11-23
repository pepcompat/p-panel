// Package dockertest is a fake Docker Engine API served over a unix socket in
// a temp dir, for container.* tests. Behaviour is selected by image name:
//
//	…/web@…      started container serves 200 on its 127.0.0.1 host port
//	…/broken@…   serves 500
//	…/crash@…    exits immediately (exit code 3)
//	…/envecho@…  serves 200 and logs "APP_SECRET=<value>" (with ANSI codes)
//	…/nopull@…   pull fails with an error message in the progress stream
package dockertest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

// Call is one request received by the fake engine.
type Call struct {
	Method string
	Path   string
	Query  string
	Body   []byte
	Header http.Header
}

// Container is the fake's container state.
type Container struct {
	ID, Name, Image string
	Labels          map[string]string
	Env             []string
	HostPort        int
	Status          string // created|running|exited
	ExitCode        int
	Logs            string
	Tty             bool
	CreatedBody     map[string]any
	srv             *http.Server
}

// Engine is a fake Docker Engine.
type Engine struct {
	t          testing.TB
	Socket     string
	mu         sync.Mutex
	Calls      []Call
	Containers map[string]*Container // by name
	Networks   map[string]map[string]string
	Volumes    map[string]map[string]string
	// StartDelay delays POST /start (serialization tests).
	StartDelay  time.Duration
	inflight    map[string]int // app -> in-flight starts
	MaxInflight map[string]int
	MaxTotal    int
	total       int
	srv         *http.Server
	seq         int
}

// New starts a fake engine; it is closed with t.Cleanup.
func New(t testing.TB) *Engine {
	dir, err := os.MkdirTemp("/tmp", "pfe")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{t: t, Socket: sock, Containers: map[string]*Container{}, Networks: map[string]map[string]string{},
		Volumes: map[string]map[string]string{}, inflight: map[string]int{}, MaxInflight: map[string]int{}}
	e.srv = &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: 5 * time.Second}
	go e.srv.Serve(ln)
	t.Cleanup(func() {
		e.Close()
		os.RemoveAll(dir)
	})
	return e
}

// Close stops the engine and every fake container listener (engine "down").
func (e *Engine) Close() {
	e.srv.Close()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.Containers {
		if c.srv != nil {
			c.srv.Close()
			c.srv = nil
		}
	}
}

// AddContainer injects a pre-existing container (e.g. unlabelled, created outside pPanel).
func (e *Engine) AddContainer(c *Container) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.ID == "" {
		e.seq++
		c.ID = fmt.Sprintf("%064x", 0xabc000+e.seq)
	}
	if c.Labels == nil {
		c.Labels = map[string]string{}
	}
	if c.Status == "" {
		c.Status = "running"
	}
	e.Containers[c.Name] = c
}

// CallsSnapshot returns a copy of all calls.
func (e *Engine) CallsSnapshot() []Call {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Call(nil), e.Calls...)
}

// MutatingCalls returns every non-GET call.
func (e *Engine) MutatingCalls() []Call {
	var out []Call
	for _, c := range e.CallsSnapshot() {
		if c.Method != http.MethodGet && c.Method != http.MethodHead {
			out = append(out, c)
		}
	}
	return out
}

// Find returns the container by name.
func (e *Engine) Find(name string) *Container {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Containers[name]
}

func (e *Engine) byRef(ref string) *Container {
	if c, ok := e.Containers[ref]; ok {
		return c
	}
	for _, c := range e.Containers {
		if c.ID == ref || (len(ref) >= 12 && strings.HasPrefix(c.ID, ref)) {
			return c
		}
	}
	return nil
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func msg(w http.ResponseWriter, code int, m string) {
	jsonOut(w, code, map[string]string{"message": m})
}

func kind(image string) string {
	for _, k := range []string{"envecho", "broken", "crash", "nopull", "web"} {
		if strings.Contains(image, "/"+k+"@") {
			return k
		}
	}
	return "web"
}

func (e *Engine) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	e.mu.Lock()
	e.Calls = append(e.Calls, Call{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body, Header: r.Header.Clone()})
	e.mu.Unlock()
	p := r.URL.Path
	switch {
	case p == "/_ping":
		w.Write([]byte("OK"))
	case p == "/version":
		jsonOut(w, 200, map[string]string{"Version": "29.0.0-fake", "ApiVersion": "1.51"})
	case p == "/containers/json" && r.Method == http.MethodGet:
		e.list(w, r)
	case p == "/containers/create" && r.Method == http.MethodPost:
		e.create(w, r, body)
	case strings.HasPrefix(p, "/containers/"):
		e.container(w, r, strings.Split(strings.TrimPrefix(p, "/containers/"), "/"))
	case p == "/images/create" && r.Method == http.MethodPost:
		img := r.URL.Query().Get("fromImage") + "@" + r.URL.Query().Get("tag")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"Pulling from ppanel-test"}` + "\n"))
		if kind(img) == "nopull" {
			w.Write([]byte(`{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}` + "\n"))
			return
		}
		w.Write([]byte(`{"status":"Digest: ` + r.URL.Query().Get("tag") + `"}` + "\n"))
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		jsonOut(w, 200, map[string]any{"Id": "sha256:" + strings.Repeat("1", 64), "RepoDigests": []string{strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json")}})
	case p == "/networks/create" && r.Method == http.MethodPost:
		var b struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(body, &b)
		e.mu.Lock()
		e.Networks[b.Name] = b.Labels
		e.mu.Unlock()
		jsonOut(w, 201, map[string]string{"Id": "net-" + b.Name})
	case strings.HasPrefix(p, "/networks/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(p, "/networks/")
		e.mu.Lock()
		l, ok := e.Networks[name]
		e.mu.Unlock()
		if !ok {
			msg(w, 404, "network "+name+" not found")
			return
		}
		jsonOut(w, 200, map[string]any{"Id": "net-" + name, "Name": name, "Driver": "bridge", "Labels": l})
	case p == "/volumes/create" && r.Method == http.MethodPost:
		var b struct {
			Name   string
			Labels map[string]string
		}
		_ = json.Unmarshal(body, &b)
		e.mu.Lock()
		if l, ok := e.Volumes[b.Name]; ok {
			b.Labels = l
		} else {
			e.Volumes[b.Name] = b.Labels
		}
		e.mu.Unlock()
		jsonOut(w, 201, map[string]any{"Name": b.Name, "Driver": "local", "Labels": b.Labels})
	default:
		msg(w, 404, "page not found")
	}
}

func (e *Engine) list(w http.ResponseWriter, r *http.Request) {
	var f map[string][]string
	_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &f)
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []map[string]any{}
	for _, c := range e.Containers {
		match := true
		for _, l := range f["label"] {
			k, v, _ := strings.Cut(l, "=")
			if c.Labels[k] != v {
				match = false
			}
		}
		if !match {
			continue
		}
		ports := []map[string]any{}
		if c.HostPort > 0 {
			ports = append(ports, map[string]any{"IP": "127.0.0.1", "PrivatePort": 8080, "PublicPort": c.HostPort, "Type": "tcp"})
		}
		out = append(out, map[string]any{"Id": c.ID, "Names": []string{"/" + c.Name}, "Image": c.Image, "ImageID": "sha256:" + strings.Repeat("1", 64),
			"State": c.Status, "Status": c.Status, "Created": time.Now().Unix(), "Labels": c.Labels, "Ports": ports})
	}
	jsonOut(w, 200, out)
}

func (e *Engine) create(w http.ResponseWriter, r *http.Request, body []byte) {
	name := r.URL.Query().Get("name")
	var b map[string]any
	if err := json.Unmarshal(body, &b); err != nil {
		msg(w, 400, "bad json")
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.Containers[name]; ok {
		msg(w, 409, "Conflict. The container name \"/"+name+"\" is already in use")
		return
	}
	e.seq++
	c := &Container{ID: fmt.Sprintf("%064x", 0xc0ffee000+e.seq), Name: name, Status: "created", CreatedBody: b, Labels: map[string]string{}}
	c.Image, _ = b["Image"].(string)
	if l, ok := b["Labels"].(map[string]any); ok {
		for k, v := range l {
			c.Labels[k], _ = v.(string)
		}
	}
	if env, ok := b["Env"].([]any); ok {
		for _, x := range env {
			s, _ := x.(string)
			c.Env = append(c.Env, s)
		}
	}
	if hc, ok := b["HostConfig"].(map[string]any); ok {
		if pb, ok := hc["PortBindings"].(map[string]any); ok {
			for _, v := range pb {
				if arr, ok := v.([]any); ok && len(arr) > 0 {
					m, _ := arr[0].(map[string]any)
					c.HostPort, _ = strconv.Atoi(fmt.Sprint(m["HostPort"]))
				}
			}
		}
	}
	e.Containers[name] = c
	jsonOut(w, 201, map[string]any{"Id": c.ID, "Warnings": []string{}})
}

func (e *Engine) container(w http.ResponseWriter, r *http.Request, parts []string) {
	e.mu.Lock()
	c := e.byRef(parts[0])
	e.mu.Unlock()
	if c == nil {
		msg(w, 404, "No such container: "+parts[0])
		return
	}
	op := ""
	if len(parts) > 1 {
		op = parts[1]
	}
	switch {
	case r.Method == http.MethodGet && op == "json":
		e.mu.Lock()
		defer e.mu.Unlock()
		running := c.Status == "running"
		jsonOut(w, 200, map[string]any{
			"Id": c.ID, "Name": "/" + c.Name, "Image": "sha256:" + strings.Repeat("1", 64), "Created": time.Now().UTC().Format(time.RFC3339Nano),
			"State":      map[string]any{"Status": c.Status, "Running": running, "Restarting": false, "ExitCode": c.ExitCode},
			"Config":     map[string]any{"Image": c.Image, "Labels": c.Labels, "Tty": c.Tty, "Env": c.Env},
			"HostConfig": map[string]any{"PortBindings": map[string]any{"8080/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": strconv.Itoa(c.HostPort)}}}},
		})
	case r.Method == http.MethodGet && op == "logs":
		e.logs(w, r, c)
	case r.Method == http.MethodPost && (op == "start" || op == "restart"):
		app := c.Labels["ppanel.app"]
		e.mu.Lock()
		e.inflight[app]++
		e.total++
		if e.inflight[app] > e.MaxInflight[app] {
			e.MaxInflight[app] = e.inflight[app]
		}
		if e.total > e.MaxTotal {
			e.MaxTotal = e.total
		}
		e.mu.Unlock()
		time.Sleep(e.StartDelay)
		e.mu.Lock()
		e.inflight[app]--
		e.total--
		e.mu.Unlock()
		if op == "start" && c.Status == "running" {
			w.WriteHeader(304)
			return
		}
		e.start(c)
		w.WriteHeader(204)
	case r.Method == http.MethodPost && op == "stop":
		e.mu.Lock()
		defer e.mu.Unlock()
		if c.Status != "running" {
			w.WriteHeader(304)
			return
		}
		e.stopLocked(c)
		w.WriteHeader(204)
	case r.Method == http.MethodDelete && op == "":
		e.mu.Lock()
		defer e.mu.Unlock()
		if c.Status == "running" && r.URL.Query().Get("force") != "1" {
			msg(w, 409, "cannot remove a running container")
			return
		}
		e.stopLocked(c)
		delete(e.Containers, c.Name)
		w.WriteHeader(204)
	default:
		msg(w, 404, "unsupported")
	}
}

func (e *Engine) stopLocked(c *Container) {
	if c.srv != nil {
		c.srv.Close()
		c.srv = nil
	}
	if c.Status == "running" {
		c.Status = "exited"
	}
}

func (e *Engine) start(c *Container) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.srv != nil {
		c.srv.Close()
		c.srv = nil
	}
	k := kind(c.Image)
	secret := ""
	for _, kv := range c.Env {
		if v, ok := strings.CutPrefix(kv, "APP_SECRET="); ok {
			secret = v
		}
	}
	c.Logs += "\x1b[32mstarting " + k + "\x1b[0m\n"
	if k == "envecho" {
		c.Logs += "APP_SECRET=" + secret + "\n" + "\x1b[1mready\x1b[0m secret=" + secret + "\n"
	}
	if k == "crash" {
		c.Status, c.ExitCode = "exited", 3
		c.Logs += "fatal: cannot start\n"
		return
	}
	status := 200
	if k == "broken" {
		status = 500
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.HostPort)))
	if err != nil {
		c.Status, c.ExitCode = "exited", 1
		c.Logs += "listen failed: " + err.Error() + "\n"
		return
	}
	c.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintf(w, "%s\n", k)
	}), ReadHeaderTimeout: 2 * time.Second}
	go c.srv.Serve(ln)
	c.Status = "running"
}

// frame builds one stdcopy frame.
func frame(stream byte, b []byte) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(b)))
	return append(h, b...)
}

func (e *Engine) logs(w http.ResponseWriter, r *http.Request, c *Container) {
	e.mu.Lock()
	text := c.Logs
	tty := c.Tty
	e.mu.Unlock()
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("tail")); err == nil && n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	var buf bytes.Buffer
	for i, l := range lines {
		if tty {
			buf.WriteString(l)
		} else {
			buf.Write(frame(byte(1+i%2), []byte(l)))
		}
	}
	w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
	w.Write(buf.Bytes())
}

// FreePort returns a free 127.0.0.1 port in the managed range 20000–29999.
func FreePort(t testing.TB) int {
	for p := 20000 + int(time.Now().UnixNano()%9000); p < 29999; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err == nil {
			ln.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}
