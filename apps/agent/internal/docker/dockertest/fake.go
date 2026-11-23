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
	"archive/tar"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	// ProbePort is where a started container without a host port listens
	// (stands in for <container IP>:<port> in compose health probes).
	ProbePort    int
	Aliases      []string
	RestartCount int
	srv          *http.Server

	// ---- P6 backup helpers ----
	// Stdout/Stderr, when set, are served as separate log streams.
	Stdout, Stderr string
	// Files is the container filesystem as seen by the archive API (abs path -> content).
	Files map[string][]byte
	// RemovedWithVolumes records a DELETE with v=1.
	RemovedWithVolumes bool
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

	// ---- build node (P4b) ----
	// BuildLines replaces the default successful /build stream (one JSON per entry).
	BuildLines []string
	// BuildHang streams one line then blocks until the client cancels.
	BuildHang bool
	// PushLines replaces the default successful push stream.
	PushLines      []string
	LastBuildTar   []byte
	LastBuildQuery url.Values
	BuildCancelled bool
	CancelCalls    int
	// Images are local tags created by /build (removed by DELETE /images/...).
	Images map[string]bool

	// ---- P6 ----
	// HelperHook runs when a container labelled ppanel.backup is started; it
	// sets ExitCode/Stdout/Stderr/Files (default: exit 0, no output). When it
	// returns block=true the container stays running until stopped.
	HelperHook func(e *Engine, c *Container) (block bool)
	// Removed lists every removed container (name), in order.
	Removed []*Container
	// VolumeData is the content of named volumes (vol -> rel path -> data),
	// mapped into helper containers at their mount target for the archive API.
	VolumeData map[string]map[string][]byte
}

// Mounts returns the (source, target, readOnly) mounts of a created container.
func (c *Container) Mounts() []map[string]any {
	hc, _ := c.CreatedBody["HostConfig"].(map[string]any)
	ms, _ := hc["Mounts"].([]any)
	out := []map[string]any{}
	for _, m := range ms {
		if mm, ok := m.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

// Cmd returns the container command of a created container.
func (c *Container) Cmd() []string {
	var out []string
	if xs, ok := c.CreatedBody["Cmd"].([]any); ok {
		for _, x := range xs {
			s, _ := x.(string)
			out = append(out, s)
		}
	}
	return out
}

// Entrypoint returns the entrypoint override of a created container.
func (c *Container) Entrypoint() []string {
	var out []string
	if xs, ok := c.CreatedBody["Entrypoint"].([]any); ok {
		for _, x := range xs {
			s, _ := x.(string)
			out = append(out, s)
		}
	}
	return out
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
		Volumes: map[string]map[string]string{}, inflight: map[string]int{}, MaxInflight: map[string]int{}, Images: map[string]bool{},
		VolumeData: map[string]map[string][]byte{}}
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
		e.container(w, r, strings.Split(strings.TrimPrefix(p, "/containers/"), "/"), body)
	case p == "/build" && r.Method == http.MethodPost:
		e.build(w, r, body)
	case p == "/build/cancel" && r.Method == http.MethodPost:
		e.mu.Lock()
		e.CancelCalls++
		e.mu.Unlock()
		w.WriteHeader(200)
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/push") && r.Method == http.MethodPost:
		e.push(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/push"))
	case strings.HasPrefix(p, "/images/") && r.Method == http.MethodDelete:
		ref := strings.TrimPrefix(p, "/images/")
		e.mu.Lock()
		ok := e.Images[ref]
		delete(e.Images, ref)
		e.mu.Unlock()
		if !ok {
			msg(w, 404, "No such image: "+ref)
			return
		}
		jsonOut(w, 200, []map[string]string{{"Untagged": ref}})
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
	case strings.HasPrefix(p, "/networks/") && r.Method == http.MethodDelete:
		name := strings.TrimPrefix(p, "/networks/")
		e.mu.Lock()
		_, ok := e.Networks[name]
		delete(e.Networks, name)
		e.mu.Unlock()
		if !ok {
			msg(w, 404, "network "+name+" not found")
			return
		}
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/volumes/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(p, "/volumes/")
		e.mu.Lock()
		l, ok := e.Volumes[name]
		e.mu.Unlock()
		if !ok {
			msg(w, 404, "get "+name+": no such volume")
			return
		}
		jsonOut(w, 200, map[string]any{"Name": name, "Driver": "local", "Labels": l})
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
	if nc, ok := b["NetworkingConfig"].(map[string]any); ok {
		if ec, ok := nc["EndpointsConfig"].(map[string]any); ok {
			for _, v := range ec {
				if m, ok := v.(map[string]any); ok {
					if al, ok := m["Aliases"].([]any); ok {
						for _, a := range al {
							s, _ := a.(string)
							c.Aliases = append(c.Aliases, s)
						}
					}
				}
			}
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

func (e *Engine) container(w http.ResponseWriter, r *http.Request, parts []string, body []byte) {
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
			"State":        map[string]any{"Status": c.Status, "Running": running, "Restarting": false, "ExitCode": c.ExitCode},
			"Config":       map[string]any{"Image": c.Image, "Labels": c.Labels, "Tty": c.Tty, "Env": c.Env},
			"HostConfig":   map[string]any{"PortBindings": map[string]any{"8080/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": strconv.Itoa(c.HostPort)}}}},
			"RestartCount": c.RestartCount,
			"NetworkSettings": map[string]any{"Networks": map[string]any{
				"ppanel-" + c.Labels["ppanel.app"]: map[string]any{"IPAddress": "127.0.0.1"},
			}},
		})
	case r.Method == http.MethodGet && op == "logs":
		e.logs(w, r, c)
	case r.Method == http.MethodPost && op == "wait":
		for {
			e.mu.Lock()
			st, code := c.Status, c.ExitCode
			e.mu.Unlock()
			if st != "running" {
				jsonOut(w, 200, map[string]any{"StatusCode": code})
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	case r.Method == http.MethodGet && op == "archive":
		e.getArchive(w, r, c)
	case r.Method == http.MethodPut && op == "archive":
		e.putArchive(w, r, c, body)
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
		if c.Labels["ppanel.backup"] != "" {
			c.ExitCode = 130
		}
		w.WriteHeader(204)
	case r.Method == http.MethodDelete && op == "":
		e.mu.Lock()
		defer e.mu.Unlock()
		if c.Status == "running" && r.URL.Query().Get("force") != "1" {
			msg(w, 409, "cannot remove a running container")
			return
		}
		e.stopLocked(c)
		c.RemovedWithVolumes = r.URL.Query().Get("v") == "1"
		delete(e.Containers, c.Name)
		e.Removed = append(e.Removed, c)
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
	if c.Labels["ppanel.backup"] != "" {
		e.mu.Lock()
		hook := e.HelperHook
		c.Status = "running"
		e.mu.Unlock()
		block := false
		if hook != nil && c.Labels["ppanel.backup.role"] != "scratch" {
			block = hook(e, c)
		}
		if !block {
			e.mu.Lock()
			c.Status = "exited"
			e.mu.Unlock()
		}
		return
	}
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
	c.ProbePort = ln.Addr().(*net.TCPAddr).Port
	c.Status = "running"
}

// ProbeAddr maps a container id to the address its fake server listens on
// (for containerops.Options.ProbeAddr in compose tests).
func (e *Engine) ProbeAddr(id, _ string, _ int) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.Containers {
		if c.ID == id && c.ProbePort > 0 {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(c.ProbePort))
		}
	}
	return ""
}

func (e *Engine) build(w http.ResponseWriter, r *http.Request, body []byte) {
	e.mu.Lock()
	e.LastBuildTar = body
	e.LastBuildQuery = r.URL.Query()
	lines, hang := e.BuildLines, e.BuildHang
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fl, _ := w.(http.Flusher)
	if hang {
		w.Write([]byte(`{"stream":"Step 1/2 : FROM busybox\n"}` + "\n"))
		if fl != nil {
			fl.Flush()
		}
		<-r.Context().Done()
		e.mu.Lock()
		e.BuildCancelled = true
		e.mu.Unlock()
		return
	}
	if lines == nil {
		lines = []string{`{"stream":"Step 1/2 : FROM busybox\n"}`, `{"stream":"\u001b[1mStep 2/2\u001b[0m : COPY . /srv\n"}`,
			`{"aux":{"ID":"sha256:` + strings.Repeat("2", 64) + `"}}`, `{"stream":"Successfully built 222222222222\n"}`}
		e.mu.Lock()
		e.Images[r.URL.Query().Get("t")] = true
		e.mu.Unlock()
	}
	for _, l := range lines {
		w.Write([]byte(l + "\n"))
	}
}

func (e *Engine) push(w http.ResponseWriter, r *http.Request, repo string) {
	e.mu.Lock()
	lines := e.PushLines
	e.mu.Unlock()
	tag := r.URL.Query().Get("tag")
	if lines == nil {
		lines = []string{`{"status":"The push refers to repository [` + repo + `]"}`,
			`{"status":"Pushing","progressDetail":{"current":1,"total":2},"progress":"[==>   ]","id":"abc"}`,
			`{"status":"` + tag + `: digest: sha256:` + strings.Repeat("d", 64) + ` size: 528"}`,
			`{"progressDetail":{},"aux":{"Tag":"` + tag + `","Digest":"sha256:` + strings.Repeat("d", 64) + `","Size":528}}`}
	}
	w.Header().Set("Content-Type", "application/json")
	for _, l := range lines {
		w.Write([]byte(l + "\n"))
	}
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
	so, se := c.Stdout, c.Stderr
	e.mu.Unlock()
	if so != "" || se != "" {
		var buf bytes.Buffer
		if so != "" && r.URL.Query().Get("stdout") == "1" {
			buf.Write(frame(1, []byte(so)))
		}
		if se != "" && r.URL.Query().Get("stderr") == "1" {
			buf.Write(frame(2, []byte(se)))
		}
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		w.Write(buf.Bytes())
		return
	}
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

// containerFiles returns the files visible in c: its own Files plus the data
// of mounted volumes at their targets.
func (e *Engine) containerFiles(c *Container) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range c.Files {
		out[k] = v
	}
	for _, m := range c.Mounts() {
		src, _ := m["Source"].(string)
		tgt, _ := m["Target"].(string)
		for rel, data := range e.VolumeData[src] {
			out[tgt+"/"+rel] = data
		}
	}
	return out
}

func (e *Engine) getArchive(w http.ResponseWriter, r *http.Request, c *Container) {
	root := r.URL.Query().Get("path")
	e.mu.Lock()
	files := e.containerFiles(c)
	e.mu.Unlock()
	base := root[strings.LastIndex(root, "/")+1:]
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	n := 0
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		var name string
		switch {
		case k == root:
			name = base
		case strings.HasPrefix(k, root+"/"):
			name = base + "/" + strings.TrimPrefix(k, root+"/")
		default:
			continue
		}
		data := files[k]
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
		n++
	}
	_ = tw.Close()
	if n == 0 {
		msg(w, 404, "Could not find the file "+root+" in container "+c.Name)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Write(buf.Bytes())
}

func (e *Engine) putArchive(w http.ResponseWriter, r *http.Request, c *Container, body []byte) {
	dir := r.URL.Query().Get("path")
	tr := tar.NewReader(bytes.NewReader(body))
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.Files == nil {
		c.Files = map[string][]byte{}
	}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(tr)
		if h.Typeflag == tar.TypeReg {
			c.Files[dir+"/"+h.Name] = data
		}
	}
	w.WriteHeader(200)
}

// SetVolumeFile stores a file of a named volume (rel path).
func (e *Engine) SetVolumeFile(vol, rel string, data []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.VolumeData[vol] == nil {
		e.VolumeData[vol] = map[string][]byte{}
	}
	e.VolumeData[vol][rel] = data
}

// AddVolume registers a named volume with labels.
func (e *Engine) AddVolume(name string, labels map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Volumes[name] = labels
}

// AddNetwork registers a network with labels.
func (e *Engine) AddNetwork(name string, labels map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Networks[name] = labels
}

// RemovedSnapshot returns the removed containers.
func (e *Engine) RemovedSnapshot() []*Container {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*Container(nil), e.Removed...)
}

// Lock/Unlock expose the fake's mutex to hooks that edit a container.
func (e *Engine) Lock()   { e.mu.Lock() }
func (e *Engine) Unlock() { e.mu.Unlock() }
