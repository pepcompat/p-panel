package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Engine is the WRITE-CAPABLE Docker Engine API client. It is used ONLY by the
// container.* job handlers (internal/containerops); discovery/inventory keep
// using the GET-only Client. Even here the transport enforces an allowlist of
// (method, path) pairs: no exec, no build, no image/volume/network deletion,
// no swarm/plugins/system endpoints.
type Engine struct {
	socket string
	hc     *http.Client // short requests
	long   *http.Client // image pull (streams for minutes)
}

// ErrNotFound is returned for HTTP 404 from the engine.
var ErrNotFound = errors.New("docker: not found")

// APIError is a non-2xx Engine response (message from {"message": ...}).
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("docker: HTTP %d: %s", e.Status, e.Message) }

// UnavailableError wraps transport-level failures (socket missing, daemon down).
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string { return "docker engine unavailable: " + e.Err.Error() }
func (e *UnavailableError) Unwrap() error { return e.Err }

// IsUnavailable reports whether err means the engine could not be reached.
func IsUnavailable(err error) bool {
	var u *UnavailableError
	return errors.As(err, &u)
}

const idOrName = `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`

// writeAllow is the complete list of non-GET calls the Engine may make.
var writeAllow = []struct {
	method string
	re     *regexp.Regexp
}{
	{http.MethodPost, regexp.MustCompile(`^/images/create$`)},
	{http.MethodPost, regexp.MustCompile(`^/networks/create$`)},
	{http.MethodPost, regexp.MustCompile(`^/volumes/create$`)},
	{http.MethodPost, regexp.MustCompile(`^/containers/create$`)},
	{http.MethodPost, regexp.MustCompile(`^/containers/` + idOrName + `/(start|stop|restart)$`)},
	{http.MethodDelete, regexp.MustCompile(`^/containers/` + idOrName + `$`)},
}

// getDeny blocks GET endpoints that could leak secrets or are irrelevant.
var getDeny = regexp.MustCompile(`^/(exec|secrets|configs|swarm|plugins|distribution|session|build)`)

// AllowedCall reports whether the Engine transport permits method+path.
func AllowedCall(method, path string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return !getDeny.MatchString(path) && !strings.Contains(path, "/exec")
	}
	for _, a := range writeAllow {
		if a.method == method && a.re.MatchString(path) {
			return true
		}
	}
	return false
}

type allowlist struct{ rt http.RoundTripper }

func (a allowlist) RoundTrip(r *http.Request) (*http.Response, error) {
	if !AllowedCall(r.Method, r.URL.Path) {
		return nil, fmt.Errorf("docker: %s %s refused (not in the container-ops allowlist)", r.Method, r.URL.Path)
	}
	return a.rt.RoundTrip(r)
}

// NewEngine returns a write-capable client for the unix socket.
func NewEngine(socket string) *Engine {
	mk := func(hdr, total time.Duration) *http.Client {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			MaxIdleConns:          2,
			IdleConnTimeout:       10 * time.Second,
			ResponseHeaderTimeout: hdr,
		}
		return &http.Client{Transport: allowlist{tr}, Timeout: total}
	}
	return &Engine{socket: socket, hc: mk(30*time.Second, 60*time.Second), long: mk(60*time.Second, 0)}
}

// Socket returns the socket path.
func (e *Engine) Socket() string { return e.socket }

func (e *Engine) do(ctx context.Context, hc *http.Client, method, path string, q url.Values, hdr http.Header, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	u := "http://docker" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if strings.Contains(err.Error(), "refused (not in the container-ops allowlist)") {
			return nil, err
		}
		return nil, &UnavailableError{Err: err}
	}
	return resp, nil
}

func readErr(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &m)
	if m.Message == "" {
		m.Message = strings.TrimSpace(string(b))
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, m.Message)
	}
	return &APIError{Status: resp.StatusCode, Message: m.Message}
}

// call performs a request and decodes a JSON body into out (nil = discard).
func (e *Engine) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	resp, err := e.do(ctx, e.hc, method, path, q, nil, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return readErr(resp)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(b) > MaxResponseBytes {
		return errors.New("docker: response too large")
	}
	if out == nil || len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

// Ping returns nil when GET /_ping answers 200.
func (e *Engine) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := e.do(ctx, e.hc, http.MethodGet, "/_ping", nil, nil, nil)
	if err != nil {
		if IsUnavailable(err) {
			return err
		}
		return &UnavailableError{Err: err}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return &UnavailableError{Err: fmt.Errorf("/_ping HTTP %d", resp.StatusCode)}
	}
	return nil
}

// ContainerState is the subset of State we use.
type ContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Restarting bool   `json:"Restarting"`
	ExitCode   int    `json:"ExitCode"`
	OOMKilled  bool   `json:"OOMKilled"`
	Error      string `json:"Error"`
	StartedAt  string `json:"StartedAt"`
}

// PortBinding is a HostConfig port binding.
type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// ContainerInfo is the subset of GET /containers/{id}/json we use. Config.Env
// is deliberately NOT decoded (it may carry secret values).
type ContainerInfo struct {
	ID      string         `json:"Id"`
	Name    string         `json:"Name"`
	Image   string         `json:"Image"` // image id (sha256:...)
	Created string         `json:"Created"`
	State   ContainerState `json:"State"`
	Config  struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
		Tty    bool              `json:"Tty"`
	} `json:"Config"`
	HostConfig struct {
		PortBindings map[string][]PortBinding `json:"PortBindings"`
	} `json:"HostConfig"`
}

// InspectContainer returns the container or ErrNotFound.
func (e *Engine) InspectContainer(ctx context.Context, nameOrID string) (*ContainerInfo, error) {
	if !regexp.MustCompile(`^` + idOrName + `$`).MatchString(nameOrID) {
		return nil, fmt.Errorf("docker: invalid container reference")
	}
	var ci ContainerInfo
	if err := e.call(ctx, http.MethodGet, "/containers/"+nameOrID+"/json", nil, nil, &ci); err != nil {
		return nil, err
	}
	return &ci, nil
}

// ListSummary is one entry of GET /containers/json.
type ListSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// ListContainers lists all containers matching every label filter (k=v).
func (e *Engine) ListContainers(ctx context.Context, labels []string) ([]ListSummary, error) {
	f, _ := json.Marshal(map[string][]string{"label": labels})
	q := url.Values{"all": {"1"}, "filters": {string(f)}}
	var out []ListSummary
	if err := e.call(ctx, http.MethodGet, "/containers/json", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SplitDigestRef splits repo@sha256:hex.
func SplitDigestRef(ref string) (repo, digest string, ok bool) {
	i := strings.LastIndex(ref, "@")
	if i <= 0 || !strings.HasPrefix(ref[i+1:], "sha256:") {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// PullImage pulls a digest reference. authB64 (may be "") is sent as the
// X-Registry-Auth header. The streamed progress is consumed and the first
// error message is returned. Credentials are never part of returned errors.
func (e *Engine) PullImage(ctx context.Context, ref, authB64 string) error {
	repo, digest, ok := SplitDigestRef(ref)
	if !ok {
		return fmt.Errorf("image reference must be pinned by digest")
	}
	hdr := http.Header{}
	if authB64 != "" {
		hdr.Set("X-Registry-Auth", authB64)
	}
	resp, err := e.do(ctx, e.long, http.MethodPost, "/images/create", url.Values{"fromImage": {repo}, "tag": {digest}}, hdr, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return readErr(resp)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var m struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil && (m.Error != "" || m.ErrorDetail.Message != "") {
			msg := m.ErrorDetail.Message
			if msg == "" {
				msg = m.Error
			}
			return &APIError{Status: 200, Message: msg}
		}
	}
	return sc.Err()
}

// ImageInfo is the subset of GET /images/{ref}/json.
type ImageInfo struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

// InspectImage returns image metadata.
func (e *Engine) InspectImage(ctx context.Context, ref string) (*ImageInfo, error) {
	var ii ImageInfo
	if err := e.call(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, &ii); err != nil {
		return nil, err
	}
	return &ii, nil
}

// NetworkInfo is the subset of GET /networks/{id}.
type NetworkInfo struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Driver string            `json:"Driver"`
	Labels map[string]string `json:"Labels"`
}

// InspectNetwork returns the network or ErrNotFound.
func (e *Engine) InspectNetwork(ctx context.Context, name string) (*NetworkInfo, error) {
	var n NetworkInfo
	if err := e.call(ctx, http.MethodGet, "/networks/"+name, nil, nil, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

// CreateNetwork creates a bridge network with labels.
func (e *Engine) CreateNetwork(ctx context.Context, name string, labels map[string]string) error {
	body := map[string]any{"Name": name, "Driver": "bridge", "CheckDuplicate": true, "Internal": false,
		"Attachable": false, "EnableIPv6": false, "Labels": labels}
	return e.call(ctx, http.MethodPost, "/networks/create", nil, body, nil)
}

// VolumeInfo is the subset of a volume.
type VolumeInfo struct {
	Name   string            `json:"Name"`
	Driver string            `json:"Driver"`
	Labels map[string]string `json:"Labels"`
}

// CreateVolume creates (or returns the existing) local named volume.
func (e *Engine) CreateVolume(ctx context.Context, name string, labels map[string]string) (*VolumeInfo, error) {
	var v VolumeInfo
	body := map[string]any{"Name": name, "Driver": "local", "Labels": labels}
	if err := e.call(ctx, http.MethodPost, "/volumes/create", nil, body, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// CreateContainer posts a container create body; returns the new id.
func (e *Engine) CreateContainer(ctx context.Context, name string, body any) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	if err := e.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// StartContainer starts a container (304 = already running is success).
func (e *Engine) StartContainer(ctx context.Context, id string) error {
	return e.call(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, nil)
}

// StopContainer stops with a grace period in seconds.
func (e *Engine) StopContainer(ctx context.Context, id string, graceSec int) error {
	return e.call(ctx, http.MethodPost, "/containers/"+id+"/stop", url.Values{"t": {fmt.Sprint(graceSec)}}, nil, nil)
}

// RestartContainer restarts with a grace period in seconds.
func (e *Engine) RestartContainer(ctx context.Context, id string, graceSec int) error {
	return e.call(ctx, http.MethodPost, "/containers/"+id+"/restart", url.Values{"t": {fmt.Sprint(graceSec)}}, nil, nil)
}

// RemoveContainer deletes a container. Volumes are NEVER removed (v=0).
func (e *Engine) RemoveContainer(ctx context.Context, id string, force bool) error {
	q := url.Values{"v": {"0"}, "force": {"0"}}
	if force {
		q.Set("force", "1")
	}
	return e.call(ctx, http.MethodDelete, "/containers/"+id, q, nil, nil)
}

// Logs returns up to maxBytes of demultiplexed stdout+stderr for the last
// tail lines (sinceUnix 0 = no lower bound). truncated is true when the
// engine sent more than maxBytes.
func (e *Engine) Logs(ctx context.Context, id string, tail int, sinceUnix int64, tty bool, maxBytes int) (text string, truncated bool, err error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {fmt.Sprint(tail)}, "timestamps": {"0"}}
	if sinceUnix > 0 {
		q.Set("since", fmt.Sprint(sinceUnix))
	}
	resp, err := e.do(ctx, e.hc, http.MethodGet, "/containers/"+id+"/logs", q, nil, nil)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, readErr(resp)
	}
	// Stream the whole (bounded) response, demultiplexing frames, and keep only
	// the most recent bytes: Docker sends oldest → newest.
	var buf []byte
	dropped := false
	add := func(b []byte) {
		buf = append(buf, b...)
		if len(buf) > 2*maxBytes {
			buf = append([]byte(nil), buf[len(buf)-maxBytes-1:]...)
			dropped = true
		}
	}
	body := bufio.NewReaderSize(io.LimitReader(resp.Body, 64<<20), 64<<10)
	chunk := make([]byte, 32<<10)
	raw := tty || resp.Header.Get("Content-Type") == "application/vnd.docker.raw-stream"
	hdr := make([]byte, 8)
	for {
		if raw {
			n, rerr := body.Read(chunk)
			add(chunk[:n])
			if rerr != nil {
				break
			}
			continue
		}
		n, rerr := io.ReadFull(body, hdr)
		if rerr != nil {
			add(hdr[:n])
			break
		}
		if hdr[0] > 2 || hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 {
			add(hdr) // not multiplexed after all
			raw = true
			continue
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		for size > 0 {
			want := int64(len(chunk))
			if size < want {
				want = size
			}
			m, rerr := io.ReadFull(body, chunk[:want])
			add(chunk[:m])
			size -= int64(m)
			if rerr != nil {
				size = -1
			}
		}
		if size < 0 {
			break
		}
	}
	out := buf
	if len(out) > maxBytes || dropped {
		if len(out) > maxBytes {
			out = out[len(out)-maxBytes:]
		}
		if i := bytes.IndexByte(out, '\n'); i >= 0 {
			out = out[i+1:] // drop the partial first line
		}
		truncated = true
	}
	return string(out), truncated, nil
}

// Demux strips the 8-byte stdcopy frame headers from a multiplexed log
// stream. Malformed input is returned as-is.
func Demux(b []byte) []byte {
	var out bytes.Buffer
	for len(b) >= 8 {
		if b[0] > 2 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
			out.Write(b)
			return out.Bytes()
		}
		n := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		if n > len(b) {
			n = len(b)
		}
		out.Write(b[:n])
		b = b[n:]
	}
	out.Write(b)
	return out.Bytes()
}
