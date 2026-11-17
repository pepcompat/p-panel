// Package docker is a minimal, READ-ONLY Docker Engine API client over the
// unix socket. The transport refuses any method other than GET.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// MaxResponseBytes caps any Docker API response.
const MaxResponseBytes = 4 << 20

// Client talks to the Engine API.
type Client struct {
	socket string
	hc     *http.Client
}

type getOnly struct{ rt http.RoundTripper }

func (g getOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		return nil, fmt.Errorf("docker: method %s refused (read-only client)", r.Method)
	}
	return g.rt.RoundTrip(r)
}

// New returns a client for the given unix socket path.
func New(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:          1,
		IdleConnTimeout:       10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &Client{socket: socket, hc: &http.Client{Transport: getOnly{tr}, Timeout: 15 * time.Second}}
}

// Accessible reports whether the socket exists and can be opened.
func (c *Client) Accessible() bool {
	st, err := os.Stat(c.socket)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return false
	}
	conn, err := net.DialTimeout("unix", c.socket, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Get performs a GET and decodes JSON into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > MaxResponseBytes {
		return errors.New("docker: response too large")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: GET %s: HTTP %d", path, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// Container is the subset of /containers/json we report.
type Container struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	ImageID string            `json:"imageId"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Created int64             `json:"created"`
	Ports   []Port            `json:"ports"`
	Labels  map[string]string `json:"labels"`
	Compose *ComposeRef       `json:"compose,omitempty"`
}

// Port is a published/exposed port.
type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}

// ComposeRef is derived from com.docker.compose.* labels (provenance).
type ComposeRef struct {
	Project     string `json:"project"`
	Service     string `json:"service"`
	WorkingDir  string `json:"workingDir,omitempty"`
	ConfigFiles string `json:"configFiles,omitempty"`
}

type rawContainer struct {
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

// sensitiveLabel reports labels that commonly carry secrets; values are redacted.
func sensitiveLabel(k string) bool {
	for _, s := range []string{"password", "secret", "token", "key", "credential"} {
		if containsFold(k, s) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	n, m := len(s), len(sub)
	for i := 0; i+m <= n; i++ {
		ok := true
		for j := 0; j < m; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Containers lists all containers (running and stopped). Env is never fetched.
func (c *Client) Containers(ctx context.Context) ([]Container, error) {
	var raw []rawContainer
	if err := c.Get(ctx, "/containers/json?all=1", &raw); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		ct := Container{ID: r.ID, Names: r.Names, Image: r.Image, ImageID: r.ImageID, State: r.State,
			Status: r.Status, Created: r.Created, Labels: map[string]string{}, Ports: []Port{}}
		for k, v := range r.Labels {
			if sensitiveLabel(k) {
				v = "[redacted]"
			}
			ct.Labels[k] = v
		}
		for _, p := range r.Ports {
			ct.Ports = append(ct.Ports, Port{IP: p.IP, PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type})
		}
		if proj := r.Labels["com.docker.compose.project"]; proj != "" {
			ct.Compose = &ComposeRef{Project: proj, Service: r.Labels["com.docker.compose.service"],
				WorkingDir: r.Labels["com.docker.compose.project.working_dir"], ConfigFiles: r.Labels["com.docker.compose.project.config_files"]}
		}
		if ct.Names == nil {
			ct.Names = []string{}
		}
		out = append(out, ct)
	}
	return out, nil
}

// Version is the subset of /version we report.
type Version struct {
	Version    string `json:"Version"`
	APIVersion string `json:"ApiVersion"`
	Os         string `json:"Os"`
	Arch       string `json:"Arch"`
}

// EngineVersion returns /version.
func (c *Client) EngineVersion(ctx context.Context) (*Version, error) {
	var v Version
	if err := c.Get(ctx, "/version", &v); err != nil {
		return nil, err
	}
	return &v, nil
}
