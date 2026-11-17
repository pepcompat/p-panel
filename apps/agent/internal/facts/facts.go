// Package facts collects static host facts sent at enrollment and in inventory.
package facts

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"strings"
)

// OS describes the host operating system.
type OS struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Name    string `json:"name,omitempty"`
	Arch    string `json:"arch"`
	Kernel  string `json:"kernel,omitempty"`
}

// Facts is the enrollment facts payload.
type Facts struct {
	OS           OS     `json:"os"`
	AgentVersion string `json:"agentVersion"`
}

// OSReleasePath is overridable for tests.
var OSReleasePath = "/etc/os-release"

// Collect gathers OS facts. Missing sources degrade to runtime values.
func Collect() OS {
	o := OS{ID: runtime.GOOS, Arch: runtime.GOARCH, Kernel: kernelRelease()}
	if f, err := os.Open(OSReleasePath); err == nil {
		defer f.Close()
		kv := ParseOSRelease(f)
		if v := kv["ID"]; v != "" {
			o.ID = v
		}
		o.Version = kv["VERSION_ID"]
		o.Name = kv["PRETTY_NAME"]
	} else if runtime.GOOS == "darwin" {
		o.ID = "macos"
	}
	return o
}

// ParseOSRelease parses the freedesktop os-release KEY=VALUE format.
func ParseOSRelease(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, 64<<10))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// Hostname returns the host name or "unknown".
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
