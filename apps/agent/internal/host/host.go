// Package host contains read-only probes of the managed host: capability
// detection, nginx, systemd, PHP-FPM pools and listening ports.
package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
)

// Env bundles host access dependencies (overridable in tests).
type Env struct {
	Exec            execx.Executor
	Docker          *docker.Client
	NginxBinary     string // override (absolute) or ""
	SystemctlBinary string // override (absolute) or ""
	PhpFpmPoolGlob  string
	SystemdRunDir   string // default /run/systemd/system
	ProcRoot        string // default /proc
	// BuildEnabled mirrors the local build.enabled config; "build" is reported
	// only when it is true, Docker answers and a git binary exists.
	BuildEnabled bool
	GitBinary    string // resolved git path ("" = none)
	// BackupReady is true when the local config enabled backups and a host
	// restic >= 0.17 was verified at startup ("backup" capability).
	BackupReady bool
}

func (e *Env) nginx() (string, bool)     { return execx.Find("nginx", e.NginxBinary) }
func (e *Env) systemctl() (string, bool) { return execx.Find("systemctl", e.SystemctlBinary) }

func (e *Env) runDir() string {
	if e.SystemdRunDir != "" {
		return e.SystemdRunDir
	}
	return "/run/systemd/system"
}

func (e *Env) proc() string {
	if e.ProcRoot != "" {
		return e.ProcRoot
	}
	return "/proc"
}

// Capabilities returns the subset of docker|build|nginx|systemd|php-fpm present.
func (e *Env) Capabilities() []string {
	caps := []string{}
	// docker only when the Engine API actually answers GET /_ping (a socket file
	// or a docker CLI binary alone is not a usable capability).
	if e.Docker != nil && e.Docker.Accessible() && e.Docker.Ping(context.Background()) {
		caps = append(caps, "docker")
		if e.BuildEnabled && e.GitBinary != "" {
			caps = append(caps, "build")
		}
	}
	if _, ok := e.nginx(); ok {
		caps = append(caps, "nginx")
	}
	if st, err := os.Stat(e.runDir()); err == nil && st.IsDir() {
		if _, ok := e.systemctl(); ok {
			caps = append(caps, "systemd")
		}
	}
	if e.phpFpmPresent() {
		caps = append(caps, "php-fpm")
	}
	if e.BackupReady {
		caps = append(caps, "backup")
	}
	return caps
}

func (e *Env) phpFpmPresent() bool {
	if m, _ := filepath.Glob(e.PhpFpmPoolGlob); len(m) > 0 {
		return true
	}
	for _, d := range execx.SearchDirs {
		if m, _ := filepath.Glob(filepath.Join(d, "php-fpm*")); len(m) > 0 {
			return true
		}
	}
	return false
}

// NginxInfo is nginx presence/version.
type NginxInfo struct {
	Present bool   `json:"present"`
	Binary  string `json:"binary,omitempty"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

var nginxVersionRe = regexp.MustCompile(`nginx/([0-9][0-9A-Za-z.\-]*)`)

// Nginx runs `nginx -v` (fixed argv, read-only).
func (e *Env) Nginx(ctx context.Context) NginxInfo {
	bin, ok := e.nginx()
	if !ok {
		return NginxInfo{Present: false}
	}
	info := NginxInfo{Present: true, Binary: bin}
	res, err := e.Exec.Run(ctx, bin, []string{"-v"}, 5*time.Second, 64<<10)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	if m := nginxVersionRe.FindSubmatch(append(res.Stderr, res.Stdout...)); m != nil {
		info.Version = string(m[1])
	}
	return info
}

// NginxDump runs `nginx -T` (test config + dump; never reloads) and returns stdout.
func (e *Env) NginxDump(ctx context.Context) (string, string, error) {
	bin, ok := e.nginx()
	if !ok {
		return "", "", errors.New("nginx binary not found")
	}
	res, err := e.Exec.Run(ctx, bin, []string{"-T"}, 30*time.Second, 16<<20)
	if err != nil {
		return "", "", err
	}
	if res.Truncated {
		return "", string(res.Stderr), errors.New("nginx -T output exceeded 16MiB cap")
	}
	if res.ExitCode != 0 {
		return string(res.Stdout), string(res.Stderr), errors.New("nginx -T exited non-zero: " + firstLine(res.Stderr))
	}
	return string(res.Stdout), string(res.Stderr), nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// Unit is a systemd unit summary.
type Unit struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

// SystemdUnits lists service units read-only via
// `systemctl list-units --type=service --all --no-pager --output=json`,
// falling back to `--plain --no-legend` on older systemd.
func (e *Env) SystemdUnits(ctx context.Context) ([]Unit, error) {
	bin, ok := e.systemctl()
	if !ok {
		return nil, errors.New("systemctl not found")
	}
	res, err := e.Exec.Run(ctx, bin, []string{"list-units", "--type=service", "--all", "--no-pager", "--output=json"}, 15*time.Second, 4<<20)
	if err == nil && res.ExitCode == 0 {
		if units, perr := ParseUnitsJSON(res.Stdout); perr == nil {
			return units, nil
		}
	}
	res, err = e.Exec.Run(ctx, bin, []string{"list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"}, 15*time.Second, 4<<20)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, errors.New("systemctl list-units failed: " + firstLine(res.Stderr))
	}
	return ParseUnitsPlain(res.Stdout), nil
}

// ParseUnitsJSON parses systemctl's JSON output.
func ParseUnitsJSON(b []byte) ([]Unit, error) {
	var raw []map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make([]Unit, 0, len(raw))
	for _, r := range raw {
		out = append(out, Unit{Unit: r["unit"], Load: r["load"], Active: r["active"], Sub: r["sub"], Description: r["description"]})
	}
	return out, nil
}

// ParseUnitsPlain parses `--plain --no-legend` columns.
func ParseUnitsPlain(b []byte) []Unit {
	out := []Unit{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) < 4 {
			continue
		}
		out = append(out, Unit{Unit: f[0], Load: f[1], Active: f[2], Sub: f[3], Description: strings.Join(f[4:], " ")})
	}
	return out
}

// FPMPool is a PHP-FPM pool definition.
type FPMPool struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Listen string `json:"listen,omitempty"`
	User   string `json:"user,omitempty"`
	Group  string `json:"group,omitempty"`
	PM     string `json:"pm,omitempty"`
	PHP    string `json:"phpVersion,omitempty"`
}

var phpVerRe = regexp.MustCompile(`/php/([0-9]+\.[0-9]+)/`)

// PhpFpmPools parses pool files matched by the configured glob (read-only).
func (e *Env) PhpFpmPools() ([]FPMPool, error) {
	files, err := filepath.Glob(e.PhpFpmPoolGlob)
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) > 200 {
		files = files[:200]
	}
	out := []FPMPool{}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		pools := ParseFPMPools(io.LimitReader(fh, 1<<20), f)
		fh.Close()
		out = append(out, pools...)
	}
	return out, nil
}

// ParseFPMPools parses an ini-style pool file.
func ParseFPMPools(r io.Reader, file string) []FPMPool {
	var out []FPMPool
	var cur *FPMPool
	ver := ""
	if m := phpVerRe.FindStringSubmatch(file); m != nil {
		ver = m[1]
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "global" {
				cur = nil
				continue
			}
			out = append(out, FPMPool{Name: name, File: file, PHP: ver})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "listen":
			cur.Listen = v
		case "user":
			cur.User = v
		case "group":
			cur.Group = v
		case "pm":
			cur.PM = v
		}
	}
	if out == nil {
		out = []FPMPool{}
	}
	return out
}
