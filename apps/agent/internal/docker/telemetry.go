package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// Telemetry reads (P5). Every call here is a GET on the read-only Client.

// ContainerIDRe is the only container reference telemetry calls accept (engine ids).
var ContainerIDRe = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func checkID(id string) error {
	if !ContainerIDRe.MatchString(id) {
		return errors.New("docker: invalid container id")
	}
	return nil
}

// HealthInfo is the subset of GET /containers/{id}/json used by the heartbeat.
// Config.Env is deliberately not decoded.
type HealthInfo struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
		Tty    bool              `json:"Tty"`
	} `json:"Config"`
}

// Inspect returns state/health/restart count of a container.
func (c *Client) Inspect(ctx context.Context, id string) (*HealthInfo, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	var hi HealthInfo
	if err := c.Get(ctx, "/containers/"+id+"/json", &hi); err != nil {
		return nil, err
	}
	return &hi, nil
}

// CPUStats is the cpu_stats / precpu_stats object.
type CPUStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  uint32 `json:"online_cpus"`
}

// Stats is the subset of GET /containers/{id}/stats we use.
type Stats struct {
	Read        time.Time `json:"read"`
	CPUStats    CPUStats  `json:"cpu_stats"`
	PreCPUStats CPUStats  `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// MemUsed is usage minus page cache, like `docker stats` (cgroup v2
// inactive_file, v1 total_inactive_file).
func (s *Stats) MemUsed() uint64 {
	u := s.MemoryStats.Usage
	for _, k := range []string{"inactive_file", "total_inactive_file"} {
		if v, ok := s.MemoryStats.Stats[k]; ok && v < u {
			return u - v
		}
	}
	return u
}

// CPUPercent computes CPU% between two cpu stat samples (docker stats formula).
// ok=false when the samples do not allow a computation.
func CPUPercent(prev, cur CPUStats) (float64, bool) {
	if cur.SystemUsage <= prev.SystemUsage || cur.CPUUsage.TotalUsage < prev.CPUUsage.TotalUsage || prev.SystemUsage == 0 {
		return 0, false
	}
	cpus := float64(cur.OnlineCPUs)
	if cpus == 0 {
		cpus = 1
	}
	pct := float64(cur.CPUUsage.TotalUsage-prev.CPUUsage.TotalUsage) / float64(cur.SystemUsage-prev.SystemUsage) * cpus * 100
	return float64(int64(pct*10+0.5)) / 10, true
}

// ContainerStats is the one-shot GET /containers/{id}/stats?stream=false&one-shot=true.
func (c *Client) ContainerStats(ctx context.Context, id string) (*Stats, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	var st Stats
	if err := c.Get(ctx, "/containers/"+id+"/stats?stream=false&one-shot=true", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// LogLine is one demultiplexed container log line.
type LogLine struct {
	// Stream is "stdout" or "stderr" ("" for TTY containers).
	Stream string
	// TS is the engine timestamp (timestamps=1); zero if unparsable.
	TS time.Time
	// Line has no trailing newline and no timestamp prefix.
	Line []byte
}

// MaxFollowLine caps one line read from a follow stream (longer → split).
const MaxFollowLine = 64 << 10

// FollowLogs streams GET /containers/{id}/logs?follow=1&stdout=1&stderr=1&timestamps=1&since=…
// calling fn per complete line until ctx is cancelled, the container stops (EOF)
// or an error occurs. since is the docker `since` value ("" = none), e.g.
// "1700000000.000000001".
func (c *Client) FollowLogs(ctx context.Context, id, since string, tty bool, fn func(LogLine)) error {
	if err := checkID(id); err != nil {
		return err
	}
	q := url.Values{"follow": {"1"}, "stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}}
	if since != "" {
		q.Set("since", since)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/logs?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker: GET logs: HTTP %d", resp.StatusCode)
	}
	raw := tty || resp.Header.Get("Content-Type") == "application/vnd.docker.raw-stream"
	return DemuxLines(resp.Body, raw, fn)
}

// DemuxLines reads a (possibly stdcopy-multiplexed) stream with timestamps=1
// and emits complete lines per stream. Partial lines are buffered per stream
// up to MaxFollowLine.
func DemuxLines(r io.Reader, raw bool, fn func(LogLine)) error {
	pend := map[string][]byte{}
	emit := func(stream string, b []byte) {
		buf := append(pend[stream], b...)
		for {
			i := indexNL(buf)
			if i < 0 {
				break
			}
			fn(parseTSLine(stream, buf[:i]))
			buf = buf[i+1:]
		}
		for len(buf) > MaxFollowLine {
			fn(parseTSLine(stream, buf[:MaxFollowLine]))
			buf = buf[MaxFollowLine:]
		}
		pend[stream] = append([]byte(nil), buf...)
	}
	flush := func() {
		for s, b := range pend {
			if len(b) > 0 {
				fn(parseTSLine(s, b))
			}
		}
	}
	br := bufio.NewReaderSize(r, 64<<10)
	if raw {
		chunk := make([]byte, 32<<10)
		for {
			n, err := br.Read(chunk)
			if n > 0 {
				emit("", chunk[:n])
			}
			if err != nil {
				flush()
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			flush()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 || hdr[0] > 2 {
			// not multiplexed after all: treat the rest as raw
			emit("", hdr)
			return DemuxLines(br, true, func(l LogLine) { fn(l) })
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		if size > 16<<20 {
			return errors.New("docker: oversized log frame")
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(br, b); err != nil {
			emit(stream, b)
			flush()
			return nil
		}
		emit(stream, b)
	}
}

func indexNL(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}

func parseTSLine(stream string, b []byte) LogLine {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	l := LogLine{Stream: stream}
	for i := 0; i < len(b) && i < 40; i++ {
		if b[i] == ' ' {
			if ts, err := time.Parse(time.RFC3339Nano, string(b[:i])); err == nil {
				l.TS = ts
				l.Line = append([]byte(nil), b[i+1:]...)
				return l
			}
			break
		}
	}
	l.Line = append([]byte(nil), b...)
	return l
}

// SinceParam formats a docker `since` value strictly after t (t + 1ns).
func SinceParam(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.Add(time.Nanosecond)
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}
