// Command fakefleet is the P7.06 load generator: N fake pPanel agents speaking the real agent protocol
// (docs/AGENT_PROTOCOL.md) against a LAB Center.
//
//   - enrollment: POST /api/v1/enrollments (admin) + POST /api/v1/agent/enroll with a locally generated
//     ECDSA P-256 CSR (identities persisted in -state so ramp phases reuse them);
//   - mTLS gateway: heartbeat every -hb (default 15 s, jittered start), optional long-poll
//     GET /agent/v1/tasks?waitSec=25 (like the real agent), gzip log batches every 2 s carrying
//     -log-rate lines/s spread over the fleet (source nginx_access, no app → no label spoofing);
//   - optional API probe (-probe): admin GET /servers, /metrics/fleet, /logs/query at fixed rates.
//
// Results (latency percentiles, status counts, per-window stats) are written as JSON to -out.
// LAB ONLY. The Center must run with TRUST_PROXY=1 so each fake agent's enrollment carries its own
// X-Forwarded-For (the public enroll endpoint is rate-limited to 10/min per IP).
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type identity struct {
	ServerID string `json:"serverId"`
	Name     string `json:"name"`
	KeyPEM   string `json:"keyPem"`
	CertPEM  string `json:"certPem"`
	CAPEM    string `json:"caPem"`
}

type opts struct {
	api, gateway, email, password, state, out, prefix, env string
	agents, enrollConc                                     int
	hb, duration, window                                   time.Duration
	logRate                                                float64
	longPoll, probe, enrollOnly                            bool
}

// ---------------------------------------------------------------- stats

type series struct {
	mu   sync.Mutex
	lat  []float64 // ms
	code map[string]int
}

func newSeries() *series { return &series{code: map[string]int{}} }

func (s *series) add(ms float64, code string) {
	s.mu.Lock()
	s.lat = append(s.lat, ms)
	s.code[code]++
	s.mu.Unlock()
}

type summary struct {
	Count  int            `json:"count"`
	Codes  map[string]int `json:"codes"`
	P50    float64        `json:"p50Ms"`
	P95    float64        `json:"p95Ms"`
	P99    float64        `json:"p99Ms"`
	Max    float64        `json:"maxMs"`
	ErrPct float64        `json:"errorPct"`
}

func (s *series) snap(reset bool) summary {
	s.mu.Lock()
	l := append([]float64(nil), s.lat...)
	c := map[string]int{}
	for k, v := range s.code {
		c[k] = v
	}
	if reset {
		s.lat = s.lat[:0]
		s.code = map[string]int{}
	}
	s.mu.Unlock()
	sort.Float64s(l)
	p := func(q float64) float64 {
		if len(l) == 0 {
			return 0
		}
		i := int(q*float64(len(l))+0.5) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(l) {
			i = len(l) - 1
		}
		return float64(int(l[i]*10)) / 10
	}
	errs := 0
	for k, v := range c {
		if !strings.HasPrefix(k, "2") {
			errs += v
		}
	}
	out := summary{Count: len(l), Codes: c, P50: p(0.50), P95: p(0.95), P99: p(0.99)}
	if len(l) > 0 {
		out.Max = l[len(l)-1]
		out.ErrPct = float64(int(10000*float64(errs)/float64(len(l)))) / 100
	}
	return out
}

var (
	stHB, stLogs, stPoll, stEnroll = newSeries(), newSeries(), newSeries(), newSeries()
	stAPI                          = map[string]*series{"servers": newSeries(), "metricsFleet": newSeries(), "logsQuery": newSeries()}
	linesSent, linesAccepted       atomic.Int64
	logs429                        atomic.Int64
)

// ---------------------------------------------------------------- main

func main() {
	var o opts
	flag.StringVar(&o.api, "api", "http://localhost:4000", "Center API base")
	flag.StringVar(&o.gateway, "gateway", "https://localhost:4443", "agent gateway base (SAN must match)")
	flag.StringVar(&o.email, "email", "superadmin@ppanel.local", "admin login (dev seed)")
	flag.StringVar(&o.password, "password", "password", "admin password (dev seed)")
	flag.StringVar(&o.state, "state", ".lab/load/identities.json", "persisted fake identities")
	flag.StringVar(&o.out, "out", "", "JSON result file")
	flag.StringVar(&o.prefix, "prefix", "p7load-", "server name prefix (cleanup key)")
	flag.StringVar(&o.env, "environment", "development", "environment of fake servers")
	flag.IntVar(&o.agents, "agents", 50, "number of fake agents")
	flag.IntVar(&o.enrollConc, "enroll-concurrency", 8, "parallel enrollments")
	flag.DurationVar(&o.hb, "hb", 15*time.Second, "heartbeat interval")
	flag.DurationVar(&o.duration, "duration", 2*time.Minute, "run time after enrollment")
	flag.DurationVar(&o.window, "window", 30*time.Second, "stats window")
	flag.Float64Var(&o.logRate, "log-rate", 0, "total log lines per second across the fleet")
	flag.BoolVar(&o.longPoll, "long-poll", true, "hold GET /agent/v1/tasks long-polls like the real agent")
	flag.BoolVar(&o.probe, "probe", true, "probe the admin API while loading")
	flag.BoolVar(&o.enrollOnly, "enroll-only", false, "only enroll up to -agents, then exit")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ids := loadState(o.state)
	if len(ids) < o.agents {
		tok, err := adminLogin(o)
		if err != nil {
			log.Fatalf("admin login: %v", err)
		}
		t0 := time.Now()
		ids = enrollMore(ctx, o, tok, ids)
		saveState(o.state, ids)
		log.Printf("enrolled up to %d identities in %s", len(ids), time.Since(t0).Round(time.Millisecond))
	}
	if o.enrollOnly {
		writeOut(o, map[string]any{"enroll": stEnroll.snap(false), "identities": len(ids)}, nil)
		return
	}
	ids = ids[:o.agents]

	runCtx, cancel := context.WithTimeout(ctx, o.duration)
	defer cancel()
	var wg sync.WaitGroup
	perAgentRate := o.logRate / float64(len(ids))
	for i, id := range ids {
		cl, err := mtlsClient(id)
		if err != nil {
			log.Fatalf("identity %s: %v", id.ServerID, err)
		}
		wg.Add(1)
		go func(i int, id identity, cl *http.Client) {
			defer wg.Done()
			runAgent(runCtx, o, i, id, cl, perAgentRate)
		}(i, id, cl)
	}
	if o.probe {
		tok, err := adminLogin(o)
		if err == nil {
			wg.Add(1)
			go func() { defer wg.Done(); probeAPI(runCtx, o, tok) }()
		}
	}
	var windows []map[string]any
	tick := time.NewTicker(o.window)
	start := time.Now()
loop:
	for {
		select {
		case <-runCtx.Done():
			break loop
		case <-tick.C:
			w := map[string]any{"tSec": int(time.Since(start).Seconds()), "heartbeat": stHB.snap(false),
				"logsBatches": stLogs.snap(false), "linesSent": linesSent.Load(), "linesAccepted": linesAccepted.Load(),
				"logs429": logs429.Load()}
			windows = append(windows, w)
			b, _ := json.Marshal(w)
			log.Printf("window %s", b)
		}
	}
	tick.Stop()
	wg.Wait()
	el := time.Since(start).Seconds()
	res := map[string]any{
		"agents": len(ids), "durationSec": int(el), "heartbeatIntervalSec": o.hb.Seconds(), "logRateTarget": o.logRate,
		"heartbeat": stHB.snap(false), "logsBatches": stLogs.snap(false), "taskPolls": stPoll.snap(false),
		"linesSent": linesSent.Load(), "linesAccepted": linesAccepted.Load(), "logs429": logs429.Load(),
		"linesAcceptedPerSec": float64(int(10*float64(linesAccepted.Load())/el)) / 10,
		"heartbeatsPerSec":    float64(int(10*float64(stHB.snap(false).Count)/el)) / 10,
		"api": map[string]any{"servers": stAPI["servers"].snap(false), "metricsFleet": stAPI["metricsFleet"].snap(false),
			"logsQuery": stAPI["logsQuery"].snap(false)},
		"enroll": stEnroll.snap(false),
	}
	writeOut(o, res, windows)
}

func writeOut(o opts, res map[string]any, windows []map[string]any) {
	res["windows"] = windows
	res["finishedAt"] = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.MarshalIndent(res, "", "  ")
	if o.out != "" {
		_ = os.WriteFile(o.out, b, 0o644)
	}
	fmt.Println(string(b))
}

// ---------------------------------------------------------------- enrollment

func loadState(p string) []identity {
	var ids []identity
	b, err := os.ReadFile(p)
	if err == nil {
		_ = json.Unmarshal(b, &ids)
	}
	return ids
}

func saveState(p string, ids []identity) {
	_ = os.MkdirAll(dirOf(p), 0o700)
	b, _ := json.Marshal(ids)
	_ = os.WriteFile(p, b, 0o600)
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "."
}

var plain = &http.Client{Timeout: 60 * time.Second}

func envelope(resp *http.Response) (json.RawMessage, error) {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %.300s", resp.StatusCode, b)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

func postJSON(cl *http.Client, u string, body any, hdr map[string]string) (*http.Response, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return cl.Do(req)
}

func adminLogin(o opts) (string, error) {
	resp, err := postJSON(plain, o.api+"/api/v1/auth/login", map[string]string{"email": o.email, "password": o.password}, nil)
	if err != nil {
		return "", err
	}
	d, err := envelope(resp)
	if err != nil {
		return "", err
	}
	var v struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.Unmarshal(d, &v)
	return v.AccessToken, nil
}

func enrollMore(ctx context.Context, o opts, tok string, have []identity) []identity {
	need := o.agents - len(have)
	var mu sync.Mutex
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < o.enrollConc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				id, err := enrollOne(o, tok, i)
				if err != nil {
					log.Printf("enroll %d: %v", i, err)
					continue
				}
				mu.Lock()
				have = append(have, id)
				mu.Unlock()
			}
		}()
	}
	base := len(have)
	for i := 0; i < need && ctx.Err() == nil; i++ {
		jobs <- base + i
	}
	close(jobs)
	wg.Wait()
	return have
}

func enrollOne(o opts, tok string, i int) (identity, error) {
	t0 := time.Now()
	name := fmt.Sprintf("%s%04d-%s", o.prefix, i, randHex(3))
	resp, err := postJSON(plain, o.api+"/api/v1/enrollments",
		map[string]any{"name": name, "environment": o.env, "ttlMinutes": 15},
		map[string]string{"Authorization": "Bearer " + tok})
	if err != nil {
		return identity{}, err
	}
	d, err := envelope(resp)
	if err != nil {
		return identity{}, err
	}
	var e struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(d, &e)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		return identity{}, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	xff := fmt.Sprintf("10.%d.%d.%d", 77+(i>>16)&0x7f, (i>>8)&0xff, i&0xff)
	resp, err = postJSON(plain, o.api+"/api/v1/agent/enroll", map[string]any{
		"token": e.Token, "csrPem": string(csrPEM), "hostname": name,
		"facts": map[string]any{"os": map[string]string{"id": "ubuntu", "version": "24.04", "arch": "arm64", "kernel": "6.8"},
			"agentVersion": "0.1.0-fake"},
	}, map[string]string{"X-Forwarded-For": xff})
	if err != nil {
		stEnroll.add(ms(t0), "ERR")
		return identity{}, err
	}
	code := fmt.Sprint(resp.StatusCode)
	d, err = envelope(resp)
	stEnroll.add(ms(t0), code)
	if err != nil {
		return identity{}, err
	}
	var r struct {
		ServerID       string `json:"serverId"`
		CertificatePem string `json:"certificatePem"`
		CaPem          string `json:"caPem"`
	}
	_ = json.Unmarshal(d, &r)
	kb, _ := x509.MarshalECPrivateKey(key)
	return identity{ServerID: r.ServerID, Name: name, KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})),
		CertPEM: r.CertificatePem, CAPEM: r.CaPem}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func ms(t0 time.Time) float64 { return float64(time.Since(t0).Microseconds()) / 1000 }

// ---------------------------------------------------------------- agent loops

func mtlsClient(id identity) (*http.Client, error) {
	cert, err := tls.X509KeyPair([]byte(id.CertPEM), []byte(id.KeyPEM))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(id.CAPEM)) {
		return nil, errors.New("bad CA")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: false}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

func gw(cl *http.Client, method, u string, body []byte, gz bool) (int, []byte, error) {
	req, _ := http.NewRequest(method, u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Protocol", "1")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func runAgent(ctx context.Context, o opts, i int, id identity, cl *http.Client, rate float64) {
	// jittered start so heartbeats spread over the interval like a real fleet
	if !sleepCtx(ctx, time.Duration(mrand.Int64N(int64(o.hb)))) {
		return
	}
	var wg sync.WaitGroup
	if o.longPoll {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				t0 := time.Now()
				st, _, err := gw(cl, http.MethodGet, o.gateway+"/agent/v1/tasks?waitSec=25", nil, false)
				code := fmt.Sprint(st)
				if err != nil {
					code = "ERR"
				}
				stPoll.add(ms(t0), code)
				if err != nil || st >= 300 {
					sleepCtx(ctx, 5*time.Second)
				}
			}
		}()
	}
	if rate > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); logLoop(ctx, o, id, cl, rate) }()
	}
	seq := 0
	t := time.NewTicker(o.hb)
	defer t.Stop()
	for {
		seq++
		hb := map[string]any{
			"seq": seq, "sentAt": time.Now().UTC().Format(time.RFC3339Nano), "agentVersion": "0.1.0-fake",
			"metrics": map[string]any{"cpuPct": 5 + mrand.Float64()*20, "memPct": 30 + mrand.Float64()*10, "diskPct": 41.5,
				"load1": mrand.Float64(), "uptimeSec": 1000 + seq*15, "memTotalBytes": 4 << 30, "memAvailableBytes": 2 << 30,
				"diskTotalBytes": 40 << 30, "diskFreeBytes": 20 << 30, "netRxBytes": seq * 10000, "netTxBytes": seq * 8000},
			"addresses":    []map[string]string{{"family": "ipv4", "scope": "private", "address": fmt.Sprintf("10.99.%d.%d", (i>>8)&0xff, i&0xff), "interface": "eth0"}},
			"capabilities": []string{"nginx", "systemd"}, "runningJobIds": []string{},
			"logShipping": map[string]any{"bufferedBytes": 0, "bufferCapBytes": 64 << 20, "droppedEntries": 0},
		}
		b, _ := json.Marshal(hb)
		t0 := time.Now()
		st, _, err := gw(cl, http.MethodPost, o.gateway+"/agent/v1/heartbeat", b, false)
		code := fmt.Sprint(st)
		if err != nil {
			code = "ERR"
		}
		stHB.add(ms(t0), code)
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
		}
	}
}

func logLoop(ctx context.Context, o opts, id identity, cl *http.Client, rate float64) {
	const every = 2 * time.Second
	carry := 0.0
	seq := 0
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		carry += rate * every.Seconds()
		n := int(carry)
		carry -= float64(n)
		if n == 0 {
			continue
		}
		seq++
		now := time.Now().UTC()
		entries := make([]map[string]any, n)
		for k := 0; k < n; k++ {
			ts := now.Add(-time.Duration(n-k) * time.Millisecond)
			entries[k] = map[string]any{"ts": ts.Format(time.RFC3339Nano), "source": "nginx_access", "app": nil, "service": nil,
				"container": nil, "file": "/var/log/nginx/access.log", "stream": nil, "level": nil,
				"line": fmt.Sprintf(`10.0.0.%d - - [%s] "GET /p7/load/%d HTTP/1.1" 200 612 "-" "fakefleet/1.0"`, k%250, ts.Format("02/Jan/2006:15:04:05 -0700"), seq)}
		}
		body, _ := json.Marshal(map[string]any{"batchId": uuid4(), "seq": seq, "sentAt": now.Format(time.RFC3339Nano), "entries": entries,
			"dropped": map[string]any{"entries": 0, "since": nil}})
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		t0 := time.Now()
		st, rb, err := gw(cl, http.MethodPost, o.gateway+"/agent/v1/logs", buf.Bytes(), true)
		code := fmt.Sprint(st)
		if err != nil {
			code = "ERR"
		}
		stLogs.add(ms(t0), code)
		linesSent.Add(int64(n))
		if st == 429 {
			logs429.Add(1)
		}
		if st == 200 {
			var env struct {
				Data struct {
					Accepted int `json:"accepted"`
				} `json:"data"`
			}
			_ = json.Unmarshal(rb, &env)
			linesAccepted.Add(int64(env.Data.Accepted))
		}
	}
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---------------------------------------------------------------- admin API probe

func probeAPI(ctx context.Context, o opts, tok0 string) {
	var tok atomic.Value
	tok.Store(tok0)
	// rates stay under the per-user limits: metrics 60/min, logs 30/min
	type ep struct {
		key   string
		every time.Duration
		path  func() string
	}
	eps := []ep{
		{"servers", 1 * time.Second, func() string { return "/api/v1/servers?limit=100" }},
		{"metricsFleet", 2 * time.Second, func() string { return "/api/v1/metrics/fleet" }},
		{"logsQuery", 4 * time.Second, func() string {
			to := time.Now().UTC()
			return "/api/v1/logs/query?" + url.Values{"from": {to.Add(-5 * time.Minute).Format(time.RFC3339)},
				"to": {to.Format(time.RFC3339)}, "limit": {"200"}, "source": {"nginx_access"}}.Encode()
		}},
	}
	var wg sync.WaitGroup
	for _, e := range eps {
		wg.Add(1)
		go func(e ep) {
			defer wg.Done()
			t := time.NewTicker(e.every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
				req, _ := http.NewRequest(http.MethodGet, o.api+e.path(), nil)
				req.Header.Set("Authorization", "Bearer "+tok.Load().(string))
				t0 := time.Now()
				resp, err := plain.Do(req)
				code := "ERR"
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					code = fmt.Sprint(resp.StatusCode)
					if resp.StatusCode == 401 { // access token expired: re-login
						if nt, err := adminLogin(o); err == nil {
							tok.Store(nt)
						}
					}
				}
				stAPI[e.key].add(ms(t0), code)
			}
		}(e)
	}
	wg.Wait()
}
