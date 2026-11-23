package containerops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// TestLabDindContainers runs the container.* operations against the REAL Docker
// Engine of the lab (lab-dind sidecar sharing lab-node-b's network namespace).
// It must run INSIDE ppanel-lab-node-b. Opt-in, driven by scripts/lab/agent_containers_lab.sh:
//
//	PPANEL_LAB_DIND=1 PPANEL_LAB_IMAGE_WEB_V1=… PPANEL_LAB_IMAGE_WEB_V2=… PPANEL_LAB_IMAGE_BROKEN=… \
//	PPANEL_LAB_IMAGE_ENVECHO=… PPANEL_LAB_UNMANAGED=ppanel-labtest-0badc0de ./containerops.test -test.run TestLabDind -test.v
//
// The Center's one-time secrets endpoint is replaced by an in-process stub that
// returns a fake secret once (the real endpoint is exercised by the Center E2E).
func TestLabDindContainers(t *testing.T) {
	if os.Getenv("PPANEL_LAB_DIND") != "1" {
		t.Skip("set PPANEL_LAB_DIND=1 (inside ppanel-lab-node-b) to run against the lab dind engine")
	}
	imgs := map[string]string{}
	for _, k := range []string{"WEB_V1", "WEB_V2", "BROKEN", "ENVECHO"} {
		imgs[k] = os.Getenv("PPANEL_LAB_IMAGE_" + k)
		if !ImageDigestRefRe.MatchString(imgs[k]) {
			t.Fatalf("PPANEL_LAB_IMAGE_%s must be a digest ref, got %q", k, imgs[k])
		}
	}
	const app = "labtest"
	const fakeSecret = "lab-FAKE-secret-9f8e7d"
	sock := "/var/run/docker.sock"
	if !docker.New(sock).Ping(context.Background()) {
		t.Fatal("docker capability: GET /_ping failed on " + sock)
	}
	var logBuf bytes.Buffer
	fetches := 0
	eng := docker.NewEngine(sock)
	m := New(Options{Engine: eng, Log: slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Secrets: func(ctx context.Context) (*transport.JobSecrets, error) {
			fetches++
			if fetches > 1 {
				return nil, &transport.APIError{HTTPStatus: 409, Code: "SECRETS_ALREADY_FETCHED"}
			}
			return &transport.JobSecrets{Env: map[string]string{"APP_SECRET": fakeSecret}}, nil
		}})
	ctx := context.Background()
	hc := map[string]any{"path": "/healthz", "intervalSec": 1, "timeoutSec": 2, "startPeriodSec": 20}
	mk := func(name, image string, port int, extra map[string]any) RunParams {
		raw := map[string]any{"deploymentId": "4a1f0d3e-0000-4000-8000-00000000000" + name[len(name)-1:], "app": app, "name": name, "image": image,
			"containerPort": 8080, "hostPort": port, "healthcheck": hc, "resources": map[string]any{"memoryMb": 64, "cpus": 0.5, "pids": 64}}
		for k, v := range extra {
			raw[k] = v
		}
		b, _ := json.Marshal(raw)
		p, err := DecodeRun(b)
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return p
	}
	get := func(port int) (int, string) {
		resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/")
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	created := []string{}
	t.Cleanup(func() {
		for _, n := range created {
			_, _ = m.Stop(ctx, RefParams{App: app, Name: n})
			_, _ = m.Remove(ctx, RefParams{App: app, Name: n})
		}
	})
	pick := func() int {
		for p := 23000 + int(time.Now().UnixNano()%3000); p < 29999; p++ {
			if !LoopbackPortInUse(p) {
				return p
			}
		}
		t.Fatal("no free port")
		return 0
	}

	// 1. web v1 healthy on 127.0.0.1 (node-b loopback)
	p1 := pick()
	v1 := mk("ppanel-labtest-00000001", imgs["WEB_V1"], p1, nil)
	out, err := m.RunCandidate(ctx, v1)
	if err != nil {
		t.Fatalf("run web v1: %v", err)
	}
	created = append(created, v1.Name)
	st, body := get(p1)
	t.Logf("web v1: out=%+v health=%+v GET / -> %d %q", out, out.Health, st, body)
	if st != 200 || body != "ppanel-test web v1" {
		t.Fatalf("web v1 not serving: %d %q", st, body)
	}
	ci, err := eng.InspectContainer(ctx, v1.Name)
	if err != nil || ci.HostConfig.PortBindings["8080/tcp"][0].HostIP != "127.0.0.1" || !IsOwned(ci, app, v1.Name) {
		t.Fatalf("inspect v1: %+v %v", ci, err)
	}
	// not reachable on a non-loopback address of node-b
	if addrs, _ := net.InterfaceAddrs(); len(addrs) > 0 {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
				continue
			}
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), strconv.Itoa(p1)), time.Second)
			if err == nil {
				c.Close()
				t.Fatalf("candidate port reachable on %s (must be 127.0.0.1 only)", ipn.IP)
			}
			t.Logf("port %d not reachable on %s: ok", p1, ipn.IP)
		}
	}

	// 2. PORT_IN_USE (real listener = v1's docker-proxy)
	if _, err := m.RunCandidate(ctx, mk("ppanel-labtest-00000009", imgs["WEB_V2"], p1, nil)); codeOf(err) != CodePortInUse {
		t.Fatalf("port in use: %v", err)
	}

	// 3. web v2 side by side
	p2 := pick()
	v2 := mk("ppanel-labtest-00000002", imgs["WEB_V2"], p2, nil)
	if _, err := m.RunCandidate(ctx, v2); err != nil {
		t.Fatalf("run web v2: %v", err)
	}
	created = append(created, v2.Name)
	if st, body := get(p2); st != 200 || body != "ppanel-test web v2" {
		t.Fatalf("web v2: %d %q", st, body)
	}

	// 4. broken → CANDIDATE_UNHEALTHY, removed, logTail
	pb := pick()
	_, err = m.RunCandidate(ctx, mk("ppanel-labtest-00000003", imgs["BROKEN"], pb, nil))
	if codeOf(err) != CodeCandidateUnhealthy {
		t.Fatalf("broken: %v", err)
	}
	d := detailsOf(err)
	t.Logf("broken: %v details=%v", err, d)
	if _, ierr := eng.InspectContainer(ctx, "ppanel-labtest-00000003"); !errors.Is(ierr, docker.ErrNotFound) {
		t.Fatalf("broken candidate not removed: %v", ierr)
	}
	if !strings.Contains(strings.Join(d.LogTail, "\n"), "fatal: missing configuration") {
		t.Fatalf("logTail %q", d.LogTail)
	}

	// 5. envecho: leaky app with a fake secret, forced unhealthy (expect 204) → logTail redacted
	pe := pick()
	pr := mk("ppanel-labtest-00000004", imgs["ENVECHO"], pe, map[string]any{"secretEnvKeys": []string{"APP_SECRET"},
		"healthcheck": map[string]any{"path": "/healthz", "expectStatus": []int{204}, "intervalSec": 1, "timeoutSec": 2, "startPeriodSec": 4}})
	_, err = m.RunCandidate(ctx, pr)
	if codeOf(err) != CodeCandidateUnhealthy {
		t.Fatalf("envecho unhealthy: %v", err)
	}
	ed := detailsOf(err)
	tail := strings.Join(ed.LogTail, "\n")
	t.Logf("envecho logTail: %q", ed.LogTail)
	if strings.Contains(tail, fakeSecret) || !strings.Contains(tail, "APP_SECRET="+Redacted) {
		t.Fatalf("envecho logTail not redacted: %q", tail)
	}
	errJSON, _ := json.Marshal(err)
	if strings.Contains(string(errJSON), fakeSecret) || strings.Contains(err.Error(), fakeSecret) {
		t.Fatal("secret in error result")
	}
	// second fetch for the same job → Center 409 → SECRETS_UNAVAILABLE, nothing created
	_, err = m.RunCandidate(ctx, mk("ppanel-labtest-00000005", imgs["ENVECHO"], pick(), map[string]any{"secretEnvKeys": []string{"APP_SECRET"}}))
	if codeOf(err) != CodeSecretsUnavailable {
		t.Fatalf("second secrets fetch: %v", err)
	}
	if _, ierr := eng.InspectContainer(ctx, "ppanel-labtest-00000005"); !errors.Is(ierr, docker.ErrNotFound) {
		t.Fatal("container created without secrets")
	}
	if strings.Contains(logBuf.String(), fakeSecret) {
		t.Fatal("secret in agent structured log")
	}

	// 6. lifecycle on v1
	ref := RefParams{App: app, Name: v1.Name}
	if _, err := m.Remove(ctx, ref); err == nil {
		t.Fatal("remove of running container accepted")
	}
	so, err := m.Stop(ctx, ref)
	if err != nil || so.State != "exited" {
		t.Fatalf("stop: %+v %v", so, err)
	}
	if st, _ := get(p1); st != 0 {
		t.Fatal("v1 still serving after stop")
	}
	hcp := v1.Healthcheck
	if so, err := m.Start(ctx, StartParams{App: app, Name: v1.Name, HostPort: p1, Healthcheck: hcp}, false); err != nil {
		t.Fatalf("start: %v", err)
	} else {
		t.Logf("start: %+v", so.Health)
	}
	if so, err := m.Start(ctx, StartParams{App: app, Name: v1.Name, HostPort: p1, Healthcheck: hcp}, true); err != nil {
		t.Fatalf("restart: %v", err)
	} else {
		t.Logf("restart: %+v", so.Health)
	}
	if st, body := get(p1); st != 200 || body != "ppanel-test web v1" {
		t.Fatalf("v1 after restart: %d %q", st, body)
	}
	lo, err := m.List(ctx, ListParams{App: app})
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := json.Marshal(lo)
	t.Logf("list: %s", lb)
	if len(lo.Containers) != 2 {
		t.Fatalf("list: expected 2 managed containers, got %d", len(lo.Containers))
	}
	logs, err := m.Logs(ctx, LogsParams{App: app, Name: v1.Name, TailLines: 20})
	if err != nil || len(logs.Lines) == 0 {
		t.Fatalf("logs: %+v %v", logs, err)
	}
	t.Logf("logs v1 (%d lines, truncated=%v): %q", len(logs.Lines), logs.Truncated, logs.Lines)
	for _, n := range []string{v1.Name, v2.Name} {
		if _, err := m.Stop(ctx, RefParams{App: app, Name: n}); err != nil {
			t.Fatal(err)
		}
		if ro, err := m.Remove(ctx, RefParams{App: app, Name: n}); err != nil || ro.State != "removed" {
			t.Fatalf("remove %s: %v", n, err)
		}
	}
	created = nil

	// 7. a container created directly in dind (no pPanel labels) is never touched
	if un := os.Getenv("PPANEL_LAB_UNMANAGED"); un != "" {
		before, err := eng.InspectContainer(ctx, un)
		if err != nil || !before.State.Running {
			t.Fatalf("unmanaged fixture %s not running: %v", un, err)
		}
		hp := StartParams{App: app, Name: un, HostPort: 20000, Healthcheck: hcp}
		_, e1 := m.Stop(ctx, RefParams{App: app, Name: un})
		_, e2 := m.Remove(ctx, RefParams{App: app, Name: un})
		_, e3 := m.Start(ctx, hp, true)
		_, e4 := m.Logs(ctx, LogsParams{App: app, Name: un, TailLines: 5})
		for i, e := range []error{e1, e2, e3, e4} {
			if codeOf(e) != CodeContainerNotManaged {
				t.Fatalf("unmanaged op%d: %v", i, e)
			}
		}
		after, err := eng.InspectContainer(ctx, un)
		if err != nil || !after.State.Running || after.State.StartedAt != before.State.StartedAt {
			t.Fatalf("unmanaged container was touched: %+v %v", after.State, err)
		}
		if lo, _ := m.List(ctx, ListParams{}); lo != nil {
			for _, c := range lo.Containers {
				if c.Name == un {
					t.Fatal("unmanaged container listed")
				}
			}
		}
		t.Logf("unmanaged %s: CONTAINER_NOT_MANAGED for stop/remove/restart/logs, still running (startedAt unchanged)", un)
	}
	if fetches != 2 {
		t.Fatalf("secrets fetch count %d (1 per job expected: envecho run + refused second)", fetches)
	}
}

type labDetails struct {
	LogTail    []string `json:"logTail"`
	ExitCode   *int     `json:"exitCode"`
	LastStatus *int     `json:"lastStatus"`
}

func codeOf(err error) string {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je.Code
	}
	if err != nil {
		return "non-job error: " + err.Error()
	}
	return ""
}

func detailsOf(err error) labDetails {
	var d labDetails
	b, _ := json.Marshal(err)
	var w struct {
		Details labDetails `json:"details"`
	}
	_ = json.Unmarshal(b, &w)
	d = w.Details
	return d
}
