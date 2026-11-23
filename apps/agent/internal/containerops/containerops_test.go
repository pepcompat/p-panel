package containerops

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/docker/dockertest"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

const (
	dep    = "0b7c2a7e-3f43-4a52-9d55-6f0e9a9b1c01"
	digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secret = "s3cr3t-Value-42!"
	regPw  = "reg-pa55-word"
)

func img(kind string) string { return "lab-registry:5000/ppanel-test/" + kind + "@" + digest }

type harness struct {
	fe      *dockertest.Engine
	m       *Manager
	logBuf  *syncBuf
	fetches atomic.Int32
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{fe: dockertest.New(t), logBuf: &syncBuf{}}
	log := slog.New(slog.NewJSONHandler(h.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.m = New(Options{Engine: docker.NewEngine(h.fe.Socket), Log: log,
		Secrets: func(ctx context.Context) (*transport.JobSecrets, error) {
			if h.fetches.Add(1) > 1 {
				return nil, &transport.APIError{HTTPStatus: 409, Code: "SECRETS_ALREADY_FETCHED", Message: "already fetched"}
			}
			return &transport.JobSecrets{Env: map[string]string{"APP_SECRET": secret},
				RegistryAuth: &transport.RegistryAuth{Username: "ci", Password: regPw, ServerAddress: "lab-registry:5000"}}, nil
		}})
	return h
}

func runParams(t *testing.T, kind string, port int, extra map[string]any) RunParams {
	t.Helper()
	m := map[string]any{"deploymentId": dep, "app": "shop", "name": "ppanel-shop-1a2b3c4d", "image": img(kind),
		"containerPort": 8080, "hostPort": port,
		"healthcheck": map[string]any{"path": "/healthz", "intervalSec": 1, "timeoutSec": 1, "startPeriodSec": 3}}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	p, err := DecodeRun(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func errCode(t *testing.T, err error) string {
	t.Helper()
	var je *jobs.Error
	if !errors.As(err, &je) {
		t.Fatalf("expected *jobs.Error, got %v", err)
	}
	return je.Code
}

func errDetails(t *testing.T, err error) map[string]any {
	var je *jobs.Error
	if !errors.As(err, &je) {
		t.Fatalf("expected *jobs.Error, got %v", err)
	}
	b, _ := json.Marshal(je.Details)
	var d map[string]any
	_ = json.Unmarshal(b, &d)
	return d
}

func createCalls(fe *dockertest.Engine) []dockertest.Call {
	var out []dockertest.Call
	for _, c := range fe.MutatingCalls() {
		if c.Path == "/containers/create" {
			out = append(out, c)
		}
	}
	return out
}

// ---------------- decode ----------------

func TestDecodeRunStrict(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"deploymentId": dep, "app": "shop", "name": "ppanel-shop-1a2b3c4d", "image": img("web"), "containerPort": 8080, "hostPort": 20001}
	}
	b, _ := json.Marshal(base())
	p, err := DecodeRun(b)
	if err != nil {
		t.Fatal(err)
	}
	want := Healthcheck{Path: "/", ExpectStatus: []int{200}, IntervalSec: 2, TimeoutSec: 3, StartPeriodSec: 60}
	if !reflect.DeepEqual(p.Healthcheck, want) || p.Resources != (Resources{512, 1, 512}) || p.RegistryAuth || p.ReadOnlyRootfs || len(p.Env) != 0 {
		t.Fatalf("defaults: %+v", p)
	}
	bad := map[string]func(m map[string]any){
		"tag-only-image":   func(m map[string]any) { m["image"] = "lab-registry:5000/ppanel-test/web:v1" },
		"latest":           func(m map[string]any) { m["image"] = "nginx:latest" },
		"short-digest":     func(m map[string]any) { m["image"] = "nginx@sha256:abc" },
		"tag-and-digest":   func(m map[string]any) { m["image"] = "nginx:v1@" + digest },
		"uppercase-image":  func(m map[string]any) { m["image"] = "Nginx@" + digest },
		"name-other-app":   func(m map[string]any) { m["name"] = "ppanel-blog-1a2b3c4d" },
		"name-bad":         func(m map[string]any) { m["name"] = "shop" },
		"port-low":         func(m map[string]any) { m["hostPort"] = 8080 },
		"port-high":        func(m map[string]any) { m["hostPort"] = 30000 },
		"port-float":       func(m map[string]any) { m["hostPort"] = 20001.5 },
		"unknown-field":    func(m map[string]any) { m["privileged"] = true },
		"unknown-nested":   func(m map[string]any) { m["resources"] = map[string]any{"memoryMb": 64, "devices": "x"} },
		"bad-env-key":      func(m map[string]any) { m["env"] = map[string]any{"lower": "x"} },
		"env-null":         func(m map[string]any) { m["env"] = nil },
		"secret-dup-env":   func(m map[string]any) { m["env"] = map[string]any{"A": "1"}; m["secretEnvKeys"] = []string{"A"} },
		"volume-host-path": func(m map[string]any) { m["volumes"] = []any{map[string]any{"name": "/var/run", "mountPath": "/data"}} },
		"volume-bind-field": func(m map[string]any) {
			m["volumes"] = []any{map[string]any{"name": "d", "mountPath": "/data", "source": "/"}}
		},
		"mount-traversal":    func(m map[string]any) { m["volumes"] = []any{map[string]any{"name": "d", "mountPath": "/data/../etc"}} },
		"health-bad-path":    func(m map[string]any) { m["healthcheck"] = map[string]any{"path": "http://evil/"} },
		"health-period-high": func(m map[string]any) { m["healthcheck"] = map[string]any{"startPeriodSec": 601} },
		"cpus-low":           func(m map[string]any) { m["resources"] = map[string]any{"cpus": 0.01} },
		"user-bad":           func(m map[string]any) { m["user"] = "root;rm" },
		"no-deployment":      func(m map[string]any) { delete(m, "deploymentId") },
	}
	for name, mut := range bad {
		m := base()
		mut(m)
		b, _ := json.Marshal(m)
		if _, err := DecodeRun(b); err == nil {
			t.Fatalf("%s accepted", name)
		} else if errCode(t, err) != jobs.RejectedInvalidParams {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"logs-tail-high": `{"app":"shop","name":"ppanel-shop-1a2b3c4d","tailLines":1001}`,
		"logs-extra":     `{"app":"shop","name":"ppanel-shop-1a2b3c4d","follow":true}`,
	} {
		if _, err := DecodeLogs(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := DecodeStart(json.RawMessage(`{"app":"shop","name":"ppanel-shop-1a2b3c4d"}`)); err == nil {
		t.Fatal("start without hostPort accepted")
	}
	if p, err := DecodeList(json.RawMessage(`{}`)); err != nil || p.App != "" {
		t.Fatal(err)
	}
}

// ---------------- hardened run ----------------

func TestRunCandidateHardenedHostConfig(t *testing.T) {
	h := newHarness(t)
	port := dockertest.FreePort(t)
	p := runParams(t, "web", port, map[string]any{"env": map[string]any{"MODE": "prod"},
		"volumes":   []any{map[string]any{"name": "data", "mountPath": "/data"}},
		"resources": map[string]any{"memoryMb": 256, "cpus": 0.5, "pids": 128}, "readOnlyRootfs": true,
		"command": []string{"/srv/web", "-v"}, "user": "1000:1000"})
	out, err := h.m.RunCandidate(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != p.Name || out.Image != p.Image || out.HostPort != port || out.ContainerID == "" || !strings.HasPrefix(out.ImageID, "sha256:") ||
		out.Health == nil || out.Health.Status != "healthy" || out.Health.Attempts < 1 {
		t.Fatalf("output %+v", out)
	}
	b, _ := json.Marshal(out)
	for _, k := range []string{`"containerId":`, `"name":`, `"image":`, `"imageId":`, `"hostPort":`, `"health":{"status":"healthy","attempts":`, `"elapsedMs":`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("output JSON missing %s: %s", k, b)
		}
	}
	cc := createCalls(h.fe)
	if len(cc) != 1 || cc[0].Query != "name=ppanel-shop-1a2b3c4d" {
		t.Fatalf("create calls %+v", cc)
	}
	var body map[string]any
	_ = json.Unmarshal(cc[0].Body, &body)
	hc := body["HostConfig"].(map[string]any)
	exp := map[string]any{
		"PortBindings":    map[string]any{"8080/tcp": []any{map[string]any{"HostIp": "127.0.0.1", "HostPort": strconv.Itoa(port)}}},
		"Privileged":      false,
		"PublishAllPorts": false,
		"CapDrop":         []any{"ALL"},
		"CapAdd":          []any{"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE", "DAC_OVERRIDE"},
		"SecurityOpt":     []any{"no-new-privileges:true"},
		"Memory":          float64(256 << 20),
		"MemorySwap":      float64(256 << 20),
		"NanoCpus":        float64(5e8),
		"PidsLimit":       float64(128),
		"ReadonlyRootfs":  true,
		"RestartPolicy":   map[string]any{"Name": "unless-stopped"},
		"NetworkMode":     "ppanel-shop",
		"IpcMode":         "private",
		"Mounts":          []any{map[string]any{"Type": "volume", "Source": "ppanel-shop-data", "Target": "/data", "ReadOnly": false}},
	}
	for k, v := range exp {
		if !reflect.DeepEqual(hc[k], v) {
			t.Fatalf("HostConfig.%s = %#v, want %#v", k, hc[k], v)
		}
	}
	for _, forbidden := range []string{"Binds", "Devices", "PidMode", "UsernsMode", "CgroupParent", "VolumesFrom", "Links", "CapAddAll", "DeviceRequests"} {
		if _, ok := hc[forbidden]; ok {
			t.Fatalf("HostConfig must not contain %s", forbidden)
		}
	}
	if strings.Contains(string(cc[0].Body), "docker.sock") || strings.Contains(string(cc[0].Body), `"host"`) {
		t.Fatalf("socket/host namespace in body: %s", cc[0].Body)
	}
	labels := body["Labels"].(map[string]any)
	if labels["ppanel.managed"] != "true" || labels["ppanel.app"] != "shop" || labels["ppanel.deployment"] != dep || labels["ppanel.image"] != p.Image {
		t.Fatalf("labels %v", labels)
	}
	if body["Image"] != p.Image || !reflect.DeepEqual(body["Env"], []any{"MODE=prod"}) || body["User"] != "1000:1000" ||
		!reflect.DeepEqual(body["Cmd"], []any{"/srv/web", "-v"}) || body["Tty"] != false {
		t.Fatalf("config %v", body)
	}
	if l := h.fe.Networks["ppanel-shop"]; l["ppanel.managed"] != "true" {
		t.Fatalf("network labels %v", l)
	}
	if l := h.fe.Volumes["ppanel-shop-data"]; l["ppanel.managed"] != "true" || l["ppanel.app"] != "shop" {
		t.Fatalf("volume labels %v", l)
	}
	// pull was by digest, no secrets fetched (none requested)
	for _, c := range h.fe.MutatingCalls() {
		if c.Path == "/images/create" && c.Query != "fromImage=lab-registry%3A5000%2Fppanel-test%2Fweb&tag="+strings.ReplaceAll(digest, ":", "%3A") {
			t.Fatalf("pull query %s", c.Query)
		}
		if c.Header.Get("X-Registry-Auth") != "" {
			t.Fatal("registry auth sent without registryAuth")
		}
	}
	if h.fetches.Load() != 0 {
		t.Fatal("secrets fetched without secret keys")
	}
	// same name again → CONTAINER_EXISTS, no new create
	if _, err := h.m.RunCandidate(context.Background(), p); errCode(t, err) != CodeContainerExists {
		t.Fatalf("exists: %v", err)
	}
	if len(createCalls(h.fe)) != 1 {
		t.Fatal("create called for existing name")
	}
}

func TestRunCandidateRefusesUnmanagedNetworkOrVolume(t *testing.T) {
	h := newHarness(t)
	h.fe.Networks["ppanel-shop"] = map[string]string{}
	_, err := h.m.RunCandidate(context.Background(), runParams(t, "web", dockertest.FreePort(t), nil))
	if errCode(t, err) != CodeContainerNotManaged || len(createCalls(h.fe)) != 0 {
		t.Fatalf("unmanaged network: %v", err)
	}
	h.fe.Networks["ppanel-shop"] = map[string]string{"ppanel.managed": "true"}
	h.fe.Volumes["ppanel-shop-data"] = map[string]string{"owner": "someone"}
	_, err = h.m.RunCandidate(context.Background(), runParams(t, "web", dockertest.FreePort(t),
		map[string]any{"volumes": []any{map[string]any{"name": "data", "mountPath": "/data"}}}))
	if errCode(t, err) != CodeContainerNotManaged || len(createCalls(h.fe)) != 0 {
		t.Fatalf("unmanaged volume: %v", err)
	}
}

// ---------------- secrets ----------------

func TestSecretsFetchedOnceNeverLeaked(t *testing.T) {
	h := newHarness(t)
	port := dockertest.FreePort(t)
	p := runParams(t, "envecho", port, map[string]any{"secretEnvKeys": []string{"APP_SECRET"}, "registryAuth": true})
	out, err := h.m.RunCandidate(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if h.fetches.Load() != 1 {
		t.Fatalf("secrets fetched %d times", h.fetches.Load())
	}
	// the value reached the engine (env) and the registry auth header — nowhere else
	cc := createCalls(h.fe)
	if !strings.Contains(string(cc[0].Body), "APP_SECRET="+secret) {
		t.Fatal("secret env not passed to the engine")
	}
	var auth string
	for _, c := range h.fe.MutatingCalls() {
		if c.Path == "/images/create" {
			auth = c.Header.Get("X-Registry-Auth")
		}
	}
	raw, err := base64.URLEncoding.DecodeString(auth)
	if err != nil || !strings.Contains(string(raw), `"password":"`+regPw+`"`) || !strings.Contains(string(raw), `"serveraddress":"lab-registry:5000"`) {
		t.Fatalf("X-Registry-Auth %q (%v)", raw, err)
	}
	res, _ := json.Marshal(out)
	for _, s := range []string{secret, regPw} {
		if strings.Contains(string(res), s) || strings.Contains(h.logBuf.String(), s) {
			t.Fatalf("secret leaked: result=%s log=%s", res, h.logBuf.String())
		}
	}
	if !strings.Contains(h.logBuf.String(), "secrets received") {
		t.Fatal("expected structured log lines to be captured")
	}
	// a second run of the same job: the Center refuses (409) → SECRETS_UNAVAILABLE, nothing created
	p2 := runParams(t, "envecho", dockertest.FreePort(t), map[string]any{"name": "ppanel-shop-2a2b3c4d", "secretEnvKeys": []string{"APP_SECRET"}})
	_, err = h.m.RunCandidate(context.Background(), p2)
	if errCode(t, err) != CodeSecretsUnavailable || len(createCalls(h.fe)) != 1 {
		t.Fatalf("second fetch: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("secret in error")
	}
}

func TestSecretsMissingKeyNothingCreated(t *testing.T) {
	h := newHarness(t)
	p := runParams(t, "web", dockertest.FreePort(t), map[string]any{"secretEnvKeys": []string{"APP_SECRET", "DB_PASSWORD"}})
	_, err := h.m.RunCandidate(context.Background(), p)
	if errCode(t, err) != CodeSecretsUnavailable {
		t.Fatal(err)
	}
	for _, c := range h.fe.MutatingCalls() {
		t.Fatalf("mutating call after missing secret: %s %s", c.Method, c.Path)
	}
}

// ---------------- unhealthy ----------------

func TestUnhealthyCandidateRemovedWithRedactedLogTail(t *testing.T) {
	h := newHarness(t)
	// envecho serves 200, so expect 204 to force "unhealthy" while the app logs its secret
	p := runParams(t, "envecho", dockertest.FreePort(t), map[string]any{"secretEnvKeys": []string{"APP_SECRET"},
		"healthcheck": map[string]any{"path": "/healthz", "expectStatus": []int{204}, "intervalSec": 1, "timeoutSec": 1, "startPeriodSec": 2}})
	_, err := h.m.RunCandidate(context.Background(), p)
	if errCode(t, err) != CodeCandidateUnhealthy {
		t.Fatal(err)
	}
	d := errDetails(t, err)
	if d["lastStatus"] != float64(200) || d["removed"] != true {
		t.Fatalf("details %v", d)
	}
	tail := fmt.Sprint(d["logTail"])
	if strings.Contains(tail, secret) || !strings.Contains(tail, "APP_SECRET="+Redacted) || strings.Contains(tail, "\x1b") || !strings.Contains(tail, "ready secret="+Redacted) {
		t.Fatalf("logTail not redacted/stripped: %q", tail)
	}
	if h.fe.Find(p.Name) != nil {
		t.Fatal("unhealthy candidate not removed")
	}
	var del bool
	for _, c := range h.fe.MutatingCalls() {
		if c.Method == http.MethodDelete && strings.Contains(c.Query, "force=1") && strings.Contains(c.Query, "v=0") {
			del = true
		}
	}
	if !del {
		t.Fatal("expected DELETE ?force=1&v=0")
	}
	if strings.Contains(h.logBuf.String(), secret) {
		t.Fatal("secret in agent log")
	}

	// broken: healthz 500
	p = runParams(t, "broken", dockertest.FreePort(t), map[string]any{"name": "ppanel-shop-3a2b3c4d",
		"healthcheck": map[string]any{"path": "/healthz", "intervalSec": 1, "timeoutSec": 1, "startPeriodSec": 2}})
	_, err = h.m.RunCandidate(context.Background(), p)
	if errCode(t, err) != CodeCandidateUnhealthy || errDetails(t, err)["lastStatus"] != float64(500) || h.fe.Find(p.Name) != nil {
		t.Fatalf("broken: %v", err)
	}

	// crash: fail fast on exit (well before startPeriodSec)
	p = runParams(t, "crash", dockertest.FreePort(t), map[string]any{"name": "ppanel-shop-4a2b3c4d",
		"healthcheck": map[string]any{"intervalSec": 5, "startPeriodSec": 120}})
	start := time.Now()
	_, err = h.m.RunCandidate(context.Background(), p)
	if errCode(t, err) != CodeCandidateUnhealthy || time.Since(start) > 10*time.Second {
		t.Fatalf("crash: %v after %s", err, time.Since(start))
	}
	d = errDetails(t, err)
	if d["exitCode"] != float64(3) || !strings.Contains(fmt.Sprint(d["logTail"]), "fatal: cannot start") || h.fe.Find(p.Name) != nil {
		t.Fatalf("crash details %v", d)
	}
}

// ---------------- preflight errors ----------------

func TestPortInUse(t *testing.T) {
	h := newHarness(t)
	port := dockertest.FreePort(t)
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !LoopbackPortInUse(port) {
		t.Fatal("LoopbackPortInUse false for a listening port")
	}
	_, err = h.m.RunCandidate(context.Background(), runParams(t, "web", port, nil))
	if errCode(t, err) != CodePortInUse {
		t.Fatal(err)
	}
	if len(h.fe.MutatingCalls()) != 0 {
		t.Fatal("mutating call despite PORT_IN_USE")
	}
	ln.Close()
	if LoopbackPortInUse(port) {
		t.Fatal("free port reported in use")
	}
}

func TestDockerUnavailable(t *testing.T) {
	h := newHarness(t)
	h.fe.Close()
	ctx := context.Background()
	_, err := h.m.RunCandidate(ctx, runParams(t, "web", dockertest.FreePort(t), nil))
	if errCode(t, err) != CodeDockerUnavailable {
		t.Fatalf("run: %v", err)
	}
	if _, err := h.m.List(ctx, ListParams{}); errCode(t, err) != CodeDockerUnavailable {
		t.Fatalf("list: %v", err)
	}
	if _, err := h.m.Stop(ctx, RefParams{App: "shop", Name: "ppanel-shop-1a2b3c4d"}); errCode(t, err) != CodeDockerUnavailable {
		t.Fatalf("stop: %v", err)
	}
	nm := New(Options{})
	if _, err := nm.List(ctx, ListParams{}); errCode(t, err) != CodeDockerUnavailable {
		t.Fatalf("unconfigured: %v", err)
	}
}

// ---------------- ownership ----------------

func TestOwnershipRefusalNoMutatingCall(t *testing.T) {
	h := newHarness(t)
	// created outside pPanel with a managed-looking name, no labels
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-shop-aaaaaaaa", Image: "nginx", HostPort: 20500})
	// pPanel labels but for another app (renamed across apps)
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-shop-bbbbbbbb", HostPort: 20501, Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "blog"}})
	// managed=false
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-shop-cccccccc", HostPort: 20502, Labels: map[string]string{"ppanel.managed": "false", "ppanel.app": "shop"}})
	// renamed: a managed container renamed to something outside the pattern
	h.fe.AddContainer(&dockertest.Container{Name: "my-db", HostPort: 20503, Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "shop"}})
	ctx := context.Background()
	for _, name := range []string{"ppanel-shop-aaaaaaaa", "ppanel-shop-bbbbbbbb", "ppanel-shop-cccccccc", "my-db", "ppanel-blog-bbbbbbbb"} {
		ref := RefParams{App: "shop", Name: name}
		_, e1 := h.m.Stop(ctx, ref)
		_, e2 := h.m.Remove(ctx, ref)
		_, e3 := h.m.Start(ctx, StartParams{App: "shop", Name: name, HostPort: 20500, Healthcheck: Healthcheck{Path: "/", ExpectStatus: []int{200}, IntervalSec: 1, TimeoutSec: 1, StartPeriodSec: 1}}, false)
		_, e4 := h.m.Start(ctx, StartParams{App: "shop", Name: name, HostPort: 20500, Healthcheck: Healthcheck{Path: "/", ExpectStatus: []int{200}, IntervalSec: 1, TimeoutSec: 1, StartPeriodSec: 1}}, true)
		_, e5 := h.m.Logs(ctx, LogsParams{App: "shop", Name: name, TailLines: 10})
		for i, err := range []error{e1, e2, e3, e4, e5} {
			if errCode(t, err) != CodeContainerNotManaged {
				t.Fatalf("%s op%d: %v", name, i, err)
			}
		}
	}
	if mc := h.fe.MutatingCalls(); len(mc) != 0 {
		t.Fatalf("mutating calls reached the engine: %+v", mc)
	}
	// names that don't match the app pattern never reach the engine at all
	n := len(h.fe.CallsSnapshot())
	_, err := h.m.Stop(ctx, RefParams{App: "shop", Name: "my-db"})
	if errCode(t, err) != CodeContainerNotManaged || len(h.fe.CallsSnapshot()) != n {
		t.Fatal("pattern mismatch should be refused without any docker call")
	}
	// list only reports owned containers
	out, err := h.m.List(ctx, ListParams{})
	if err != nil || len(out.Containers) != 0 {
		t.Fatalf("list exposed unmanaged containers: %+v %v", out, err)
	}
	if _, err := h.m.Stop(ctx, RefParams{App: "shop", Name: "ppanel-shop-dddddddd"}); errCode(t, err) != CodeContainerNotFound {
		t.Fatalf("missing: %v", err)
	}
}

// ---------------- lifecycle ----------------

func TestLifecycleStopStartRestartRemoveList(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	port := dockertest.FreePort(t)
	p := runParams(t, "web", port, nil)
	if _, err := h.m.RunCandidate(ctx, p); err != nil {
		t.Fatal(err)
	}
	ref := RefParams{App: "shop", Name: p.Name}
	if _, err := h.m.Remove(ctx, ref); errCode(t, err) != jobs.HandlerFailed || !strings.Contains(err.Error(), "stop it first") {
		t.Fatalf("remove running: %v", err)
	}
	so, err := h.m.Stop(ctx, ref)
	if err != nil || so.State != "exited" || so.Name != p.Name {
		t.Fatalf("stop: %+v %v", so, err)
	}
	if !strings.Contains(findCall(h.fe, "/stop").Query, "t=10") {
		t.Fatal("stop grace must be 10s")
	}
	hc := p.Healthcheck
	st, err := h.m.Start(ctx, StartParams{App: "shop", Name: p.Name, HostPort: port, Healthcheck: hc}, false)
	if err != nil || st.Health.Status != "healthy" {
		t.Fatalf("start: %+v %v", st, err)
	}
	b, _ := json.Marshal(st)
	if !strings.HasPrefix(string(b), `{"name":"ppanel-shop-1a2b3c4d","health":{"status":"healthy"`) {
		t.Fatalf("start JSON %s", b)
	}
	if _, err := h.m.Start(ctx, StartParams{App: "shop", Name: p.Name, HostPort: port + 1, Healthcheck: hc}, true); errCode(t, err) != jobs.HandlerFailed {
		t.Fatalf("restart with wrong hostPort: %v", err)
	}
	if rs, err := h.m.Start(ctx, StartParams{App: "shop", Name: p.Name, HostPort: port, Healthcheck: hc}, true); err != nil || rs.Health.Status != "healthy" {
		t.Fatalf("restart: %v", err)
	}
	lo, err := h.m.List(ctx, ListParams{App: "shop"})
	if err != nil || len(lo.Containers) != 1 {
		t.Fatalf("list %+v %v", lo, err)
	}
	c := lo.Containers[0]
	if c.Name != p.Name || c.Image != p.Image || *c.HostPort != port || c.DeploymentID != dep || c.State != "running" || c.CreatedAt == "" || c.App != "shop" {
		t.Fatalf("list entry %+v", c)
	}
	lb, _ := json.Marshal(lo)
	for _, k := range []string{`"name"`, `"id"`, `"image"`, `"state"`, `"status"`, `"hostPort"`, `"deploymentId"`, `"createdAt"`} {
		if !strings.Contains(string(lb), k) {
			t.Fatalf("list JSON missing %s", k)
		}
	}
	if other, _ := h.m.List(ctx, ListParams{App: "blog"}); len(other.Containers) != 0 {
		t.Fatal("app filter ignored")
	}
	if _, err := h.m.Stop(ctx, ref); err != nil {
		t.Fatal(err)
	}
	ro, err := h.m.Remove(ctx, ref)
	if err != nil || ro.State != "removed" || h.fe.Find(p.Name) != nil {
		t.Fatalf("remove %+v %v", ro, err)
	}
	for _, c := range h.fe.MutatingCalls() {
		if c.Method == http.MethodDelete && (strings.Contains(c.Query, "v=1") || strings.Contains(c.Query, "force=1")) {
			t.Fatalf("container.remove must not force/remove volumes: %s", c.Query)
		}
	}
}

func TestStartUnhealthyLeftStoppedNotRemoved(t *testing.T) {
	h := newHarness(t)
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-shop-eeeeeeee", Image: img("broken"), Status: "exited", HostPort: dockertest.FreePort(t),
		Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "shop"}})
	c := h.fe.Find("ppanel-shop-eeeeeeee")
	_, err := h.m.Start(context.Background(), StartParams{App: "shop", Name: c.Name, HostPort: c.HostPort,
		Healthcheck: Healthcheck{Path: "/", ExpectStatus: []int{200}, IntervalSec: 1, TimeoutSec: 1, StartPeriodSec: 2}}, false)
	if errCode(t, err) != CodeCandidateUnhealthy || errDetails(t, err)["removed"] != false {
		t.Fatalf("start broken: %v", err)
	}
	if got := h.fe.Find(c.Name); got == nil || got.Status != "exited" {
		t.Fatal("container must be left stopped, not removed")
	}
}

func findCall(fe *dockertest.Engine, suffix string) dockertest.Call {
	for _, c := range fe.CallsSnapshot() {
		if strings.HasSuffix(c.Path, suffix) {
			return c
		}
	}
	return dockertest.Call{}
}

// ---------------- serialization ----------------

func TestPerAppSerialization(t *testing.T) {
	h := newHarness(t)
	h.fe.StartDelay = 300 * time.Millisecond
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i, app := range []string{"shop", "shop", "shop", "blog", "blog", "news"} {
		wg.Add(1)
		go func(i int, app string) {
			defer wg.Done()
			p := runParams(t, "web", 20000, nil)
			p.App, p.Name = app, fmt.Sprintf("ppanel-%s-%08x", app, i)
			p.HostPort = 21000 + i*7 + int(time.Now().UnixNano()%500)
			_, err := h.m.RunCandidate(context.Background(), p)
			errs <- err
		}(i, app)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if h.fe.MaxInflight["shop"] != 1 || h.fe.MaxInflight["blog"] != 1 {
		t.Fatalf("per-app concurrency: %v", h.fe.MaxInflight)
	}
	if h.fe.MaxTotal < 2 {
		t.Fatalf("different apps should run in parallel (max total %d)", h.fe.MaxTotal)
	}
	// a waiter gives up when its job times out
	unlock, _ := h.m.lockApp(context.Background(), "x")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.m.lockApp(ctx, "x"); errCode(t, err) != jobs.HandlerTimeout {
		t.Fatal(err)
	}
	unlock()
}

// ---------------- logs ----------------

func TestLogsRedactionANSIAndCaps(t *testing.T) {
	h := newHarness(t)
	big := strings.Repeat("y", 1000)
	var sb strings.Builder
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&sb, "\x1b[31mline %d\x1b[0m %s token=%s\n", i, big, secret)
	}
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-shop-ffffffff", HostPort: 20600, Logs: sb.String(),
		Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "shop"}})
	h.m.setHeld("shop", []string{secret}) // values held while a run job of this app is active
	out, err := h.m.Logs(context.Background(), LogsParams{App: "shop", Name: "ppanel-shop-ffffffff", TailLines: 1000})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, l := range out.Lines {
		total += len(l) + 1
		if strings.Contains(l, secret) || strings.Contains(l, "\x1b") || !strings.Contains(l, "token="+Redacted) {
			t.Fatalf("bad line %q", l)
		}
	}
	if !out.Truncated || total > MaxLogBytes || len(out.Lines) == 0 || !strings.HasPrefix(out.Lines[len(out.Lines)-1], "line 1499 ") {
		t.Fatalf("caps: lines=%d bytes=%d truncated=%v", len(out.Lines), total, out.Truncated)
	}
	if !strings.Contains(findCall(h.fe, "/logs").Query, "tail=1000") {
		t.Fatal("tail not passed")
	}
	h.m.setHeld("shop", nil)
	small, err := h.m.Logs(context.Background(), LogsParams{App: "shop", Name: "ppanel-shop-ffffffff", TailLines: 3, SinceSec: 60})
	if err != nil || len(small.Lines) != 3 || small.Truncated {
		t.Fatalf("small: %+v %v", small, err)
	}
	if !strings.Contains(findCall(h.fe, "/logs").Query, "since=") {
		// the first /logs call is matched; check the last one instead
		calls := h.fe.CallsSnapshot()
		if !strings.Contains(calls[len(calls)-1].Query, "since=") {
			t.Fatal("since not passed")
		}
	}
}

func TestLogLinesAndRedactHelpers(t *testing.T) {
	lines, tr := LogLines("a\r\n\x1b[1mb\x1b[0m\x07\n\x1b]0;title\x07c pw\n", []string{"pw", ""}, 10, 1000)
	if !reflect.DeepEqual(lines, []string{"a", "b", "c " + Redacted}) || tr {
		t.Fatalf("%q %v", lines, tr)
	}
	if got := Redact("abcabc", []string{"abc", "abcabc"}); got != Redacted {
		t.Fatalf("longest first: %q", got)
	}
	if l, _ := LogLines("", nil, 5, 5); len(l) != 0 {
		t.Fatal("empty")
	}
}

// ---------------- engine allowlist ----------------

func TestEngineAllowlist(t *testing.T) {
	allowed := [][2]string{{"GET", "/containers/json"}, {"GET", "/_ping"}, {"POST", "/images/create"}, {"POST", "/containers/create"},
		{"POST", "/containers/ppanel-shop-1a2b3c4d/start"}, {"POST", "/containers/abc/stop"}, {"DELETE", "/containers/abc"},
		{"POST", "/networks/create"}, {"POST", "/volumes/create"}}
	refused := [][2]string{{"POST", "/containers/abc/exec"}, {"POST", "/exec/abc/start"}, {"POST", "/build"}, {"DELETE", "/images/x"},
		{"DELETE", "/volumes/ppanel-shop-data"}, {"DELETE", "/networks/x"}, {"POST", "/containers/abc/kill"}, {"PUT", "/containers/abc/archive"},
		{"POST", "/containers/abc/update"}, {"POST", "/swarm/init"}, {"POST", "/plugins/pull"}, {"GET", "/exec/abc/json"},
		{"POST", "/containers/prune"}, {"POST", "/containers/abc/rename"}, {"POST", "/containers/../exec/start"}}
	for _, a := range allowed {
		if !docker.AllowedCall(a[0], a[1]) {
			t.Fatalf("%v should be allowed", a)
		}
	}
	for _, r := range refused {
		if docker.AllowedCall(r[0], r[1]) {
			t.Fatalf("%v must be refused", r)
		}
	}
}
