package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/buildops"
	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// TestLabBuildAndCompose is the P4b REAL-lab test. It must run INSIDE ppanel-lab-node-b
// (build node: git installed, /etc/ppanel-agent/config.yaml with build.enabled) against lab-dind,
// lab-git and lab-registry. Opt-in, driven by scripts/lab/agent_build_lab.sh:
//
//	PPANEL_LAB_BUILD=1 + the PPANEL_LAB_GIT_* keys of .lab/git.env ./handlers.test -test.run TestLabBuildAndCompose -test.v
//
// The Center's one-time secrets endpoint is an in-process stub (one fetch per "job").
func TestLabBuildAndCompose(t *testing.T) {
	if os.Getenv("PPANEL_LAB_BUILD") != "1" {
		t.Skip("set PPANEL_LAB_BUILD=1 (inside ppanel-lab-node-b) to run against lab-dind + lab-git + lab-registry")
	}
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s not set (source .lab/git.env)", k)
		}
		return v
	}
	const (
		sock       = "/var/run/docker.sock"
		pushPrefix = "lab-registry:5000/ppanel-build/"
		dbPassword = "lab-FAKE-db-pw-7c1e"
		// postgres:16-alpine pinned by multi-arch index digest (same as infra/lab/git/stack/*/compose.yml)
		pgImage = "docker.io/library/postgres@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
	)
	ctx := context.Background()
	var logBuf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 0. the node's real agent config (mounted by infra/compose/lab.yml) makes it a build node
	cfg, err := config.Load(config.DefaultPath)
	if err != nil || !cfg.Build.Enabled || strings.Join(cfg.Build.GitHostsAllowlist, ",") != "lab-git" {
		t.Fatalf("node-b agent config: %v %+v", err, cfg)
	}
	gitBin, ok := execx.Find("git", "")
	if !ok {
		t.Fatal("git not installed on the build node")
	}
	henv := &host.Env{Docker: docker.New(sock), BuildEnabled: cfg.Build.Enabled, GitBinary: gitBin}
	if caps := strings.Join(henv.Capabilities(), ","); !strings.Contains(caps, "docker,build") {
		t.Fatalf("capabilities %s (want docker,build)", caps)
	}
	t.Logf("capabilities: %v", henv.Capabilities())

	var fetches int
	secretsFn := func(context.Context) (*transport.JobSecrets, error) {
		fetches++
		if fetches > 1 {
			return nil, &transport.APIError{HTTPStatus: 409, Code: "SECRETS_ALREADY_FETCHED"}
		}
		return &transport.JobSecrets{Env: map[string]string{"DB_PASSWORD": dbPassword}}, nil
	}
	newJob := func() { fetches = 0 }
	bm := buildops.New(buildops.Options{Engine: docker.NewBuildEngine(sock), Exec: execx.System{}, GitBinary: gitBin,
		WorkDir: t.TempDir(), AllowedHosts: cfg.Build.GitHostsAllowlist, Log: lg, Secrets: secretsFn})
	cm := containerops.New(containerops.Options{Engine: docker.NewEngine(sock), Log: lg, Secrets: secretsFn})

	// NOT_A_BUILD_NODE when builds are disabled (node-a / default config), decided before ack
	regOff, regOn := jobs.NewRegistry(), jobs.NewRegistry()
	RegisterAll(regOff, &Deps{Host: henv, Containers: cm})
	RegisterAll(regOn, &Deps{Host: henv, Containers: cm, Builds: bm})
	bp := func(id, app, repoKey, shaKey string, extra map[string]any) map[string]any {
		m := map[string]any{"buildId": id, "app": app, "source": map[string]any{"url": env("PPANEL_LAB_GIT_URL_" + repoKey), "commitSha": env(shaKey)},
			"dockerfile": "Dockerfile", "pushRepo": pushPrefix + app, "limits": map[string]any{"memoryMb": 1024, "cpus": 2, "timeoutSec": 900}}
		for k, v := range extra {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	g := func(typ string, params any) *jobs.Grant {
		b, _ := json.Marshal(params)
		return &jobs.Grant{JobID: "lab-" + strconv.FormatInt(time.Now().UnixNano(), 36), Type: typ, Params: b, LeaseToken: "l", ServerID: "s", ExpiresAt: time.Now().Add(time.Hour)}
	}
	if _, _, rej := regOff.Validate(g("image.build", bp("0d6a1b6e-0000-4000-8000-000000000001", "websrc", "WEBSRC", "PPANEL_LAB_GIT_SHA_WEBSRC", nil)), "s", time.Now()); rej == nil || rej.Code != buildops.CodeNotABuildNode {
		t.Fatalf("build disabled: %+v", rej)
	}
	t.Log("PASS NOT_A_BUILD_NODE before ack when build.enabled=false")
	notAllowed := bp("0d6a1b6e-0000-4000-8000-000000000001", "websrc", "WEBSRC", "PPANEL_LAB_GIT_SHA_WEBSRC", nil)
	notAllowed["source"] = map[string]any{"url": "https://github.com/acme/web", "commitSha": env("PPANEL_LAB_GIT_SHA_WEBSRC")}
	if _, _, rej := regOn.Validate(g("image.build", notAllowed), "s", time.Now()); rej == nil || rej.Code != buildops.CodeGitHostNotAllowed {
		t.Fatalf("host allowlist: %+v", rej)
	}
	t.Log("PASS GIT_HOST_NOT_ALLOWED before ack for a host outside build.gitHostsAllowlist")

	build := func(params map[string]any) *buildops.BuildOutput {
		t.Helper()
		newJob()
		h, p, rej := regOn.Validate(g("image.build", params), "s", time.Now())
		if rej != nil {
			t.Fatalf("validate: %+v", rej)
		}
		start := time.Now()
		out, err := h.Run(ctx, p)
		if err != nil {
			if je, ok := err.(*jobs.Error); ok {
				d, _ := json.Marshal(je.Details)
				t.Fatalf("build %v: %s\n%s", params["app"], je.Error(), d)
			}
			t.Fatal(err)
		}
		bo := out.(*buildops.BuildOutput)
		t.Logf("built %s in %s (%d log lines; tail: %q)", bo.Image, time.Since(start).Round(time.Second), len(bo.Log), bo.LogTail[len(bo.LogTail)-1])
		return bo
	}
	get := func(port int, path string) (int, string) {
		c := &http.Client{Timeout: 5 * time.Second}
		resp, err := c.Get("http://127.0.0.1:" + strconv.Itoa(port) + path)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, strings.TrimSpace(string(b))
	}

	// 1. websrc v1 by Dockerfile -> pushed digest -> run via containerops -> 200
	web := build(bp("0d6a1b6e-0000-4000-8000-0000000000a1", "websrc", "WEBSRC", "PPANEL_LAB_GIT_SHA_WEBSRC", nil))
	if !containerops.ImageDigestRefRe.MatchString(web.Image) || !strings.HasPrefix(web.Image, pushPrefix+"websrc@sha256:") || web.Tag != "build-0d6a1b6e0000" {
		t.Fatalf("build output %+v", web)
	}
	if _, err := docker.NewEngine(sock).InspectImage(ctx, pushPrefix+"websrc:build-0d6a1b6e0000"); err == nil {
		t.Fatal("local build tag must be removed after push")
	}
	webPort := 23400 + int(time.Now().Unix()%300)
	runRaw, _ := json.Marshal(map[string]any{"deploymentId": "0d6a1b6e-0000-4000-8000-0000000000b1", "app": "labbuild", "name": "ppanel-labbuild-0d6a1b6e",
		"image": web.Image, "containerPort": 8080, "hostPort": webPort, "resources": map[string]any{"memoryMb": 64, "cpus": 0.5, "pids": 64},
		"healthcheck": map[string]any{"path": "/healthz", "intervalSec": 1, "timeoutSec": 2, "startPeriodSec": 30}})
	rp, err := containerops.DecodeRun(runRaw)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := cm.RunCandidate(ctx, rp)
	if err != nil {
		t.Fatalf("run built image: %v", err)
	}
	if st, body := get(webPort, "/"); st != 200 || !strings.Contains(body, "websrc v1") {
		t.Fatalf("websrc: %d %q", st, body)
	}
	t.Logf("PASS websrc v1 built from git (commit %s) -> %s -> running %s -> GET / 200 'websrc v1'", web.CommitSha[:12], web.Image, ro.Name)
	cm.Stop(ctx, containerops.RefParams{App: "labbuild", Name: rp.Name})
	cm.Remove(ctx, containerops.RefParams{App: "labbuild", Name: rp.Name})

	// 2. stack app image (v1 and v2)
	app1 := build(bp("0d6a1b6e-0000-4000-8000-0000000000c1", "stack", "STACK", "PPANEL_LAB_GIT_SHA_STACK", nil))
	app2 := build(bp("0d6a1b6e-0000-4000-8000-0000000000c2", "stack", "STACK", "PPANEL_LAB_GIT_SHA_STACK_V2", nil))
	if app1.Image == app2.Image {
		t.Fatal("v1 and v2 must produce different digests")
	}

	// 3. compose plan db + worker + app
	const app = "labstack"
	appPort1, appPort2 := 23800+int(time.Now().Unix()%100), 23950+int(time.Now().Unix()%40)
	dbEnv := map[string]string{"POSTGRES_USER": "app", "POSTGRES_DB": "app"}
	appEnv := map[string]string{"DB_HOST": "db", "DB_NAME": "app", "DB_USER": "app"}
	res := map[string]any{"memoryMb": 256, "cpus": 1, "pids": 256}
	plan := func(hexApp string, appImage, appSpec string, port int) containerops.ComposeApplyParams {
		raw := map[string]any{"deploymentId": "0d6a1b6e-0000-4000-8000-0000000000d1", "app": app, "routeService": "app", "services": []any{
			map[string]any{"service": "db", "name": "ppanel-" + app + "-db-0d6a1b6e", "image": pgImage, "specHash": strings.Repeat("1", 64),
				"env": dbEnv, "secretEnv": map[string]string{"POSTGRES_PASSWORD": "DB_PASSWORD"}, "resources": res,
				"volumes": []any{map[string]any{"name": "pgdata", "mountPath": "/var/lib/postgresql/data"}},
				"health":  map[string]any{"type": "tcp", "port": 5432, "startPeriodSec": 90}},
			map[string]any{"service": "worker", "name": "ppanel-" + app + "-worker-0d6a1b6e", "image": app1.Image, "specHash": strings.Repeat("2", 64),
				"env": appEnv, "secretEnv": map[string]string{"DB_PASSWORD": "DB_PASSWORD"}, "command": []string{"php", "/app/worker.php"},
				"dependsOn": []string{"db"}, "resources": res, "health": map[string]any{"type": "running", "startPeriodSec": 5}},
			map[string]any{"service": "app", "name": "ppanel-" + app + "-app-" + hexApp, "image": appImage, "specHash": appSpec,
				"env": appEnv, "secretEnv": map[string]string{"DB_PASSWORD": "DB_PASSWORD"}, "dependsOn": []string{"db"}, "resources": res,
				"hostPort": port, "containerPort": 8080,
				"health": map[string]any{"type": "http", "port": 8080, "path": "/healthz", "intervalSec": 1, "timeoutSec": 3, "startPeriodSec": 60}},
		}}
		newJob()
		b, _ := json.Marshal(raw)
		h, p, rej := regOn.Validate(&jobs.Grant{JobID: "c", Type: "compose.apply", Params: b, LeaseToken: "l", ServerID: "s", ExpiresAt: time.Now().Add(time.Hour)}, "s", time.Now())
		if rej != nil || h.Type() != "compose.apply" {
			t.Fatalf("compose validate: %+v", rej)
		}
		return p.(containerops.ComposeApplyParams)
	}
	ids := func() map[string]string {
		out := map[string]string{}
		l, _ := cm.List(ctx, containerops.ListParams{App: app})
		for _, c := range l.Containers {
			if c.State == "running" {
				out[c.Name] = c.ID
			}
		}
		return out
	}
	t.Cleanup(func() {
		// remove the test's containers (volumes are never removed by the agent; left for inspection)
		cm.ComposeStop(context.Background(), containerops.ComposeStopParams{App: app})
		l, _ := cm.List(context.Background(), containerops.ListParams{App: app})
		for _, c := range l.Containers {
			cm.Remove(context.Background(), containerops.RefParams{App: app, Name: c.Name})
		}
	})
	start := time.Now()
	out1, err := cm.ComposeApply(ctx, plan("0d6a1b6e", app1.Image, strings.Repeat("3", 64), appPort1))
	if err != nil {
		if je, ok := err.(*jobs.Error); ok {
			d, _ := json.Marshal(je.Details)
			t.Fatalf("compose apply v1: %v\n%s", err, d)
		}
		t.Fatal(err)
	}
	b1, _ := json.Marshal(out1)
	t.Logf("compose v1 applied in %s: %s", time.Since(start).Round(time.Second), b1)
	time.Sleep(5 * time.Second) // worker writes a heartbeat every 2 s
	var r1, r2 struct {
		Version    string `json:"version"`
		Hits       int    `json:"hits"`
		Heartbeats int    `json:"heartbeats"`
	}
	st, body := get(appPort1, "/")
	if st != 200 || json.Unmarshal([]byte(body), &r1) != nil || r1.Version != "v1" || r1.Hits < 1 || r1.Heartbeats < 1 {
		t.Fatalf("stack v1: %d %s", st, body)
	}
	_, body = get(appPort1, "/")
	json.Unmarshal([]byte(body), &r2)
	if r2.Hits != r1.Hits+1 {
		t.Fatalf("hits not persisted: %d -> %d", r1.Hits, r2.Hits)
	}
	t.Logf("PASS stack v1: db+worker+app running; rows written (hits=%d heartbeats=%d)", r2.Hits, r2.Heartbeats)
	before := ids()

	// 4. re-apply with only the app changed: db/worker unchanged (same container IDs), rows persist
	out2, err := cm.ComposeApply(ctx, plan("0d6a1b6f", app2.Image, strings.Repeat("4", 64), appPort2))
	if err != nil {
		t.Fatalf("compose apply v2: %v", err)
	}
	b2, _ := json.Marshal(out2)
	t.Logf("compose v2 applied: %s", b2)
	acts := []string{}
	for _, s := range out2.Services {
		acts = append(acts, s.Service+"="+s.Action)
	}
	if strings.Join(acts, ",") != "db=unchanged,worker=unchanged,app=replaced" || out2.Services[2].PreviousName != "ppanel-"+app+"-app-0d6a1b6e" {
		t.Fatalf("actions %v", acts)
	}
	after := ids()
	for _, n := range []string{"ppanel-" + app + "-db-0d6a1b6e", "ppanel-" + app + "-worker-0d6a1b6e"} {
		if before[n] == "" || before[n] != after[n] {
			t.Fatalf("%s container changed: %s -> %s", n, before[n], after[n])
		}
	}
	var r3 struct {
		Version    string `json:"version"`
		Hits       int    `json:"hits"`
		Heartbeats int    `json:"heartbeats"`
	}
	st, body = get(appPort2, "/")
	if st != 200 || json.Unmarshal([]byte(body), &r3) != nil || r3.Version != "v2" || r3.Hits != r2.Hits+1 || r3.Heartbeats <= r2.Heartbeats {
		t.Fatalf("stack v2: %d %s (before %+v)", st, body, r2)
	}
	if st, _ := get(appPort1, "/healthz"); st != 200 {
		t.Fatal("old route container must keep running until the Center switches the route")
	}
	t.Logf("PASS re-apply app-only: db/worker same container IDs, app replaced side-by-side, data persisted (hits %d -> %d, heartbeats %d -> %d)",
		r2.Hits, r3.Hits, r2.Heartbeats, r3.Heartbeats)
	// the Center would now switch the route and stop the previous app container
	if _, err := cm.Stop(ctx, containerops.RefParams{App: app, Name: out2.Services[2].PreviousName}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logBuf.String(), dbPassword) {
		t.Fatal("secret value in agent logs")
	}

	// 5. optional: built-in nestjs template (needs the npm registry from the build containers)
	if os.Getenv("PPANEL_LAB_BUILD_TEMPLATE") != "0" {
		t.Run("template-nestjs", func(t *testing.T) {
			nb := build(bp("0d6a1b6e-0000-4000-8000-0000000000e1", "nestjs-min", "NESTJS_MIN", "PPANEL_LAB_GIT_SHA_NESTJS_MIN",
				map[string]any{"dockerfile": nil, "template": "nestjs"}))
			if nb.Template != "nestjs" {
				t.Fatalf("%+v", nb)
			}
			port := 24300 + int(time.Now().Unix()%200)
			raw, _ := json.Marshal(map[string]any{"deploymentId": "0d6a1b6e-0000-4000-8000-0000000000e2", "app": "labnest", "name": "ppanel-labnest-0d6a1b6e",
				"image": nb.Image, "containerPort": 3000, "hostPort": port, "resources": map[string]any{"memoryMb": 256, "cpus": 1, "pids": 128},
				"healthcheck": map[string]any{"path": "/healthz", "intervalSec": 1, "timeoutSec": 2, "startPeriodSec": 60}})
			p, err := containerops.DecodeRun(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cm.RunCandidate(ctx, p); err != nil {
				t.Fatalf("run nestjs: %v", err)
			}
			defer func() {
				cm.Stop(context.Background(), containerops.RefParams{App: "labnest", Name: p.Name})
				cm.Remove(context.Background(), containerops.RefParams{App: "labnest", Name: p.Name})
			}()
			if st, body := get(port, "/healthz"); st != 200 || !strings.Contains(body, "nestjs-min") {
				t.Fatalf("nestjs: %d %s", st, body)
			}
			t.Logf("PASS nestjs template build %s -> GET /healthz 200 (non-root node, dist/main on :3000)", nb.Image)
		})
	}
}
