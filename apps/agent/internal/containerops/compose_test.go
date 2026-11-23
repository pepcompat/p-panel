package containerops

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/docker/dockertest"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// stackPlan builds a db + worker + app plan. hex is the 8-hex deployment short
// id used in container names; spec overrides per-service spec hashes; kinds
// override the fake image kind (web|broken|crash).
type stackOpts struct {
	hex      map[string]string
	spec     map[string]string
	kind     map[string]string
	hostPort int
	dbHealth map[string]any
}

func stackPlan(t *testing.T, o stackOpts) ComposeApplyParams {
	t.Helper()
	get := func(m map[string]string, k, def string) string {
		if v, ok := m[k]; ok {
			return v
		}
		return def
	}
	dbHealth := o.dbHealth
	if dbHealth == nil {
		dbHealth = map[string]any{"type": "tcp", "port": 5432, "startPeriodSec": 3}
	}
	svc := func(name string, extra map[string]any) map[string]any {
		s := map[string]any{"service": name, "name": "ppanel-stack-" + name + "-" + get(o.hex, name, "1a1a1a1a"),
			"image":    img(get(o.kind, name, "web")),
			"specHash": strings.Repeat(get(o.spec, name, "a"), 64), "resources": map[string]any{"memoryMb": 64, "cpus": 0.5, "pids": 64}}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	raw := map[string]any{"deploymentId": dep, "app": "stack", "routeService": "app", "services": []any{
		svc("db", map[string]any{"env": map[string]string{"POSTGRES_USER": "app"}, "secretEnv": map[string]string{"POSTGRES_PASSWORD": "APP_SECRET"},
			"volumes": []any{map[string]any{"name": "pgdata", "mountPath": "/var/lib/postgresql/data"}}, "health": dbHealth}),
		svc("worker", map[string]any{"dependsOn": []string{"db"}, "secretEnv": map[string]string{"DB_PASSWORD": "APP_SECRET"},
			"command": []string{"php", "/app/worker.php"}, "health": map[string]any{"type": "running", "startPeriodSec": 1}}),
		svc("app", map[string]any{"dependsOn": []string{"db"}, "secretEnv": map[string]string{"DB_PASSWORD": "APP_SECRET"},
			"hostPort": o.hostPort, "containerPort": 8080,
			"health": map[string]any{"type": "http", "port": 8080, "path": "/healthz", "intervalSec": 1, "timeoutSec": 1, "startPeriodSec": 3}}),
	}}
	b, _ := json.Marshal(raw)
	p, err := DecodeComposeApply(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// apply runs compose.apply as a new job (each job has its own one-time secrets fetch).
func apply(h *harness, p ComposeApplyParams) (*ComposeOutput, error) {
	h.fetches.Store(0)
	return h.m.ComposeApply(context.Background(), p)
}

func composeHarness(t *testing.T) *harness {
	h := newHarness(t)
	h.m.o.ProbeAddr = h.fe.ProbeAddr
	return h
}

func actions(out *ComposeOutput) string {
	var s []string
	for _, r := range out.Services {
		s = append(s, r.Service+"="+r.Action)
	}
	return strings.Join(s, ",")
}

func createdNames(fe *dockertest.Engine) []string {
	var out []string
	for _, c := range createCalls(fe) {
		out = append(out, strings.TrimPrefix(c.Query, "name="))
	}
	return out
}

func TestComposeDecodeStrict(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"deploymentId": dep, "app": "stack", "services": []any{
			map[string]any{"service": "db", "name": "ppanel-stack-db-1a2b3c4d", "image": img("web"), "specHash": strings.Repeat("a", 64)},
		}}
	}
	b, _ := json.Marshal(base())
	p, err := DecodeComposeApply(b)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Services[0]
	if s.Health.Type != "running" || s.Health.StartPeriodSec != 10 || s.Resources.MemoryMb != 512 || s.HostPort != 0 || p.RegistryAuth {
		t.Fatalf("defaults %+v", s)
	}
	mut := map[string]func(m map[string]any){
		"unknown field":      func(m map[string]any) { m["x"] = 1 },
		"null":               func(m map[string]any) { m["routeService"] = nil },
		"name other app":     func(m map[string]any) { svc0(m)["name"] = "ppanel-other-db-1a2b3c4d" },
		"name other service": func(m map[string]any) { svc0(m)["name"] = "ppanel-stack-web-1a2b3c4d" },
		"plain name":         func(m map[string]any) { svc0(m)["name"] = "ppanel-stack-1a2b3c4d" },
		"tag image":          func(m map[string]any) { svc0(m)["image"] = "postgres:16" },
		"bad spec":           func(m map[string]any) { svc0(m)["specHash"] = "abc" },
		"hostPort non-route": func(m map[string]any) { svc0(m)["hostPort"] = 20001 },
		"route missing":      func(m map[string]any) { m["routeService"] = "web" },
		"route without port": func(m map[string]any) { m["routeService"] = "db" },
		"depends on later":   func(m map[string]any) { svc0(m)["dependsOn"] = []string{"app"} },
		"depends on self":    func(m map[string]any) { svc0(m)["dependsOn"] = []string{"db"} },
		"tcp with path":      func(m map[string]any) { svc0(m)["health"] = map[string]any{"type": "tcp", "port": 5432, "path": "/"} },
		"http without port":  func(m map[string]any) { svc0(m)["health"] = map[string]any{"type": "http"} },
		"running with port":  func(m map[string]any) { svc0(m)["health"] = map[string]any{"type": "running", "port": 1} },
		"unknown health":     func(m map[string]any) { svc0(m)["health"] = map[string]any{"type": "exec"} },
		"secret and env": func(m map[string]any) {
			svc0(m)["env"] = map[string]string{"A": "1"}
			svc0(m)["secretEnv"] = map[string]string{"A": "K"}
		},
		"volume host path": func(m map[string]any) { svc0(m)["volumes"] = []any{map[string]any{"name": "/etc", "mountPath": "/x"}} },
		"volume unknown field": func(m map[string]any) {
			svc0(m)["volumes"] = []any{map[string]any{"name": "d", "mountPath": "/x", "bind": "/etc"}}
		},
		"empty services": func(m map[string]any) { m["services"] = []any{} },
	}
	for name, f := range mut {
		m := base()
		f(m)
		b, _ := json.Marshal(m)
		if _, err := DecodeComposeApply(b); err == nil {
			t.Errorf("%s: accepted", name)
		} else if errCode(t, err) != jobs.RejectedInvalidParams {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeComposeStop(json.RawMessage(`{"app":"stack","x":1}`)); err == nil {
		t.Fatal("compose.stop unknown field accepted")
	}
}

func svc0(m map[string]any) map[string]any { return m["services"].([]any)[0].(map[string]any) }

func TestComposeApplyFreshThenUnchanged(t *testing.T) {
	h := composeHarness(t)
	port := dockertest.FreePort(t)
	p := stackPlan(t, stackOpts{hostPort: port})
	out, err := apply(h, p)
	if err != nil {
		t.Fatal(err)
	}
	if actions(out) != "db=created,worker=created,app=created" {
		t.Fatalf("actions %s", actions(out))
	}
	if got := strings.Join(createdNames(h.fe), ","); got != "ppanel-stack-db-1a1a1a1a,ppanel-stack-worker-1a1a1a1a,ppanel-stack-app-1a1a1a1a" {
		t.Fatalf("dependsOn order: %s", got)
	}
	if h.fetches.Load() != 1 {
		t.Fatalf("secrets fetched %d times (must be once per job)", h.fetches.Load())
	}
	for _, c := range createCalls(h.fe) {
		var b map[string]any
		json.Unmarshal(c.Body, &b)
		hc := b["HostConfig"].(map[string]any)
		labels := b["Labels"].(map[string]any)
		name := strings.TrimPrefix(c.Query, "name=")
		svc := labels[LabelService].(string)
		if hc["Privileged"] != false || hc["NetworkMode"] != "ppanel-stack" || hc["ReadonlyRootfs"] != false ||
			strings.Join(toStrings(hc["CapDrop"]), ",") != "ALL" || strings.Join(toStrings(hc["SecurityOpt"]), ",") != "no-new-privileges:true" {
			t.Errorf("%s: not hardened: %v", name, hc)
		}
		if labels[LabelManaged] != "true" || labels[LabelApp] != "stack" || labels[LabelSpec] != strings.Repeat("a", 64) || name != "ppanel-stack-"+svc+"-1a1a1a1a" {
			t.Errorf("%s labels %v", name, labels)
		}
		al := b["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["ppanel-stack"].(map[string]any)["Aliases"]
		if strings.Join(toStrings(al), ",") != svc {
			t.Errorf("%s aliases %v", name, al)
		}
		_, hasPB := hc["PortBindings"]
		if (svc == "app") != hasPB {
			t.Errorf("%s: only the route service gets a host port (%v)", name, hc["PortBindings"])
		}
		if svc == "app" {
			pb := hc["PortBindings"].(map[string]any)["8080/tcp"].([]any)[0].(map[string]any)
			if pb["HostIp"] != "127.0.0.1" {
				t.Errorf("route binding %v", pb)
			}
		}
		if svc == "db" {
			mt := hc["Mounts"].([]any)[0].(map[string]any)
			if mt["Type"] != "volume" || mt["Source"] != "ppanel-stack-pgdata" {
				t.Errorf("db mount %v", mt)
			}
		}
		if !strings.Contains(string(c.Body), secret) {
			t.Errorf("%s: secret env not delivered to the engine", name)
		}
	}
	ob, _ := json.Marshal(out)
	if strings.Contains(string(ob), secret) || strings.Contains(h.logBuf.String(), secret) {
		t.Fatal("secret leaked into output/logs")
	}
	if h.fe.Networks["ppanel-stack"]["ppanel.managed"] != "true" || h.fe.Volumes["ppanel-stack-pgdata"]["ppanel.app"] != "stack" {
		t.Fatal("network/volume not created with labels")
	}
	if *out.Services[2].HostPort != port || out.Services[2].Health.Status != "healthy" {
		t.Fatalf("route result %+v", out.Services[2])
	}

	// re-apply the same plan: nothing changes
	nCreate := len(createCalls(h.fe))
	out2, err := apply(h, p)
	if err != nil {
		t.Fatal(err)
	}
	if actions(out2) != "db=unchanged,worker=unchanged,app=unchanged" || len(createCalls(h.fe)) != nCreate {
		t.Fatalf("re-apply: %s creates=%d", actions(out2), len(createCalls(h.fe))-nCreate)
	}
	for _, c := range h.fe.MutatingCalls() {
		if strings.HasSuffix(c.Path, "/stop") {
			t.Fatal("unchanged services must not be stopped")
		}
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestComposeReplaceNonRouteStopThenStart(t *testing.T) {
	h := composeHarness(t)
	port := dockertest.FreePort(t)
	if _, err := apply(h, stackPlan(t, stackOpts{hostPort: port})); err != nil {
		t.Fatal(err)
	}
	dbID, appID := h.fe.Find("ppanel-stack-db-1a1a1a1a").ID, h.fe.Find("ppanel-stack-app-1a1a1a1a").ID
	oldWorker := h.fe.Find("ppanel-stack-worker-1a1a1a1a")
	before := len(h.fe.CallsSnapshot())
	p2 := stackPlan(t, stackOpts{hostPort: port, hex: map[string]string{"worker": "2b2b2b2b"}, spec: map[string]string{"worker": "b"}})
	out, err := apply(h, p2)
	if err != nil {
		t.Fatal(err)
	}
	if actions(out) != "db=unchanged,worker=replaced,app=unchanged" || out.Services[1].PreviousName != "ppanel-stack-worker-1a1a1a1a" ||
		out.Services[0].Name != "ppanel-stack-db-1a1a1a1a" {
		t.Fatalf("%s %+v", actions(out), out.Services)
	}
	// old worker stopped BEFORE the new one was created; db/app untouched (same containers)
	stopAt, createAt := -1, -1
	for i, c := range h.fe.CallsSnapshot()[before:] {
		if c.Path == "/containers/"+oldWorker.ID+"/stop" && stopAt < 0 {
			stopAt = i
		}
		if c.Path == "/containers/create" && strings.Contains(c.Query, "worker-2b2b2b2b") {
			createAt = i
		}
		if strings.Contains(c.Path, dbID) && c.Method != http.MethodGet || strings.Contains(c.Path, appID) && c.Method != http.MethodGet {
			t.Fatalf("unchanged service touched: %s %s", c.Method, c.Path)
		}
	}
	if stopAt < 0 || createAt < 0 || stopAt > createAt {
		t.Fatalf("stop@%d create@%d", stopAt, createAt)
	}
	if oldWorker.Status != "exited" || h.fe.Find("ppanel-stack-worker-2b2b2b2b").Status != "running" {
		t.Fatal("states after replace")
	}
	assertVolumesNeverRemoved(t, h.fe)
}

func TestComposeNonRouteFailureRestoresOld(t *testing.T) {
	h := composeHarness(t)
	port := dockertest.FreePort(t)
	if _, err := apply(h, stackPlan(t, stackOpts{hostPort: port})); err != nil {
		t.Fatal(err)
	}
	p2 := stackPlan(t, stackOpts{hostPort: port, hex: map[string]string{"worker": "3c3c3c3c"}, spec: map[string]string{"worker": "c"},
		kind: map[string]string{"worker": "crash"}})
	_, err := apply(h, p2)
	if errCode(t, err) != CodeComposeServiceUnhealthy {
		t.Fatal(err)
	}
	d := errDetails(t, err)
	if d["service"] != "worker" || d["restored"] != true || d["removed"] != true || d["previousName"] != "ppanel-stack-worker-1a1a1a1a" {
		t.Fatalf("details %v", d)
	}
	if h.fe.Find("ppanel-stack-worker-3c3c3c3c") != nil {
		t.Fatal("failed new container not removed")
	}
	if h.fe.Find("ppanel-stack-worker-1a1a1a1a").Status != "running" {
		t.Fatal("old worker not restarted")
	}
	if h.fe.Find("ppanel-stack-app-1a1a1a1a").Status != "running" {
		t.Fatal("app must be untouched")
	}
	assertVolumesNeverRemoved(t, h.fe)
}

func TestComposeRouteSideBySide(t *testing.T) {
	h := composeHarness(t)
	port := dockertest.FreePort(t)
	if _, err := apply(h, stackPlan(t, stackOpts{hostPort: port})); err != nil {
		t.Fatal(err)
	}
	port2 := dockertest.FreePort(t)
	out, err := apply(h, stackPlan(t, stackOpts{hostPort: port2, hex: map[string]string{"app": "4d4d4d4d"}, spec: map[string]string{"app": "d"}}))
	if err != nil {
		t.Fatal(err)
	}
	r := out.Services[2]
	if r.Action != "replaced" || r.PreviousName != "ppanel-stack-app-1a1a1a1a" || *r.HostPort != port2 {
		t.Fatalf("%+v", r)
	}
	old, nw := h.fe.Find("ppanel-stack-app-1a1a1a1a"), h.fe.Find("ppanel-stack-app-4d4d4d4d")
	if old.Status != "running" || nw.Status != "running" {
		t.Fatal("route: old must keep running next to the new one (the Center switches the route, then stops the old)")
	}
	for _, c := range h.fe.MutatingCalls() {
		if c.Path == "/containers/"+old.ID+"/stop" {
			t.Fatal("old route container stopped by compose.apply")
		}
	}
	// unhealthy new route container: removed, old untouched, processing stops
	port3 := dockertest.FreePort(t)
	_, err = apply(h, stackPlan(t, stackOpts{hostPort: port3, hex: map[string]string{"app": "5e5e5e5e"},
		spec: map[string]string{"app": "e"}, kind: map[string]string{"app": "broken"}}))
	if errCode(t, err) != CodeComposeServiceUnhealthy || errDetails(t, err)["service"] != "app" {
		t.Fatal(err)
	}
	if h.fe.Find("ppanel-stack-app-5e5e5e5e") != nil || nw.Status != "running" || old.Status != "running" {
		t.Fatal("route failure must remove the new container and leave the current ones untouched")
	}
	// port in use → PORT_IN_USE before anything is created
	_, err = apply(h, stackPlan(t, stackOpts{hostPort: port2, hex: map[string]string{"app": "6f6f6f6f"}, spec: map[string]string{"app": "f"}}))
	if errCode(t, err) != CodePortInUse {
		t.Fatal(err)
	}
}

func TestComposeDependsOnMustBeHealthy(t *testing.T) {
	h := composeHarness(t)
	port := dockertest.FreePort(t)
	if _, err := apply(h, stackPlan(t, stackOpts{hostPort: port})); err != nil {
		t.Fatal(err)
	}
	dbID := h.fe.Find("ppanel-stack-db-1a1a1a1a").ID
	h.m.o.ProbeAddr = func(id, ip string, port int) string {
		if id == dbID {
			return "127.0.0.1:1" // db stops answering
		}
		return h.fe.ProbeAddr(id, ip, port)
	}
	p2 := stackPlan(t, stackOpts{hostPort: port, hex: map[string]string{"worker": "7a7a7a7a"}, spec: map[string]string{"worker": "7"},
		dbHealth: map[string]any{"type": "tcp", "port": 5432, "startPeriodSec": 1}})
	_, err := apply(h, p2)
	if errCode(t, err) != CodeComposeServiceUnhealthy || errDetails(t, err)["dependency"] != "db" || errDetails(t, err)["service"] != "worker" {
		t.Fatalf("%v %v", err, errDetails(t, err))
	}
	if h.fe.Find("ppanel-stack-worker-1a1a1a1a").Status != "running" || h.fe.Find("ppanel-stack-worker-7a7a7a7a") != nil {
		t.Fatal("old worker must not be stopped while its dependency is unhealthy")
	}
}

func TestComposeOwnershipAndStop(t *testing.T) {
	h := composeHarness(t)
	port := dockertest.FreePort(t)
	// look-alikes that pPanel must never keep, stop or remove
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-stack-db-aaaaaaaa", Image: "postgres", Labels: map[string]string{"ppanel.service": "db"}})
	h.fe.AddContainer(&dockertest.Container{Name: "ppanel-stack-db-bbbbbbbb", Image: "postgres",
		Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "other", "ppanel.service": "db", "ppanel.spec": strings.Repeat("a", 64)}})
	h.fe.AddContainer(&dockertest.Container{Name: "my-db", Labels: map[string]string{"ppanel.managed": "true", "ppanel.app": "stack",
		"ppanel.service": "db", "ppanel.spec": strings.Repeat("a", 64)}})
	out, err := apply(h, stackPlan(t, stackOpts{hostPort: port}))
	if err != nil {
		t.Fatal(err)
	}
	if out.Services[0].Action != "created" || out.Services[0].Name != "ppanel-stack-db-1a1a1a1a" {
		t.Fatalf("look-alike treated as owned: %+v", out.Services[0])
	}
	st, err := h.m.ComposeStop(context.Background(), ComposeStopParams{App: "stack"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(st.Stopped, ",") != "ppanel-stack-app-1a1a1a1a,ppanel-stack-db-1a1a1a1a,ppanel-stack-worker-1a1a1a1a" {
		t.Fatalf("stopped %v", st.Stopped)
	}
	for _, n := range []string{"ppanel-stack-db-aaaaaaaa", "ppanel-stack-db-bbbbbbbb", "my-db"} {
		if h.fe.Find(n).Status != "running" {
			t.Fatalf("%s touched", n)
		}
	}
	// start = re-apply the current plan: stopped same-name containers are recreated, volume kept
	out, err = apply(h, stackPlan(t, stackOpts{hostPort: port}))
	if err != nil {
		t.Fatal(err)
	}
	if actions(out) != "db=created,worker=created,app=created" || h.fe.Find("ppanel-stack-db-1a1a1a1a").Status != "running" {
		t.Fatalf("restart: %s", actions(out))
	}
	if _, ok := h.fe.Volumes["ppanel-stack-pgdata"]; !ok {
		t.Fatal("volume gone")
	}
	assertVolumesNeverRemoved(t, h.fe)
	// container.stop accepts a compose service container (Center stops the old route container)
	if _, err := h.m.Stop(context.Background(), RefParams{App: "stack", Name: "ppanel-stack-app-1a1a1a1a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Stop(context.Background(), RefParams{App: "stack", Name: "ppanel-stack-db-bbbbbbbb"}); errCode(t, err) != CodeContainerNotManaged {
		t.Fatal(err)
	}
}

func assertVolumesNeverRemoved(t *testing.T, fe *dockertest.Engine) {
	t.Helper()
	for _, c := range fe.MutatingCalls() {
		if strings.HasPrefix(c.Path, "/volumes/") && c.Method == http.MethodDelete {
			t.Fatalf("volume removed: %s", c.Path)
		}
		if c.Method == http.MethodDelete && strings.HasPrefix(c.Path, "/containers/") && !strings.Contains(c.Query, "v=0") {
			t.Fatalf("container removed without v=0: %s?%s", c.Path, c.Query)
		}
	}
}
