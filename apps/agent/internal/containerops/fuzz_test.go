package containerops

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/docker"
)

const (
	fzDep = "0190f4c2-0000-7000-8000-0000000000d1"
	fzImg = "registry.example:5000/acme/web@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var allowedCaps = map[string]bool{"CHOWN": true, "SETUID": true, "SETGID": true, "NET_BIND_SERVICE": true, "DAC_OVERRIDE": true}

// assertHardened checks the invariants of a container create body.
func assertHardened(t *testing.T, app string, body map[string]any, wantHostPort bool) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Image        string
		Labels       map[string]string
		Tty          bool
		OpenStdin    bool
		ExposedPorts map[string]any
		HostConfig   struct {
			PortBindings    map[string][]map[string]string
			PublishAllPorts bool
			Privileged      bool
			CapDrop         []string
			CapAdd          []string
			SecurityOpt     []string
			NetworkMode     string
			IpcMode         string
			PidMode         string
			UsernsMode      string
			Binds           []string
			Devices         []any
			Mounts          []struct {
				Type, Source, Target string
			}
			Memory, PidsLimit, NanoCpus int64
		}
		NetworkingConfig *struct {
			EndpointsConfig map[string]any
		}
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	hc := c.HostConfig
	if hc.Privileged || hc.PublishAllPorts || len(hc.Binds) > 0 || len(hc.Devices) > 0 || hc.PidMode != "" || hc.UsernsMode != "" {
		t.Fatalf("dangerous HostConfig: %s", b)
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Fatalf("CapDrop: %v", hc.CapDrop)
	}
	for _, cap := range hc.CapAdd {
		if !allowedCaps[cap] {
			t.Fatalf("CapAdd %s", cap)
		}
	}
	if len(hc.SecurityOpt) != 1 || hc.SecurityOpt[0] != "no-new-privileges:true" {
		t.Fatalf("SecurityOpt %v", hc.SecurityOpt)
	}
	if hc.NetworkMode != NetworkName(app) || hc.IpcMode != "private" {
		t.Fatalf("NetworkMode %q IpcMode %q", hc.NetworkMode, hc.IpcMode)
	}
	if hc.Memory <= 0 || hc.PidsLimit <= 0 || hc.NanoCpus <= 0 {
		t.Fatalf("limits missing: %s", b)
	}
	for _, m := range hc.Mounts {
		if m.Type != "volume" || !strings.HasPrefix(m.Source, "ppanel-"+app+"-") || strings.Contains(m.Source, "/") ||
			strings.Contains(m.Source, "docker.sock") || !strings.HasPrefix(m.Target, "/") || strings.Contains(m.Target, "..") {
			t.Fatalf("mount %+v", m)
		}
	}
	for port, bs := range hc.PortBindings {
		if !wantHostPort {
			t.Fatalf("unexpected port binding %s", port)
		}
		for _, pb := range bs {
			if pb["HostIp"] != "127.0.0.1" {
				t.Fatalf("binding not loopback: %v", pb)
			}
		}
	}
	if !ImageDigestRefRe.MatchString(c.Image) || c.Labels[LabelManaged] != "true" || c.Labels[LabelApp] != app || c.Labels[LabelImage] != c.Image {
		t.Fatalf("image/labels: %s %v", c.Image, c.Labels)
	}
	if c.Tty || c.OpenStdin {
		t.Fatal("tty/stdin")
	}
	if c.NetworkingConfig != nil {
		for n := range c.NetworkingConfig.EndpointsConfig {
			if n != NetworkName(app) {
				t.Fatalf("joins foreign network %s", n)
			}
		}
	}
}

// FuzzDecodeRun: decode never panics; anything accepted yields a hardened
// create body (no privilege, loopback-only port, own network, own volumes,
// digest-pinned image) and valid env/secret keys.
func FuzzDecodeRun(f *testing.F) {
	for _, s := range []string{
		`{"deploymentId":"` + fzDep + `","app":"shop","name":"ppanel-shop-1a2b3c4d","image":"` + fzImg + `","containerPort":8080,"hostPort":20001}`,
		`{"deploymentId":"` + fzDep + `","app":"shop","name":"ppanel-shop-1a2b3c4d","image":"` + fzImg + `","containerPort":8080,"hostPort":20001,"env":{"A":"1"},"secretEnvKeys":["DB_PASSWORD"],"volumes":[{"name":"data","mountPath":"/data"}],"command":["--x"],"user":"1000:1000","readOnlyRootfs":true,"resources":{"memoryMb":64,"cpus":0.5,"pids":64},"healthcheck":{"path":"/h","expectStatus":[200]}}`,
		`{"deploymentId":"` + fzDep + `","app":"shop","name":"ppanel-shop-1a2b3c4d","image":"nginx:latest","containerPort":80,"hostPort":80}`,
		`{"deploymentId":"` + fzDep + `","app":"shop","name":"ppanel-other-1a2b3c4d","image":"` + fzImg + `","containerPort":8080,"hostPort":20001,"privileged":true}`,
		`{"deploymentId":"` + fzDep + `","app":"shop","name":"ppanel-shop-1a2b3c4d","image":"` + fzImg + `","containerPort":8080,"hostPort":20001,"volumes":[{"name":"../../var/run/docker.sock","mountPath":"/var/run/docker.sock"}]}`,
		`{"deploymentId":"` + fzDep + `","app":"shop","name":"ppanel-shop-1a2b3c4d","image":"` + fzImg + `","containerPort":8080,"hostPort":20001,"env":{"ld_preload":"x","A":null}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeRun(raw)
		if err != nil {
			return
		}
		if !PlainNameMatchesApp(p.App, p.Name) || !ImageDigestRefRe.MatchString(p.Image) || p.HostPort < PortMin || p.HostPort > PortMax {
			t.Fatalf("accepted %+v", p)
		}
		for k, v := range p.Env {
			if !EnvKeyRe.MatchString(k) || strings.IndexByte(v, 0) >= 0 || len(v) > 4096 {
				t.Fatalf("env %q accepted", k)
			}
		}
		for _, k := range p.SecretEnvKeys {
			if !EnvKeyRe.MatchString(k) {
				t.Fatalf("secret key %q accepted", k)
			}
			if _, dup := p.Env[k]; dup {
				t.Fatalf("%s both env and secret", k)
			}
		}
		for _, v := range p.Volumes {
			if !volumeNameRe.MatchString(v.Name) {
				t.Fatalf("volume %q", v.Name)
			}
		}
		if p.User != "" && (p.User == "0" || strings.HasPrefix(p.User, "root")) {
			// allowed by contract (image decides); recorded, not a failure
			_ = p.User
		}
		assertHardened(t, p.App, CreateBody(p, map[string]string{"SECRET": "x"}), true)
	})
}

// FuzzDecodeComposeApply: same invariants for every compose service; only the
// route service may get a (loopback) host port; names are per-app/per-service.
func FuzzDecodeComposeApply(f *testing.F) {
	sh := strings.Repeat("a", 64)
	for _, s := range []string{
		`{"deploymentId":"` + fzDep + `","app":"stack","routeService":"app","services":[{"service":"db","name":"ppanel-stack-db-0a1b2c3d","image":"` + fzImg + `","specHash":"` + sh + `","volumes":[{"name":"pg","mountPath":"/var/lib/postgresql/data"}],"health":{"type":"tcp","port":5432}},{"service":"app","name":"ppanel-stack-app-0a1b2c3d","image":"` + fzImg + `","specHash":"` + sh + `","dependsOn":["db"],"hostPort":20010,"containerPort":3000,"health":{"type":"http","port":3000,"path":"/"},"secretEnv":{"DB_URL":"DB_URL"}}]}`,
		`{"deploymentId":"` + fzDep + `","app":"stack","services":[{"service":"db","name":"ppanel-other-db-0a1b2c3d","image":"` + fzImg + `","specHash":"` + sh + `","hostPort":20010}]}`,
		`{"deploymentId":"` + fzDep + `","app":"stack","services":[{"service":"a","name":"ppanel-stack-a-0a1b2c3d","image":"` + fzImg + `","specHash":"` + sh + `","dependsOn":["b"]},{"service":"b","name":"ppanel-stack-b-0a1b2c3d","image":"` + fzImg + `","specHash":"` + sh + `"}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeComposeApply(raw)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, s := range p.Services {
			if !NameMatchesService(p.App, s.Service, s.Name) || !NameMatchesApp(p.App, s.Name) {
				t.Fatalf("name %s not owned by %s/%s", s.Name, p.App, s.Service)
			}
			for _, d := range s.DependsOn {
				if !seen[d] {
					t.Fatalf("dependsOn %s not earlier", d)
				}
			}
			seen[s.Service] = true
			if s.HostPort != 0 && s.Service != p.RouteService {
				t.Fatalf("non-route service %s has a host port", s.Service)
			}
			for k, v := range s.SecretEnv {
				if !EnvKeyRe.MatchString(k) || !EnvKeyRe.MatchString(v) {
					t.Fatalf("secretEnv %q=%q", k, v)
				}
			}
			body := ComposeCreateBody(p, s, map[string]string{})
			assertHardened(t, p.App, body, s.HostPort != 0)
			if body["Labels"].(map[string]string)[LabelService] != s.Service {
				t.Fatal("service label")
			}
		}
	})
}

// FuzzOwnership: the ownership rule never accepts a container of another app
// (label spoofing across apps, name collisions such as app "web" service "api"
// vs app "web-api"), a non-managed container, or a name/label mismatch.
func FuzzOwnership(f *testing.F) {
	f.Add("web", "ppanel-web-api-0a1b2c3d", "web-api", "", "true")
	f.Add("web-api", "ppanel-web-api-0a1b2c3d", "web", "api", "true")
	f.Add("web", "ppanel-web-0a1b2c3d", "web", "", "true")
	f.Add("web", "ppanel-web-0a1b2c3d", "web", "", "TRUE")
	f.Add("web", "ppanel-web-db-0a1b2c3d", "web", "db", "true")
	f.Add("web", "ppanel-web-db-0a1b2c3d", "web", "cache", "true")
	f.Add("web", "ppanel-bk-0123456789abcdef", "web", "", "true")
	f.Fuzz(func(t *testing.T, app, name, labelApp, labelService, managed string) {
		ci := &docker.ContainerInfo{Name: "/" + name}
		ci.Config.Labels = map[string]string{LabelManaged: managed, LabelApp: labelApp}
		if labelService != "" {
			ci.Config.Labels[LabelService] = labelService
		}
		if !IsOwned(ci, app, name) {
			return
		}
		if managed != "true" || labelApp != app || !AppSlugRe.MatchString(app) || !ManagedNameRe.MatchString(name) {
			t.Fatalf("owned with labels %v app=%q name=%q", ci.Config.Labels, app, name)
		}
		if !strings.HasPrefix(name, "ppanel-"+app+"-") {
			t.Fatalf("name %q not prefixed by app %q", name, app)
		}
		if labelService != "" && !NameMatchesService(app, labelService, name) {
			t.Fatalf("service label %q does not match name %q", labelService, name)
		}
		if labelService == "" && !PlainNameMatchesApp(app, name) {
			t.Fatalf("plain container name %q", name)
		}
		// the same container is never also owned by a different app
		for _, other := range []string{app + "-x", strings.TrimSuffix(app, "-x"), "x" + app} {
			if other != app && IsOwned(ci, other, name) {
				t.Fatalf("owned by two apps: %q and %q", app, other)
			}
		}
	})
}

// FuzzDecodeSmall: stop/remove/start/list/logs/compose.stop decoders.
func FuzzDecodeSmall(f *testing.F) {
	for i, s := range []string{`{"app":"shop","name":"ppanel-shop-1a2b3c4d"}`, `{"app":"shop","name":"ppanel-shop-1a2b3c4d","hostPort":20001}`,
		`{"app":"shop"}`, `{"app":"shop","name":"ppanel-shop-1a2b3c4d","tailLines":100,"sinceSec":5}`, `{"app":"../x"}`, `{}`} {
		f.Add(uint8(i), []byte(s))
	}
	f.Fuzz(func(t *testing.T, which uint8, raw []byte) {
		switch which % 6 {
		case 0:
			if p, err := DecodeRef(raw); err == nil && (!AppSlugRe.MatchString(p.App) || !ManagedNameRe.MatchString(p.Name)) {
				t.Fatalf("%+v", p)
			}
		case 1:
			if p, err := DecodeStart(raw); err == nil && (!AppSlugRe.MatchString(p.App) || !ManagedNameRe.MatchString(p.Name) ||
				(p.HostPort != 0 && (p.HostPort < PortMin || p.HostPort > PortMax))) {
				t.Fatalf("%+v", p)
			}
		case 2:
			if p, err := DecodeList(raw); err == nil && p.App != "" && !AppSlugRe.MatchString(p.App) {
				t.Fatalf("%+v", p)
			}
		case 3:
			if p, err := DecodeLogs(raw); err == nil && (!AppSlugRe.MatchString(p.App) || !ManagedNameRe.MatchString(p.Name) || p.TailLines < 1 || p.TailLines > 1000 || p.SinceSec < 0) {
				t.Fatalf("%+v", p)
			}
		case 4:
			if p, err := DecodeComposeStop(raw); err == nil && !AppSlugRe.MatchString(p.App) {
				t.Fatalf("%+v", p)
			}
		case 5:
			if p, err := DecodeRun(raw); err == nil && !ImageDigestRefRe.MatchString(p.Image) {
				t.Fatalf("%+v", p)
			}
		}
	})
}
