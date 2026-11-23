package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadYAMLAndJSON(t *testing.T) {
	d := t.TempDir()
	y := filepath.Join(d, "c.yaml")
	os.WriteFile(y, []byte("stateDir: /tmp/x\nownedUnits: [app.service]\nheartbeatIntervalSec: 10\n"), 0o600)
	c, err := Load(y)
	if err != nil || c.StateDir != "/tmp/x" || c.HeartbeatIntervalSec != 10 || c.PollWaitSec != 25 {
		t.Fatalf("%v %+v", err, c)
	}
	j := filepath.Join(d, "c.json")
	os.WriteFile(j, []byte(`{"stateDir":"/tmp/y","logLevel":"debug"}`), 0o600)
	if c, err := Load(j); err != nil || c.LogLevel != "debug" {
		t.Fatalf("%v %+v", err, c)
	}
	if c, err := Load(filepath.Join(d, "missing.yaml")); err != nil || c.StateDir != DefaultStateDir {
		t.Fatalf("missing file should yield defaults: %v", err)
	}
}

func TestRejectsInvalid(t *testing.T) {
	d := t.TempDir()
	cases := map[string]string{
		"unknown":  "stateDirr: /x\n",
		"relative": "stateDir: rel/x\n",
		"unit":     "ownedUnits: ['x; rm -rf /']\n",
		"hb":       "heartbeatIntervalSec: 1\n",
		"poll":     "pollWaitSec: 60\n",
		"level":    "logLevel: loud\n",
		"bin":      "nginxBinary: nginx\n",
	}
	for name, body := range cases {
		p := filepath.Join(d, name+".yaml")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestOwnedUnitsFile(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "owned")
	os.WriteFile(f, []byte("# owned\nweb.service\n\napi@1.service\n"), 0o600)
	c := Default()
	c.OwnedUnits = []string{"a.service"}
	c.OwnedUnitsFile = f
	s, err := c.OwnedUnitSet()
	if err != nil || len(s) != 3 || !s["api@1.service"] {
		t.Fatalf("%v %v", err, s)
	}
	os.WriteFile(f, []byte("--help\n"), 0o600)
	if _, err := c.OwnedUnitSet(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatal("invalid entry must fail closed")
	}
}

func TestNginxSectionGate(t *testing.T) {
	t.Setenv(TestNginxRootEnv, "")
	c := Default()
	if err := c.Validate(); err != nil || c.Nginx.Root != NginxRoot {
		t.Fatalf("default nginx root: %v %q", err, c.Nginx.Root)
	}
	for name, n := range map[string]NginxConfig{
		"root":        {Root: "/tmp/nginx"},
		"prefix":      {Prefix: "/tmp"},
		"conf":        {ConfFile: "/tmp/nginx.conf"},
		"allowed-out": {AllowedRoots: []string{"/etc"}},
		"allowed-dot": {AllowedRoots: []string{"/etc/nginx/../x"}},
	} {
		c := Default()
		c.Nginx = n
		if err := c.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	c = Default()
	c.Nginx = NginxConfig{AllowedRoots: []string{"/etc/nginx/ppanel-managed"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(TestNginxRootEnv, "1")
	c = Default()
	c.Nginx = NginxConfig{Root: "/tmp/nginx", Prefix: "/tmp", ConfFile: "/tmp/nginx.conf"}
	if err := c.Validate(); err != nil {
		t.Fatalf("test overrides rejected with env: %v", err)
	}
	if err := Parse([]byte("nginx:\n  root: /etc/nginx\n  bogus: 1\n"), Default()); err == nil {
		t.Fatal("unknown nginx key accepted")
	}
}

func TestBuildSection(t *testing.T) {
	d := t.TempDir()
	y := filepath.Join(d, "c.yaml")
	os.WriteFile(y, []byte("stateDir: /var/lib/x\n"), 0o600)
	c, err := Load(y)
	if err != nil || c.Build.Enabled || c.BuildWorkDir() != "/var/lib/x/builds" {
		t.Fatalf("build must default to disabled: %v %+v", err, c.Build)
	}
	os.WriteFile(y, []byte("stateDir: /var/lib/x\nbuild:\n  enabled: true\n  gitHostsAllowlist: [GitHub.com, 'lab-git', 'git.example.com:8443']\n  workDir: /srv/builds\n"), 0o600)
	c, err = Load(y)
	if err != nil || !c.Build.Enabled || c.BuildWorkDir() != "/srv/builds" || strings.Join(c.Build.GitHostsAllowlist, ",") != "github.com,lab-git,git.example.com:8443" {
		t.Fatalf("%v %+v", err, c.Build)
	}
	for name, body := range map[string]string{
		"url not host":  "build:\n  gitHostsAllowlist: ['https://github.com']\n",
		"path in host":  "build:\n  gitHostsAllowlist: ['github.com/acme']\n",
		"relative dir":  "build:\n  workDir: builds\n",
		"root dir":      "build:\n  workDir: /\n",
		"unknown field": "build:\n  enable: true\n",
	} {
		os.WriteFile(y, []byte(body), 0o600)
		if _, err := Load(y); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
