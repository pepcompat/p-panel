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

func TestLogsDefaults(t *testing.T) {
	c := Default()
	c.StateDir = "/var/lib/ppanel-agent"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	l := c.Logs
	if !l.Enabled || l.BufferCapBytes != 64<<20 || l.ShipIntervalMs != 2000 || l.MaxBatchEntries != 1000 {
		t.Fatalf("defaults: %+v", l)
	}
	if len(l.Sources) != 4 || l.Sources[0].Path != "/var/log/nginx/access.log" || l.Sources[1].Path != "/var/log/nginx/error.log" {
		t.Fatalf("default sources: %+v", l.Sources)
	}
	if c.LogBufferDir() != "/var/lib/ppanel-agent/logs/buffer" {
		t.Fatal(c.LogBufferDir())
	}
}

func TestLogsParseAndValidate(t *testing.T) {
	c := Default()
	err := Parse([]byte(`
stateDir: /var/lib/x
logs:
  enabled: false
  bufferCapBytes: 2097152
  shipIntervalMs: 500
  maxBatchEntries: 5000
  sources:
    - source: nginx_access
      path: /srv/logs/a.log
    - source: agent
`), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Logs.Enabled || len(c.Logs.Sources) != 2 || c.Logs.BufferCapBytes != 2<<20 || !c.Logs.HasLogSource("agent") || c.Logs.HasLogSource("container") {
		t.Fatalf("%+v", c.Logs)
	}
	bad := []string{
		"logs: {bufferCapBytes: 1000}",
		"logs: {maxBatchEntries: 5001}",
		"logs: {shipIntervalMs: 10}",
		"logs: {sources: [{source: journald}]}",
		"logs: {sources: [{source: nginx_access}]}",
		"logs: {sources: [{source: nginx_access, path: relative.log}]}",
		"logs: {sources: [{source: nginx_access, path: /a/../b.log}]}",
		"logs: {sources: [{source: container, path: /x}]}",
		"logs: {sources: [{source: nginx_access, path: /a.log}, {source: nginx_error, path: /a.log}]}",
		"logs: {sources: [{source: agent}, {source: agent}]}",
	}
	for _, y := range bad {
		c := Default()
		if err := Parse([]byte(y), c); err != nil {
			continue // strict decode rejection is also fine
		}
		if err := c.Validate(); err == nil {
			t.Errorf("expected invalid: %s", y)
		}
	}
	// unknown key under logs is rejected (strict)
	if err := Parse([]byte("logs: {paths: [/etc/shadow]}"), Default()); err == nil {
		t.Error("unknown logs key accepted")
	}
}

func TestBackupConfig(t *testing.T) {
	ok := "stateDir: /var/lib/ppanel-agent\nbackup:\n  enabled: true\n  resticPath: /usr/local/bin/restic\n  helperImage: lab-registry:5000/ppanel-backup/helper@sha256:" +
		strings.Repeat("a", 64) + "\n"
	c := Default()
	if err := Parse([]byte(ok), c); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil || !c.Backup.Enabled || c.BackupWorkDir() != "/var/lib/ppanel-agent/backup" {
		t.Fatalf("%v %+v", err, c.Backup)
	}
	for _, bad := range []string{
		"backup:\n  helperImage: lab-registry:5000/helper:latest\n",
		"backup:\n  resticPath: restic\n",
		"backup:\n  workDir: /\n",
		"backup:\n  prune: true\n",
	} {
		c := Default()
		err := Parse([]byte(bad), c)
		if err == nil {
			err = c.Validate()
		}
		if err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestProviderSection(t *testing.T) {
	cfg := Default()
	if err := Parse([]byte("provider:\n  metadataUrl: http://lab-do-fake:8080/metadata/node-a/v1.json\n"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil || cfg.Provider.MetadataURL == "" || cfg.Provider.MetadataDisabled {
		t.Fatalf("%v %+v", err, cfg.Provider)
	}
	for _, bad := range []string{"ftp://x/", "http://u:p@x/", "http:///x", "http://x/#f", "not a url"} {
		c := Default()
		c.Provider.MetadataURL = bad
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	c := Default()
	if err := Parse([]byte("provider:\n  metadataDisabled: true\n  bogus: 1\n"), c); err == nil {
		t.Fatal("unknown provider key accepted")
	}
}

func TestSSHConfig(t *testing.T) {
	cfg := Default()
	if err := Parse([]byte("ssh:\n  allowedUsers: [deploy, ' ops ']\n"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.AllowRoot || cfg.SSH.AllowedUsers[1] != "ops" {
		t.Fatalf("got %+v", cfg.SSH)
	}
	for _, bad := range []string{
		"ssh:\n  allowedUsers: [root]\n",
		"ssh:\n  allowedUsers: ['Bad User']\n",
		"ssh:\n  allowedUsers: [a, a]\n",
		"ssh:\n  allowedUsers: ['-x']\n",
		"ssh:\n  allowRoots: true\n",
	} {
		c := Default()
		err := Parse([]byte(bad), c)
		if err == nil {
			err = c.Validate()
		}
		if err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	c := Default()
	if err := Parse([]byte("ssh:\n  allowRoot: true\n  allowedUsers: [root]\n"), c); err != nil || c.Validate() != nil {
		t.Fatalf("allowRoot+root refused")
	}
}
