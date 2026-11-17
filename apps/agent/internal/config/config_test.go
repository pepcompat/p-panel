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
