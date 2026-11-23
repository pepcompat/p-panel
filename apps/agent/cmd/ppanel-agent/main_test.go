package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

func TestVersionAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if run([]string{"version"}, &out, &errb) != 0 || !strings.HasPrefix(out.String(), "ppanel-agent ") {
		t.Fatalf("version: %q", out.String())
	}
	if run(nil, &out, &errb) != 2 || run([]string{"bogus"}, &out, &errb) != 2 {
		t.Fatal("usage errors must exit 2")
	}
}

func TestCheckConfig(t *testing.T) {
	d := t.TempDir()
	cfg := filepath.Join(d, "config.yaml")
	os.WriteFile(cfg, []byte("stateDir: "+filepath.Join(d, "state")+"\nownedUnits: [web.service]\n"), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"check-config", "--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	var rep map[string]any
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep["enrolled"] != false || rep["ownedUnits"].(float64) != 1 {
		t.Fatalf("%v %s", err, out.String())
	}
	os.WriteFile(cfg, []byte("bogus: 1\n"), 0o600)
	if code := run([]string{"check-config", "--config", cfg}, &out, &errb); code != 1 {
		t.Fatal("invalid config must exit 1")
	}
	// loose state dir perms are flagged
	sd := filepath.Join(d, "loose")
	os.Mkdir(sd, 0o755)
	os.WriteFile(cfg, []byte("stateDir: "+sd+"\n"), 0o600)
	if code := run([]string{"check-config", "--config", cfg}, &out, &errb); code != 1 {
		t.Fatal("0755 state dir must fail check-config")
	}
}

func TestRunNotEnrolled(t *testing.T) {
	d := t.TempDir()
	var out, errb bytes.Buffer
	if code := run([]string{"run", "--config", filepath.Join(d, "none.yaml"), "--state-dir", filepath.Join(d, "s")}, &out, &errb); code != 1 {
		t.Fatalf("run without enrollment must exit 1, got %d", code)
	}
	if !strings.Contains(errb.String(), "not enrolled") || !strings.Contains(errb.String(), `"message"`) || !strings.Contains(errb.String(), `"timestamp"`) {
		t.Fatalf("expected structured log: %s", errb.String())
	}
}

func TestSecretValuesForRedaction(t *testing.T) {
	s := &transport.JobSecrets{Env: map[string]string{"DB_PASS": "db-pass-123"},
		RegistryAuth: &transport.RegistryAuth{Username: "u", Password: "reg-pass-456"},
		GitAuth:      &transport.GitAuth{Header: "Authorization: Basic Z2l0OnRva2Vu"}}
	got := strings.Join(secretValues(s), "|")
	for _, want := range []string{"db-pass-123", "reg-pass-456", "Authorization: Basic Z2l0OnRva2Vu", "Z2l0OnRva2Vu"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}
