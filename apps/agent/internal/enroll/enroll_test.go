package enroll

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppanel/ppanel/apps/agent/internal/fakecenter"
	"github.com/ppanel/ppanel/apps/agent/internal/state"
)

const tok = "ppe_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestEnrollTLSAndKeyPerms(t *testing.T) {
	c := fakecenter.New(t, "0190f4c2-0000-7000-8000-000000000001")
	c.AddToken(tok)
	url := c.StartEnrollTLS()
	caFile := filepath.Join(t.TempDir(), "center-ca.pem")
	os.WriteFile(caFile, c.CA.PEM, 0o644)
	dir := filepath.Join(t.TempDir(), "state")

	id, err := Run(context.Background(), Options{CenterURL: url, Token: tok, StateDir: dir, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if id.ServerID != c.ServerID || id.GatewayURL != c.GatewayURL {
		t.Fatalf("identity %+v", id)
	}
	st, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %o", st.Mode().Perm())
	}
	kst, _ := os.Stat(filepath.Join(dir, state.KeyFile))
	if kst.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o, want 600", kst.Mode().Perm())
	}
	if !(state.Dir{Path: dir}).Enrolled() {
		t.Fatal("not enrolled")
	}
	// private key never transmitted; facts present
	body := string(c.EnrollBodies[0])
	if strings.Contains(body, "PRIVATE KEY") || !strings.Contains(body, "CERTIFICATE REQUEST") ||
		!strings.Contains(body, `"agentVersion"`) || !strings.Contains(body, `"arch"`) || !strings.Contains(body, `"hostname"`) {
		t.Fatalf("enroll body: %s", body)
	}
	_, _, leaf, err := (state.Dir{Path: dir}).LoadTLS()
	if err != nil || leaf.Subject.CommonName != "agent:"+c.ServerID {
		t.Fatalf("leaf %v %v", err, leaf)
	}

	// re-enroll refused without --force; token reuse rejected by center
	if _, err := Run(context.Background(), Options{CenterURL: url, Token: tok, StateDir: dir, CAFile: caFile}); err == nil {
		t.Fatal("expected already-enrolled error")
	}
	_, err = Run(context.Background(), Options{CenterURL: url, Token: tok, StateDir: dir, CAFile: caFile, Force: true})
	if err == nil || !strings.Contains(err.Error(), "ENROLLMENT_TOKEN_INVALID") {
		t.Fatalf("expected token reuse rejection, got %v", err)
	}
}

func TestEnrollRejectsUntrustedCenterTLS(t *testing.T) {
	c := fakecenter.New(t, "s1")
	c.AddToken(tok)
	url := c.StartEnrollTLS()
	// no CAFile -> system roots -> test CA not trusted
	_, err := Run(context.Background(), Options{CenterURL: url, Token: tok, StateDir: filepath.Join(t.TempDir(), "s")})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected TLS verification failure, got %v", err)
	}
}

func TestInsecureHTTPRequiresEnv(t *testing.T) {
	c := fakecenter.New(t, "s2")
	c.AddToken(tok)
	url := c.StartEnrollHTTP()
	dir := filepath.Join(t.TempDir(), "s")
	t.Setenv(InsecureEnv, "")
	if _, err := Run(context.Background(), Options{CenterURL: url, Token: tok, StateDir: dir}); err == nil || !strings.Contains(err.Error(), "plain-HTTP") {
		t.Fatalf("expected plain-HTTP refusal, got %v", err)
	}
	t.Setenv(InsecureEnv, "1")
	if _, err := Run(context.Background(), Options{CenterURL: url, Token: tok, StateDir: dir}); err != nil {
		t.Fatal(err)
	}
}

func TestValidation(t *testing.T) {
	for _, u := range []string{"ftp://x", "https://user:pw@x", "https://x/?a=1", "not a url"} {
		if _, err := ValidateCenterURL(u); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
	if _, err := Run(context.Background(), Options{CenterURL: "https://x", Token: "bad token", StateDir: t.TempDir()}); err == nil {
		t.Fatal("bad token format must be rejected")
	}
}
