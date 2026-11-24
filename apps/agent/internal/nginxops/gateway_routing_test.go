package nginxops

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// P9: Gateway route files live in /etc/nginx/ppanel-gateway/<domain>.conf (depth 1)
// plus the one include file conf.d/ppanel-gateway.conf.
func TestGatewayFilesCreatableDepthOneOnly(t *testing.T) {
	mk := func(p string) json.RawMessage {
		return json.RawMessage(`{"revisionId":"` + revR1 + `","files":[{"path":"` + p + `","expectedSha256Before":null,"content":"x"}]}`)
	}
	for _, p := range []string{GatewayIncludeFile, GatewayDir + "/shop.example.lab.conf"} {
		if _, err := DecodeApply(mk(p)); err != nil {
			t.Fatalf("%s refused at decode: %v", p, err)
		}
	}
	for _, p := range []string{GatewayDir + "/a/b.conf", "/etc/nginx/ppanel-gatewayx/a.conf", "/etc/nginx/conf.d/ppanel-gateway.conf.bak",
		"/etc/nginx/ppanel-gateway.conf", "/etc/nginx/sites-enabled/ppanel-gateway.conf"} {
		if code(t, decodeErr(mk(p))) != CodePathNotAllowed {
			t.Fatalf("%s accepted", p)
		}
	}
}

func decodeErr(raw json.RawMessage) error { _, err := DecodeApply(raw); return err }

func TestGatewayRouteDirCreatedAndReverted(t *testing.T) {
	e := newEnv(t)
	before := tree(e.root)
	inc := "include /etc/nginx/ppanel-gateway/*.conf;\n"
	route := "server { listen 80; server_name shop.example.lab; location / { proxy_pass http://10.110.0.11:80; } }\n"
	out, err := e.m.Apply(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{
		{Path: GatewayIncludeFile, Content: inc},
		{Path: GatewayDir + "/shop.example.lab.conf", Content: route},
	}})
	must(t, err)
	if !out.Applied {
		t.Fatalf("not applied: %+v", out)
	}
	if b, _ := os.ReadFile(e.root + "/ppanel-gateway/shop.example.lab.conf"); string(b) != route {
		t.Fatalf("route %q", b)
	}
	if st, _ := os.Stat(e.root + "/ppanel-gateway"); st == nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("gateway dir mode %v", st)
	}
	shaI, shaR := shaHex([]byte(inc)), shaHex([]byte(route))
	_, err = e.m.Revert(ctxJob(revR2), RevertParams{RevisionID: revR1, ExpectedCurrent: []ExpectedFile{
		{Path: GatewayIncludeFile, Sha256: &shaI}, {Path: GatewayDir + "/shop.example.lab.conf", Sha256: &shaR}}})
	must(t, err)
	sameTree(t, before, tree(e.root)) // gateway dir removed again
}

func TestGatewayDirSymlinkRefused(t *testing.T) {
	e := newEnv(t)
	must(t, os.Symlink("sites-available", e.root+"/ppanel-gateway"))
	before := tree(e.root)
	_, err := e.m.Validate(ctxJob(revR2), RevisionParams{RevisionID: revR1, Files: []FileChange{{Path: GatewayDir + "/x.conf", Content: "x"}}})
	if code(t, err) != CodePathNotAllowed {
		t.Fatalf("symlinked gateway dir: %v", err)
	}
	sameTree(t, before, tree(e.root))
}

// The first gateway plan reads its (not yet existing) files: absent, not refused.
func TestReadGatewayFileBeforeDirExists(t *testing.T) {
	e := newEnv(t)
	out, err := e.m.Read(context.Background(), ReadParams{Paths: []string{GatewayDir + "/shop.example.lab.conf"}})
	if err != nil || len(out.Files) != 1 || out.Files[0].Exists {
		t.Fatalf("%+v %v", out, err)
	}
	if _, err := e.m.Read(context.Background(), ReadParams{Paths: []string{"/etc/nginx/nope/x.conf"}}); code(t, err) != CodePathNotAllowed {
		t.Fatalf("non-managed missing parent: %v", err)
	}
}
