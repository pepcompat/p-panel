package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/buildops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

func buildGrantParams(url string) map[string]any {
	return map[string]any{"buildId": "4a1f0d3e-5b6c-4d7e-8f90-0123456789ab", "app": "websrc",
		"source": map[string]any{"url": url, "commitSha": strings.Repeat("a", 40)}, "dockerfile": "Dockerfile",
		"pushRepo": "lab-registry:5000/ppanel/websrc"}
}

// NOT_A_BUILD_NODE is decided by Validate (before ack) when the local config did not enable builds.
func TestNotABuildNodeBeforeAck(t *testing.T) {
	reg, _, _ := setup(t)
	now := time.Now()
	for typ, params := range map[string]any{
		"image.build":    buildGrantParams("https://github.com/acme/web"),
		"source.inspect": map[string]any{"source": map[string]any{"url": "https://github.com/acme/web", "commitSha": strings.Repeat("a", 40)}},
	} {
		_, _, rej := reg.Validate(grant(typ, params), "s", now)
		if rej == nil || rej.Code != buildops.CodeNotABuildNode {
			t.Fatalf("%s: %+v", typ, rej)
		}
	}
	// invalid params are still rejected as such
	bad := buildGrantParams("https://github.com/acme/web")
	bad["dockerfile"] = "../Dockerfile"
	if _, _, rej := reg.Validate(grant("image.build", bad), "s", now); rej == nil || rej.Code != jobs.RejectedInvalidParams {
		t.Fatalf("%+v", rej)
	}
}

func TestGitHostNotAllowedBeforeAck(t *testing.T) {
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Builds: buildops.New(buildops.Options{AllowedHosts: []string{"lab-git"}, WorkDir: t.TempDir()})})
	now := time.Now()
	if _, _, rej := reg.Validate(grant("image.build", buildGrantParams("https://github.com/acme/web")), "s", now); rej == nil || rej.Code != buildops.CodeGitHostNotAllowed {
		t.Fatalf("%+v", rej)
	}
	if _, _, rej := reg.Validate(grant("image.build", buildGrantParams("git://lab-git/websrc.git")), "s", now); rej != nil {
		t.Fatalf("allowlisted host rejected: %+v", rej)
	}
}

func TestComposeGrantDecode(t *testing.T) {
	reg, _, _ := setup(t)
	now := time.Now()
	svc := func(name, cname string) map[string]any {
		return map[string]any{"service": name, "name": cname, "image": "lab-registry:5000/x/y@sha256:" + strings.Repeat("a", 64),
			"specHash": strings.Repeat("b", 64)}
	}
	ok := map[string]any{"deploymentId": "4a1f0d3e-5b6c-4d7e-8f90-0123456789ab", "app": "stack",
		"services": []any{svc("db", "ppanel-stack-db-1a2b3c4d")}}
	if _, _, rej := reg.Validate(grant("compose.apply", ok), "s", now); rej != nil {
		t.Fatalf("%+v", rej)
	}
	bad := map[string]any{"deploymentId": "4a1f0d3e-5b6c-4d7e-8f90-0123456789ab", "app": "stack",
		"services": []any{svc("db", "ppanel-other-db-1a2b3c4d")}}
	if _, _, rej := reg.Validate(grant("compose.apply", bad), "s", now); rej == nil || rej.Code != jobs.RejectedInvalidParams {
		t.Fatalf("%+v", rej)
	}
	if _, _, rej := reg.Validate(grant("compose.stop", map[string]any{"app": "stack"}), "s", now); rej != nil {
		t.Fatalf("%+v", rej)
	}
	// container.stop accepts a compose service container name (the Center stops the old route container)
	if _, _, rej := reg.Validate(grant("container.stop", map[string]any{"app": "stack", "name": "ppanel-stack-app-1a2b3c4d"}), "s", now); rej != nil {
		t.Fatalf("%+v", rej)
	}
}
