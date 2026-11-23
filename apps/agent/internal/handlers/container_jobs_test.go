package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/docker/dockertest"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func containerRegistry(t *testing.T) (*jobs.Registry, *dockertest.Engine) {
	fe := dockertest.New(t)
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Containers: containerops.New(containerops.Options{Engine: docker.NewEngine(fe.Socket)})})
	return reg, fe
}

func TestContainerGrantValidation(t *testing.T) {
	reg, fe := containerRegistry(t)
	run := map[string]any{"deploymentId": "0b7c2a7e-3f43-4a52-9d55-6f0e9a9b1c01", "app": "shop", "name": "ppanel-shop-1a2b3c4d",
		"image": "lab-registry:5000/ppanel-test/web:v1", "containerPort": 8080, "hostPort": 20001}
	if _, _, rej := reg.Validate(grant("container.run_candidate", run), "s", time.Now()); rej == nil || rej.Code != jobs.RejectedInvalidParams {
		t.Fatalf("tag-only image: %v", rej)
	}
	run["image"] = "lab-registry:5000/ppanel-test/web@" + testDigest
	if _, _, rej := reg.Validate(grant("container.run_candidate", run), "s", time.Now()); rej != nil {
		t.Fatalf("valid run rejected: %v", rej)
	}
	// ownership name rule is enforced before ack, with zero docker calls
	for typ, p := range map[string]map[string]any{
		"container.stop":    {"app": "shop", "name": "ppanel-blog-1a2b3c4d"},
		"container.remove":  {"app": "shop", "name": "ppanel-blog-1a2b3c4d"},
		"container.start":   {"app": "shop", "name": "ppanel-blog-1a2b3c4d", "hostPort": 20001},
		"container.restart": {"app": "shop", "name": "ppanel-blog-1a2b3c4d", "hostPort": 20001},
		"container.logs":    {"app": "shop", "name": "ppanel-blog-1a2b3c4d"},
	} {
		if _, _, rej := reg.Validate(grant(typ, p), "s", time.Now()); rej == nil || rej.Code != containerops.CodeContainerNotManaged {
			t.Fatalf("%s: %v", typ, rej)
		}
	}
	if n := len(fe.CallsSnapshot()); n != 0 {
		t.Fatalf("validation reached docker (%d calls)", n)
	}
	for _, typ := range []string{"container.run_candidate", "container.start", "container.restart", "container.stop", "container.remove"} {
		h, _ := reg.Get(typ)
		if !h.Mutating() {
			t.Fatalf("%s must be mutating", typ)
		}
	}
	for _, typ := range []string{"container.list", "container.logs"} {
		h, _ := reg.Get(typ)
		if h.Mutating() {
			t.Fatalf("%s must be read-only", typ)
		}
	}
	// list through the handler
	h, p, rej := reg.Validate(grant("container.list", map[string]any{}), "s", time.Now())
	if rej != nil {
		t.Fatal(rej)
	}
	out, err := h.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if string(b) != `{"containers":[]}` {
		t.Fatalf("list output %s", b)
	}
}

func TestContainerJobsWithoutDocker(t *testing.T) {
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{})
	h, p, rej := reg.Validate(grant("container.list", map[string]any{"app": "shop"}), "s", time.Now())
	if rej != nil {
		t.Fatal(rej)
	}
	_, err := h.Run(context.Background(), p)
	var je *jobs.Error
	if !errors.As(err, &je) || je.Code != containerops.CodeDockerUnavailable {
		t.Fatalf("%v", err)
	}
}
