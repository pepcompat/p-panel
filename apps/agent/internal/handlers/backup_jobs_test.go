package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/backupops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

func backupGrantParams(helper string) map[string]any {
	p := map[string]any{"runId": "11111111-1111-4111-8111-111111111111", "policyId": "22222222-2222-4222-8222-222222222222",
		"repo":    map[string]any{"url": "http://lab-backup:8000/node-b/", "repositoryId": "33333333-3333-4333-8333-333333333333"},
		"targets": []any{map[string]any{"type": "volume", "app": "shop", "volume": "data"}}}
	if helper != "" {
		p["helperImage"] = helper
	}
	return p
}

func TestBackupJobsPreflight(t *testing.T) {
	reg, _, _ := setup(t)
	// backups not enabled locally → RESTIC_UNAVAILABLE before ack
	_, _, je := reg.Validate(grant("backup.run", backupGrantParams("")), "s", time.Now())
	if je == nil || je.Code != backupops.CodeResticUnavailable {
		t.Fatalf("disabled: %+v", je)
	}
	// enabled, but the job asks for a different helper image → HELPER_IMAGE_NOT_ALLOWED before ack
	allowed := "lab-registry:5000/ppanel-backup/helper@sha256:" + strings.Repeat("a", 64)
	reg2 := jobs.NewRegistry()
	RegisterAll(reg2, &Deps{Backups: backupops.New(backupops.Options{ResticBin: "/usr/local/bin/restic", ResticVersion: "0.19.1",
		HelperImage: allowed, StateDir: t.TempDir()})})
	_, _, je = reg2.Validate(grant("backup.run", backupGrantParams("lab-registry:5000/other@sha256:"+strings.Repeat("b", 64))), "s", time.Now())
	if je == nil || je.Code != backupops.CodeHelperImageNotAllowed {
		t.Fatalf("helper image: %+v", je)
	}
	if _, _, je = reg2.Validate(grant("backup.run", backupGrantParams(allowed)), "s", time.Now()); je != nil {
		t.Fatalf("allowed helper refused: %+v", je)
	}
	// strict decode through the registry
	bad := backupGrantParams("")
	bad["prune"] = true
	if _, _, je = reg2.Validate(grant("backup.run", bad), "s", time.Now()); je == nil || je.Code != jobs.RejectedInvalidParams {
		t.Fatalf("unknown field: %+v", je)
	}
	for _, typ := range []string{"backup.snapshots", "backup.verify", "restore.run"} {
		h, ok := reg2.Get(typ)
		if !ok {
			t.Fatal(typ)
		}
		if typ == "restore.run" != h.Mutating() && typ != "backup.run" {
			t.Fatalf("%s mutating=%v", typ, h.Mutating())
		}
	}
}
