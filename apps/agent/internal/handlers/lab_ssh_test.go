package handlers

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/sshkeys"
)

// TestLabSSHKeysSync runs the real ssh.keys.sync handler on the P10 lab node
// (ppanel-lab-node-s, user ops). Opt-in, run INSIDE the node as root:
//
//	PPANEL_LAB_SSH=1 PPANEL_LAB_SSH_KEYS='<publicKey>|<fingerprint>;...' ./handlers.test -test.run TestLabSSHKeysSync -test.v
//
// An empty PPANEL_LAB_SSH_KEYS removes every managed key. Prints the result
// and the ssh facts as JSON (PPANEL_LAB_OUT=1).
func TestLabSSHKeysSync(t *testing.T) {
	if os.Getenv("PPANEL_LAB_SSH") != "1" {
		t.Skip("set PPANEL_LAB_SSH=1 to run on the P10 lab node")
	}
	reg := jobs.NewRegistry()
	RegisterAll(reg, &Deps{Host: &host.Env{}, Sampler: &metrics.Sampler{}, SSH: &sshkeys.Syncer{}})
	keys := []any{}
	for _, kv := range strings.Split(os.Getenv("PPANEL_LAB_SSH_KEYS"), ";") {
		if kv == "" {
			continue
		}
		pk, fp, _ := strings.Cut(kv, "|")
		keys = append(keys, map[string]any{"publicKey": pk, "fingerprint": fp})
	}
	user := os.Getenv("PPANEL_LAB_SSH_USER")
	if user == "" {
		user = "ops"
	}
	h, p, rej := reg.Validate(grant("ssh.keys.sync", map[string]any{"user": user, "keys": keys, "managedBlockId": "ppanel"}), "s", time.Now())
	if rej != nil {
		b, _ := json.Marshal(rej)
		t.Logf("REJECTED %s", b)
		if os.Getenv("PPANEL_LAB_SSH_EXPECT") == rej.Code {
			return
		}
		t.Fatal(rej)
	}
	out, err := h.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"result": out, "ssh": sshkeys.CollectFacts("")})
	t.Logf("RESULT %s", b)
}
