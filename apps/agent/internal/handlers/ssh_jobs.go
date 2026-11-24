package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/sshkeys"
)

// ---------------- ssh.keys.sync (P10) ----------------

// SSHKeysSync implements ssh.keys.sync: it rewrites ONLY the pPanel managed
// block of ~user/.ssh/authorized_keys with the desired PUBLIC keys. The agent
// never receives a private key and never opens a shell.
type SSHKeysSync struct{ d *Deps }

func (*SSHKeysSync) Type() string           { return "ssh.keys.sync" }
func (*SSHKeysSync) Mutating() bool         { return true }
func (*SSHKeysSync) Timeout() time.Duration { return 30 * time.Second }
func (*SSHKeysSync) Decode(raw json.RawMessage) (any, error) {
	return sshkeys.DecodeSyncParams(raw)
}

func (h *SSHKeysSync) syncer() *sshkeys.Syncer {
	if h.d.SSH != nil {
		return h.d.SSH
	}
	return defaultSyncer
}

var defaultSyncer = &sshkeys.Syncer{}

// Preflight applies the local user policy before ack (SSH_USER_INVALID).
func (h *SSHKeysSync) Preflight(params any) error {
	_, err := h.syncer().LookupUser(params.(sshkeys.SyncParams).User)
	return err
}

func (h *SSHKeysSync) Run(ctx context.Context, params any) (any, error) {
	return h.syncer().Sync(ctx, params.(sshkeys.SyncParams))
}
