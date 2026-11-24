# SSH keys and the web terminal

Covers P10: SSH credentials, host keys, access grants and the browser terminal. Security model:
[SSH_SECURITY.md](../SSH_SECURITY.md); contract: [P10_SSH_CONTRACT.md](../P10_SSH_CONTRACT.md).

**Ground rule:** the terminal goes through the Center SSH gateway only. pPanel never edits `sshd_config`; it only
manages its own block in a user's `authorized_keys`.

## 1. Set up a server for SSH (once per server)

1. **Endpoint** — **Server → SSH → Endpoints**: set the private and/or public endpoint (`host` is the server's
   known private or public IPv4, default port 22) and the allowed SSH users. `root` is refused. A host that isn't a
   known address of the server is refused with `SSH_ENDPOINT_UNVERIFIED`.
2. **Credential** — **SSH & Credentials → Credentials → Generate** (ed25519, step-up). You can also import an
   existing private key, unencrypted or with its passphrase. The key is stored encrypted and is never shown again;
   only the public key and fingerprint are shown.
3. **Deploy** the credential to the server and SSH user. The agent writes the public key into a managed block of
   `~user/.ssh/authorized_keys` with `restrict,pty` and leaves the user's other keys untouched.
4. **Host key** — **Host keys → Scan**, compare the fingerprint (✓ when it matches what the agent reported), then
   **Trust** (step-up). Without a trusted host key no session opens.

## 2. Get access

- **Access grants → Request**: server, SSH user, path (private/public), duration (15 min – 8 h) and reason.
  - Development/UAT: active immediately.
  - Production: waits for another person with `approvals.decide` to approve with step-up. You can't approve your
    own request.
- Revoke a grant at any time; open sessions on it close.

## 3. Use the terminal

**Open Terminal** on the server card, or **SSH & Credentials → Terminal**, then pick an active grant. Production
asks for step-up if you haven't done it in the last 10 minutes. The header shows the server, path, `host:port`, SSH
user and host-key fingerprint. Sessions close on `exit`, after 15 minutes idle, when the grant expires, or after
8 hours. Up to 3 sessions per user and 5 per server.

| Closed with                              | Meaning / action                                                                                                              |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Authentication failed (4401)             | the ticket expired or was already used. Reconnect, which issues a new ticket                                                  |
| Access denied (4403)                     | grant not active, or the key was revoked or rotated. Request a new grant                                                      |
| Idle / expired (4408)                    | idle timeout, grant expiry or maximum duration reached                                                                        |
| Host key mismatch (4409)                 | the server presented a different key. **Don't trust it blindly**: check with the server owner, then review it under Host keys |
| Too many sessions (4429)                 | close a session first                                                                                                         |
| `SSH_CONNECT_FAILED` / `SSH_AUTH_FAILED` | endpoint unreachable, or the key isn't installed for that user. Re-deploy it                                                  |

## 4. Rotate and revoke

- **Rotate** generates a new key, installs it wherever the old one was installed, and removes the old one in the
  same write. The old key stops working at the Center immediately.
- **Revoke** stops the key at the Center immediately, closes its sessions, and removes it from every host the next
  time that host's agent is online.

## Audit

Every key, endpoint, host-key, grant and session action is in **Events & Audit** (`ssh.*`). The audit holds
metadata only: who, server, user, path, fingerprints, duration, bytes and end reason. Terminal input and output
are not recorded.

## Agent host setup

The shipped systemd unit keeps `ProtectHome=read-only`. To let the agent manage a user's keys, add a drop-in
for that user only:

```ini
# /etc/systemd/system/ppanel-agent.service.d/ssh-keys.conf
[Service]
ReadWritePaths=/home/ops/.ssh
```

Then run `systemctl daemon-reload && systemctl restart ppanel-agent`. Without it, deploying a key fails with a
read-only filesystem error and nothing changes on the host.

## Limitations

- Lab-verified against a containerised `sshd`; real-VM tests are BLOCKED until a disposable VM is provided.
- Not supported: FIDO/`sk-*` keys, SSH certificates, jump hosts and session recording.
