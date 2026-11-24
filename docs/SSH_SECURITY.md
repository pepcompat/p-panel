# SSH security model (P10)

Scope: the human web terminal and SSH key administration. Contract: [P10_SSH_CONTRACT.md](P10_SSH_CONTRACT.md).
Operator guide: [guides/ssh-terminal.md](guides/ssh-terminal.md).

## Principles

1. **One path to a shell.** Browser ↔ authenticated WebSocket ↔ Center SSH gateway ↔ the server's own `sshd`. The
   Go agent has no shell job, and the MCP server (P13) gets status/metadata tools only, never a terminal.
2. **Private keys never leave the Center backend.** Generated or imported keys are encrypted with AES-256-GCM under
   `PPANEL_MASTER_KEY`, decrypted in memory only for the SSH handshake, and never appear in API responses, job
   parameters, WebSocket frames, logs or audit rows. The agent only installs public keys.
3. **No trust on first use.** A host key is used only after a person with `credentials.manage` trusts it with
   step-up MFA. The UI shows whether the scanned key matches the fingerprint the agent reported over mTLS. A
   different key at connect time blocks the session before authentication.
4. **Access is a time-boxed grant.** Every session needs an active grant for (user, server, SSH user, path).
   Production grants need a second person's approval with step-up; opening a production session needs step-up in
   the last 10 minutes.
5. **Least privilege on the host.** Managed `authorized_keys` lines carry `restrict,pty` (no port, agent or X11
   forwarding). `root` is refused by default. The Center's SSH client also requests no forwarding.
6. **Metadata audit, no recording.** Metadata is audited for every action. Keystrokes and output are
   not recorded; recording would need an explicit policy and retention decision.

## Threats and controls

| Threat                                | Control                                                                                                                                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cross-site WebSocket hijacking        | `Origin` must be a configured `WEB_ORIGIN` before upgrade (else 403); auth is a single-use, 30-second ticket sent in the first message, not a cookie                                                       |
| Ticket leak via URL, referrer or logs | ticket is never in the URL; stored as SHA-256; redacted from logs; consumed atomically                                                                                                                     |
| XSS stealing keys                     | no endpoint returns private material, so a script running in the page can't obtain it. The import textarea is cleared and never cached. CSP restricts `connect-src` to the API origin and its `ws(s)` twin |
| Stolen browser session                | a grant must exist and be active; production also requires recent step-up and a second approver                                                                                                            |
| Host impersonation / MITM             | pinned trusted host key per endpoint and algorithm; a mismatch is refused, audited and stored as a pending key for review                                                                                  |
| Revoked or rotated key still usable   | the Center refuses non-active keys immediately (even if the host is offline) and re-syncs `authorized_keys` to remove them                                                                                 |
| Lateral movement through forwarding   | `restrict,pty` in authorized_keys, plus no forwarding requests from the client                                                                                                                             |
| Resource exhaustion                   | per-user, per-server and global session limits; 64 KiB frame cap; idle timeout; maximum duration; backpressure                                                                                             |
| Orphaned sessions                     | every close path ends the SSH channel and connection. Shutdown closes sessions as `center_shutdown`; startup marks leftovers `center_restart`                                                              |
| Fallback to public exposure           | the P9 connection policy applies: `private_only` servers have no public SSH, and there is no automatic private→public fallback                                                                             |
| Lockout of a host                     | pPanel never edits `sshd_config` and only rewrites its own delimited block in `authorized_keys`, preserving every other line                                                                               |

## Not covered (known limits)

- No terminal recording (see principle 6).
- Hardware-backed keys (FIDO `sk-*`), SSH certificates, jump hosts and `sshd` hardening are not managed.
- Keys are encrypted under the master key in the database, not held in an HSM or KMS. There is no master-key
  rotation yet; losing the master key loses the stored SSH keys (see
  [RECOVERY_RUNBOOK.md](RECOVERY_RUNBOOK.md): keep it in offline escrow).
- Lab-verified against a containerised `sshd` (`lab-node-s`); real-VM verification is BLOCKED until a disposable VM
  is supplied.
