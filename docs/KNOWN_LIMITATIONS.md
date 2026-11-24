# Known limitations — pPanel 0.8.0-rc.1 (MVP-B release candidate)

This list is part of the P8 gate: nothing here is hidden behind a PASS. "BLOCKED" means the work needs
something outside the lab (credentials, public DNS, real machines) and was not attempted.

## Blocked on external inputs

| Item                                     | Needs                                    | Effect today                                                                              |
| ---------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| Clean install on a real Ubuntu VM        | a disposable VM                          | P8-T01 ran on an Ubuntu 24.04 systemd container in the lab (reported as lab substitute)   |
| ACME / HTTPS for managed sites           | public DNS pointing at a test server     | TLS issuance is not available; the wizard shows it as BLOCKED                             |
| GitHub App integration                   | GitHub App credentials                   | auto-deploy works with signed generic/GitHub webhooks only                                |
| DigitalOcean VPC verification            | read-only DO API token                   | private IPs are recorded as reported by the agent, not verified against the DO API        |
| Signed release artifacts                 | `PPANEL_RELEASE_SIGNING_KEY` repo secret | releases ship `SHA256SUMS`; the ed25519 signature is produced only once the secret exists |
| Network partitions, clock skew, quotas   | real VMs                                 | not tested; container lab cannot model them                                               |
| systemd `service.restart` job in the lab | lab nodes with systemd as PID 1          | covered by unit tests only                                                                |

## Scale and capacity (from `docs/PERFORMANCE_REPORT.md`)

- One Center Node process. On an Apple M4 it handled **1 000 agents and 2 000 log lines/s** with heartbeat
  p95 37 ms; at 2 000 agents every endpoint queued (p95 ≈ 2 s). Running more than one Center process is
  not supported yet.
- `log_batches` dedupe rows dominate database growth: about 266 MB/h at 1 000 agents, about 7 GB at
  steady state with the 24 h dedupe window.
- The load generator ran on the same machine as the Center, so these numbers are conservative.

## Behaviour to be aware of

- **Center high availability is not provided.** Managed sites keep serving while the Center is down
  (P7-T01), but the Center itself and the gateway (:4443) are single instances.
- Webhook "latest wins" coalescing applies to **image-mode** auto-deploy only. In build mode, a build
  that finishes while a deployment runs records a deploy error instead of queuing.
- Auto-deploy for Compose applications is not available.
- `server_offline` alert rules need `forSec >= 90`; older rules were raised to 90 by a migration.
- An agent restart after a crash mid nginx apply restores the backup from its journal. If that restore
  fails, the Center still records the apply as not applied and a later drift scan flags the files.
- A backup to an unreachable repository fails after the 60 s preflight; slow-but-reachable repositories
  still follow restic's own retry timing.
- Agents older than the Center's `minAgentVersion` keep serving but receive no new mutating jobs
  (`AGENT_OUTDATED`) until upgraded.

## Not implemented (shown in the UI as proposed or absent)

- Operator-triggered agent certificate rotation (agents renew automatically at 2/3 of the lifetime).
- Connection policy enforcement, address overrides and network diagnostics.
- TLS status/expiry per Nginx site.
- Fleet-wide list of Nginx revision approvals (the Approvals page says so).
- Server groups and backup repository creation have APIs but no UI.
- Editing a container app's configuration in the UI.

## Verification gaps

- The P7 chaos scenarios that originally failed (F-3, F-7 … F-10) were fixed and covered by unit and
  integration tests, but not re-run in the lab against the fixed build.
- Center disaster recovery is covered by an integration test and the runbook, not by a run on a
  separate host.
- UI journeys J03, J04, J06–J10 and J12 are covered by mock-mode Playwright specs plus real-API lab
  scripts (`scripts/lab/e2e_p3.py` … `e2e_p6.py`), not by UI runs against the real API.
- The dev seeder's `superadmin` has no 2FA (development only; production first boot enforces TOTP).
