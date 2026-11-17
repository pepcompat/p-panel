# pPanel operator runbooks

Index of operational procedures. A runbook is "verified" only when its steps were executed in the lab
(or on an authorized target) and evidence is linked in `docs/TEST_REPORT.md`.

| Runbook                                                                                 | Phase | Status                                  |
| --------------------------------------------------------------------------------------- | ----- | --------------------------------------- |
| [Dev setup & lab](../DEPLOYMENT_RUNBOOK.md)                                             | P0    | documented; lab cycle verified (P0-T02) |
| Lab operations (`infra/lab/README.md`)                                                  | P0    | verified 2026-11-17                     |
| Agent enrollment / revoke / cert rotation                                               | P1    | TODO                                    |
| Legacy Nginx import (Discover → Observe → Adopt → Managed)                              | P3    | TODO                                    |
| Nginx change apply + emergency revert                                                   | P3    | TODO                                    |
| Deploy / rollback / auto-deploy                                                         | P4    | TODO                                    |
| Alerts, logs, retention                                                                 | P5    | TODO                                    |
| Backup, verified restore, restore drill                                                 | P6    | TODO                                    |
| Center disaster recovery (DB + config + master key + CA re-key) → `RECOVERY_RUNBOOK.md` | P6.06 | TODO                                    |
| Center outage behaviour / agent reconnect                                               | P7    | TODO                                    |
| Production install → `DEPLOYMENT_RUNBOOK.md` §4                                         | P8    | TODO                                    |
| Upgrade / migration / rollback → `UPGRADE_RUNBOOK.md`, `MIGRATION_RUNBOOK.md`           | P8.04 | TODO                                    |
| Gateway shadow test & DNS cutover/rollback                                              | P9    | TODO                                    |
| SSH key rotation & host-key mismatch                                                    | P10   | TODO                                    |
| Firewall lockout recovery                                                               | P11   | TODO                                    |
| Plugin install failure recovery                                                         | P12   | TODO                                    |
| MCP client revocation / AI incident                                                     | P13   | TODO                                    |

Conventions: each runbook lists prerequisites, exact commands, expected output, verification, rollback,
and who may execute it (permission + approval).
