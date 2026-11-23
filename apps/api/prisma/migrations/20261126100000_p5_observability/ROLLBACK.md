# Rollback plan — 20261126100000_p5_observability

Adds P5 tables only (`container_samples`, `server_telemetry`, `log_batches`, `log_tail_tokens`,
`alert_rules`, `alert_states`, `incidents`, `incident_events`, `notification_channels`,
`notification_deliveries`). No existing table or column is changed.

Rolling back destroys alert rules, incident history and notification channels (channel secrets are
encrypted and cannot be re-exported in clear) — export first if needed
(`pg_dump -t alert_rules -t incidents -t incident_events -t notification_channels`).
Logs live in Loki and metrics in Prometheus; neither is affected. Stop the Center first so the alert
evaluator and notification dispatcher are not running.

```sql
BEGIN;
DROP TABLE IF EXISTS "notification_deliveries", "notification_channels", "incident_events",
  "incidents", "alert_states", "alert_rules", "log_tail_tokens", "log_batches",
  "server_telemetry", "container_samples" CASCADE;
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261126100000_p5_observability';
COMMIT;
```
