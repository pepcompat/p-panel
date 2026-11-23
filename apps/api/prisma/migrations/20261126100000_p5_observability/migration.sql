-- P5: monitoring, central logs, alerts and incidents (API_CONTRACTS §9, AGENT_PROTOCOL Telemetry).
-- CreateTable
CREATE TABLE "container_samples" (
    "server_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "app_name" TEXT NOT NULL,
    "application_id" UUID,
    "service" TEXT,
    "deployment_id" UUID,
    "state" TEXT NOT NULL,
    "health" TEXT,
    "restart_count" INTEGER,
    "cpu_pct" DOUBLE PRECISION,
    "mem_bytes" BIGINT,
    "mem_limit_bytes" BIGINT,
    "sampled_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "container_samples_pkey" PRIMARY KEY ("server_id","name")
);

-- CreateTable
CREATE TABLE "server_telemetry" (
    "server_id" UUID NOT NULL,
    "log_shipping" JSONB,
    "containers_reported_at" TIMESTAMPTZ(3),
    "agent_dropped_total" BIGINT NOT NULL DEFAULT 0,
    "center_dropped_total" BIGINT NOT NULL DEFAULT 0,
    "accepted_total" BIGINT NOT NULL DEFAULT 0,
    "last_dropped_at" TIMESTAMPTZ(3),
    "last_batch_at" TIMESTAMPTZ(3),
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "server_telemetry_pkey" PRIMARY KEY ("server_id")
);

-- CreateTable
CREATE TABLE "log_batches" (
    "server_id" UUID NOT NULL,
    "batch_id" UUID NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "accepted" INTEGER NOT NULL DEFAULT 0,
    "received_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "log_batches_pkey" PRIMARY KEY ("server_id","batch_id")
);

-- CreateTable
CREATE TABLE "log_tail_tokens" (
    "id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "user_id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "params_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "log_tail_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_rules" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "scope_type" TEXT NOT NULL,
    "scope_id" TEXT,
    "kind" TEXT NOT NULL,
    "params" JSONB NOT NULL DEFAULT '{}',
    "severity" TEXT NOT NULL,
    "for_sec" INTEGER NOT NULL DEFAULT 60,
    "channel_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_by" UUID NOT NULL,
    "updated_by" UUID,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "alert_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_states" (
    "rule_id" UUID NOT NULL,
    "target_type" TEXT NOT NULL,
    "target_id" UUID NOT NULL,
    "status" TEXT NOT NULL,
    "since" TIMESTAMPTZ(3) NOT NULL,
    "fired_at" TIMESTAMPTZ(3),
    "last_value" DOUBLE PRECISION,
    "incident_id" UUID,
    "evaluated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "alert_states_pkey" PRIMARY KEY ("rule_id","target_type","target_id")
);

-- CreateTable
CREATE TABLE "incidents" (
    "id" UUID NOT NULL,
    "rule_id" UUID,
    "rule_name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "target_type" TEXT NOT NULL,
    "target_id" UUID NOT NULL,
    "target_name" TEXT NOT NULL,
    "server_id" UUID NOT NULL,
    "environment" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'firing',
    "started_at" TIMESTAMPTZ(3) NOT NULL,
    "acknowledged_at" TIMESTAMPTZ(3),
    "acknowledged_by_id" UUID,
    "resolved_at" TIMESTAMPTZ(3),
    "last_value" DOUBLE PRECISION,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incident_events" (
    "id" UUID NOT NULL,
    "incident_id" UUID NOT NULL,
    "at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "type" TEXT NOT NULL,
    "actor_id" UUID,
    "detail" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "incident_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_channels" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "config_public" JSONB NOT NULL DEFAULT '{}',
    "config_encrypted" TEXT NOT NULL,
    "created_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "notification_channels_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_deliveries" (
    "id" UUID NOT NULL,
    "channel_id" UUID NOT NULL,
    "incident_id" UUID,
    "event" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "error" TEXT,
    "response_status" INTEGER,
    "next_attempt_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "delivered_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "notification_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "container_samples_application_id_idx" ON "container_samples"("application_id");

-- CreateIndex
CREATE INDEX "log_batches_received_at_idx" ON "log_batches"("received_at");

-- CreateIndex
CREATE UNIQUE INDEX "log_tail_tokens_token_hash_key" ON "log_tail_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "log_tail_tokens_expires_at_idx" ON "log_tail_tokens"("expires_at");

-- CreateIndex
CREATE INDEX "alert_rules_enabled_idx" ON "alert_rules"("enabled");

-- CreateIndex
CREATE INDEX "incidents_status_started_at_idx" ON "incidents"("status", "started_at");

-- CreateIndex
CREATE INDEX "incidents_server_id_started_at_idx" ON "incidents"("server_id", "started_at");

-- CreateIndex
CREATE INDEX "incidents_rule_id_target_type_target_id_idx" ON "incidents"("rule_id", "target_type", "target_id");

-- CreateIndex
CREATE INDEX "incident_events_incident_id_at_idx" ON "incident_events"("incident_id", "at");

-- CreateIndex
CREATE INDEX "notification_deliveries_status_next_attempt_at_idx" ON "notification_deliveries"("status", "next_attempt_at");

-- CreateIndex
CREATE INDEX "notification_deliveries_channel_id_created_at_idx" ON "notification_deliveries"("channel_id", "created_at");

-- CreateIndex
CREATE INDEX "notification_deliveries_incident_id_idx" ON "notification_deliveries"("incident_id");

-- AddForeignKey
ALTER TABLE "container_samples" ADD CONSTRAINT "container_samples_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "server_telemetry" ADD CONSTRAINT "server_telemetry_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_states" ADD CONSTRAINT "alert_states_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "alert_rules"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "alert_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_channel_id_fkey" FOREIGN KEY ("channel_id") REFERENCES "notification_channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- ---------------------------------------------------------------- hand-written (not expressible in Prisma)

-- One open incident per (rule, target): dedupe while firing/acknowledged (P5.05).
CREATE UNIQUE INDEX "incidents_open_rule_target_key"
  ON "incidents" ("rule_id", "target_type", "target_id")
  WHERE "status" <> 'resolved';

ALTER TABLE "incidents" ADD CONSTRAINT "incidents_status_check"
  CHECK ("status" IN ('firing','acknowledged','resolved'));
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_severity_check"
  CHECK ("severity" IN ('info','warning','critical'));
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_target_type_check"
  CHECK ("target_type" IN ('server','app'));
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_type_check"
  CHECK ("type" IN ('fired','notified','notify_failed','acknowledged','resolved','comment'));
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_kind_check"
  CHECK ("kind" IN ('server_offline','metric_threshold','app_down','log_dropped','backup_failed'));
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_scope_type_check"
  CHECK ("scope_type" IN ('global','environment','server','app'));
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_severity_check"
  CHECK ("severity" IN ('info','warning','critical'));
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_for_sec_check"
  CHECK ("for_sec" BETWEEN 0 AND 86400);
ALTER TABLE "alert_states" ADD CONSTRAINT "alert_states_status_check"
  CHECK ("status" IN ('pending','firing'));
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_type_check"
  CHECK ("type" IN ('webhook','email','telegram'));
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_status_check"
  CHECK ("status" IN ('pending','sending','delivered','failed'));
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_event_check"
  CHECK ("event" IN ('fired','resolved','test'));
ALTER TABLE "log_batches" ADD CONSTRAINT "log_batches_status_check"
  CHECK ("status" IN ('pending','done'));
ALTER TABLE "server_telemetry" ADD CONSTRAINT "server_telemetry_counters_check"
  CHECK ("agent_dropped_total" >= 0 AND "center_dropped_total" >= 0 AND "accepted_total" >= 0);

-- Rollback (manual): see ROLLBACK.md next to this file.
