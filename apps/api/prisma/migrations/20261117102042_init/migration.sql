-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "last_login_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "family_id" UUID NOT NULL,
    "refresh_token_hash" TEXT NOT NULL,
    "amr" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "ip" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "last_used_at" TIMESTAMPTZ(3),
    "rotated_at" TIMESTAMPTZ(3),
    "replaced_by_id" UUID,
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_reason" TEXT,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mfa_factors" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'totp',
    "secret_enc" TEXT NOT NULL,
    "confirmed_at" TIMESTAMPTZ(3),
    "last_used_step" INTEGER,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "mfa_factors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recovery_codes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "code_hash" TEXT NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "recovery_codes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_bindings" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "role_key" TEXT NOT NULL,
    "scope_type" TEXT NOT NULL,
    "scope_id" TEXT,
    "created_by_id" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "role_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "server_groups" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "environment" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "server_groups_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "servers" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "environment" TEXT NOT NULL,
    "group_id" UUID,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "status" TEXT NOT NULL DEFAULT 'enrolling',
    "last_heartbeat_at" TIMESTAMPTZ(3),
    "last_seq" BIGINT,
    "agent_version" TEXT,
    "os" JSONB,
    "provider" JSONB,
    "connection_policy" TEXT NOT NULL DEFAULT 'auto',
    "metrics" JSONB,
    "metrics_sampled_at" TIMESTAMPTZ(3),
    "owned_units" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "enrollment_id" UUID,
    "version" INTEGER NOT NULL DEFAULT 1,
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "servers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "server_addresses" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "family" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "interface" TEXT,
    "source" TEXT NOT NULL DEFAULT 'detected',
    "verified_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "server_addresses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_enrollments" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "environment" TEXT NOT NULL,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "token_hash" TEXT NOT NULL,
    "ttl_minutes" INTEGER NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "server_id" UUID,
    "created_by_id" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_enrollments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_certificates" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "serial" TEXT NOT NULL,
    "fingerprint_sha256" TEXT NOT NULL,
    "cert_pem" TEXT NOT NULL,
    "not_before" TIMESTAMPTZ(3) NOT NULL,
    "not_after" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_reason" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_certificates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_heartbeats" (
    "id" BIGSERIAL NOT NULL,
    "server_id" UUID NOT NULL,
    "seq" BIGINT NOT NULL,
    "sent_at" TIMESTAMPTZ(3),
    "received_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "agent_version" TEXT,
    "metrics" JSONB,

    CONSTRAINT "agent_heartbeats_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "server_capabilities" (
    "server_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "details" JSONB,
    "detected_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "server_capabilities_pkey" PRIMARY KEY ("server_id","name")
);

-- CreateTable
CREATE TABLE "ca_keys" (
    "id" UUID NOT NULL,
    "purpose" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'ECDSA-P256',
    "cert_pem" TEXT NOT NULL,
    "private_key_enc" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "not_after" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ca_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "jobs" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "params" JSONB NOT NULL DEFAULT '{}',
    "status" TEXT NOT NULL DEFAULT 'queued',
    "mutating" BOOLEAN NOT NULL,
    "resource_key" TEXT,
    "idempotency_key" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "lease_until" TIMESTAMPTZ(3),
    "lease_token_hash" TEXT,
    "leased_at" TIMESTAMPTZ(3),
    "started_at" TIMESTAMPTZ(3),
    "finished_at" TIMESTAMPTZ(3),
    "attempt" INTEGER NOT NULL DEFAULT 0,
    "desired_version" INTEGER,
    "actor_id" UUID,
    "correlation_id" TEXT NOT NULL,
    "result" JSONB,
    "error" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "jobs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "actor_id" TEXT,
    "actor_type" TEXT NOT NULL DEFAULT 'user',
    "action" TEXT NOT NULL,
    "target_type" TEXT,
    "target_id" TEXT,
    "result" TEXT NOT NULL,
    "request_id" TEXT,
    "diff_hash" TEXT,
    "metadata" JSONB,
    "ip" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_refresh_token_hash_key" ON "sessions"("refresh_token_hash");

-- CreateIndex
CREATE INDEX "sessions_family_id_idx" ON "sessions"("family_id");

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "mfa_factors_user_id_type_key" ON "mfa_factors"("user_id", "type");

-- CreateIndex
CREATE UNIQUE INDEX "recovery_codes_code_hash_key" ON "recovery_codes"("code_hash");

-- CreateIndex
CREATE INDEX "recovery_codes_user_id_idx" ON "recovery_codes"("user_id");

-- CreateIndex
CREATE INDEX "role_bindings_user_id_idx" ON "role_bindings"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "server_groups_name_key" ON "server_groups"("name");

-- CreateIndex
CREATE INDEX "servers_environment_idx" ON "servers"("environment");

-- CreateIndex
CREATE INDEX "servers_last_heartbeat_at_idx" ON "servers"("last_heartbeat_at");

-- CreateIndex
CREATE UNIQUE INDEX "server_addresses_server_id_address_source_key" ON "server_addresses"("server_id", "address", "source");

-- CreateIndex
CREATE UNIQUE INDEX "agent_enrollments_token_hash_key" ON "agent_enrollments"("token_hash");

-- CreateIndex
CREATE UNIQUE INDEX "agent_certificates_serial_key" ON "agent_certificates"("serial");

-- CreateIndex
CREATE INDEX "agent_certificates_server_id_idx" ON "agent_certificates"("server_id");

-- CreateIndex
CREATE INDEX "agent_heartbeats_server_id_received_at_idx" ON "agent_heartbeats"("server_id", "received_at" DESC);

-- CreateIndex
CREATE INDEX "ca_keys_purpose_active_idx" ON "ca_keys"("purpose", "active");

-- CreateIndex
CREATE INDEX "jobs_server_id_status_created_at_idx" ON "jobs"("server_id", "status", "created_at");

-- CreateIndex
CREATE INDEX "jobs_status_lease_until_idx" ON "jobs"("status", "lease_until");

-- CreateIndex
CREATE UNIQUE INDEX "jobs_server_id_idempotency_key_key" ON "jobs"("server_id", "idempotency_key");

-- CreateIndex
CREATE INDEX "audit_events_created_at_idx" ON "audit_events"("created_at");

-- CreateIndex
CREATE INDEX "audit_events_action_idx" ON "audit_events"("action");

-- CreateIndex
CREATE INDEX "audit_events_actor_id_idx" ON "audit_events"("actor_id");

-- CreateIndex
CREATE INDEX "audit_events_target_id_idx" ON "audit_events"("target_id");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mfa_factors" ADD CONSTRAINT "mfa_factors_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_bindings" ADD CONSTRAINT "role_bindings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "servers" ADD CONSTRAINT "servers_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "server_groups"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "server_addresses" ADD CONSTRAINT "server_addresses_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_certificates" ADD CONSTRAINT "agent_certificates_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_heartbeats" ADD CONSTRAINT "agent_heartbeats_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "server_capabilities" ADD CONSTRAINT "server_capabilities_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

-- Per-server+resource concurrency lock: at most one in-flight (leased/running)
-- mutating job per (server_id, resource_key). Enforced by the database.
CREATE UNIQUE INDEX "jobs_inflight_resource_lock"
  ON "jobs" ("server_id", "resource_key")
  WHERE "resource_key" IS NOT NULL AND "status" IN ('leased', 'running');

-- One binding per (user, role, scope); NULL scope ids compare equal.
CREATE UNIQUE INDEX "role_bindings_user_role_scope_key"
  ON "role_bindings" ("user_id", "role_key", "scope_type", "scope_id") NULLS NOT DISTINCT;

-- Data integrity checks for enum-like columns.
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_status_check"
  CHECK ("status" IN ('queued','leased','running','succeeded','failed','expired','cancelled'));
ALTER TABLE "servers" ADD CONSTRAINT "servers_status_check"
  CHECK ("status" IN ('enrolling','online','degraded','offline','stale','revoked'));
ALTER TABLE "servers" ADD CONSTRAINT "servers_environment_check"
  CHECK ("environment" IN ('production','uat','development'));
ALTER TABLE "role_bindings" ADD CONSTRAINT "role_bindings_scope_check"
  CHECK ("scope_type" IN ('global','environment','project','server')
         AND (("scope_type" = 'global') = ("scope_id" IS NULL)));
