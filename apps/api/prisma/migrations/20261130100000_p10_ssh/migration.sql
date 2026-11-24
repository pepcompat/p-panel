-- P10 central SSH gateway: credentials, endpoints, key deployments, host keys, grants, sessions.
-- Expand-only (new tables + nullable servers.ssh_facts). Generated part: `prisma migrate diff`;
-- hand-written CHECK constraints below. Rollback: DROP the six ssh_* tables and servers.ssh_facts.

-- AlterTable
ALTER TABLE "servers" ADD COLUMN     "ssh_facts" JSONB;

-- CreateTable
CREATE TABLE "ssh_credentials" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "fingerprint_sha256" TEXT NOT NULL,
    "private_key_enc" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "rotated_from_id" UUID,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_by" UUID,

    CONSTRAINT "ssh_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ssh_endpoints" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "path" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "port" INTEGER NOT NULL DEFAULT 22,
    "allowed_users" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "ssh_endpoints_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ssh_key_deployments" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "credential_id" UUID NOT NULL,
    "ssh_user" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "job_id" UUID,
    "last_error" TEXT,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "ssh_key_deployments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ssh_host_keys" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "endpoint_id" UUID NOT NULL,
    "algorithm" TEXT NOT NULL,
    "fingerprint_sha256" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "seen_via" TEXT NOT NULL,
    "agent_match" BOOLEAN,
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "trusted_by" UUID,
    "trusted_at" TIMESTAMPTZ(3),

    CONSTRAINT "ssh_host_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ssh_access_grants" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "ssh_user" TEXT NOT NULL,
    "endpoint_path" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "duration_min" INTEGER NOT NULL,
    "status" TEXT NOT NULL,
    "grant_hash" TEXT NOT NULL,
    "requested_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "approved_by" UUID,
    "approved_at" TIMESTAMPTZ(3),
    "starts_at" TIMESTAMPTZ(3),
    "expires_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_by" UUID,

    CONSTRAINT "ssh_access_grants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ssh_sessions" (
    "id" UUID NOT NULL,
    "grant_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "ssh_user" TEXT NOT NULL,
    "endpoint_path" TEXT NOT NULL,
    "endpoint_host" TEXT NOT NULL,
    "endpoint_port" INTEGER NOT NULL,
    "credential_fingerprint" TEXT NOT NULL,
    "host_key_fingerprint" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "end_reason" TEXT,
    "exit_code" INTEGER,
    "client_ip" TEXT,
    "user_agent" TEXT,
    "bytes_in" BIGINT NOT NULL DEFAULT 0,
    "bytes_out" BIGINT NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "opened_at" TIMESTAMPTZ(3),
    "closed_at" TIMESTAMPTZ(3),
    "ticket_hash" TEXT,
    "ticket_expires_at" TIMESTAMPTZ(3),

    CONSTRAINT "ssh_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ssh_credentials_fingerprint_sha256_key" ON "ssh_credentials"("fingerprint_sha256");

-- CreateIndex
CREATE INDEX "ssh_credentials_status_idx" ON "ssh_credentials"("status");

-- CreateIndex
CREATE UNIQUE INDEX "ssh_endpoints_server_id_path_key" ON "ssh_endpoints"("server_id", "path");

-- CreateIndex
CREATE INDEX "ssh_key_deployments_credential_id_idx" ON "ssh_key_deployments"("credential_id");

-- CreateIndex
CREATE INDEX "ssh_key_deployments_job_id_idx" ON "ssh_key_deployments"("job_id");

-- CreateIndex
CREATE UNIQUE INDEX "ssh_key_deployments_server_id_credential_id_ssh_user_key" ON "ssh_key_deployments"("server_id", "credential_id", "ssh_user");

-- CreateIndex
CREATE INDEX "ssh_host_keys_server_id_idx" ON "ssh_host_keys"("server_id");

-- CreateIndex
CREATE UNIQUE INDEX "ssh_host_keys_endpoint_id_fingerprint_sha256_key" ON "ssh_host_keys"("endpoint_id", "fingerprint_sha256");

-- CreateIndex
CREATE INDEX "ssh_access_grants_user_id_status_idx" ON "ssh_access_grants"("user_id", "status");

-- CreateIndex
CREATE INDEX "ssh_access_grants_server_id_status_idx" ON "ssh_access_grants"("server_id", "status");

-- CreateIndex
CREATE INDEX "ssh_access_grants_status_expires_at_idx" ON "ssh_access_grants"("status", "expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "ssh_sessions_ticket_hash_key" ON "ssh_sessions"("ticket_hash");

-- CreateIndex
CREATE INDEX "ssh_sessions_user_id_status_idx" ON "ssh_sessions"("user_id", "status");

-- CreateIndex
CREATE INDEX "ssh_sessions_server_id_status_idx" ON "ssh_sessions"("server_id", "status");

-- CreateIndex
CREATE INDEX "ssh_sessions_grant_id_idx" ON "ssh_sessions"("grant_id");

-- CreateIndex
CREATE INDEX "ssh_sessions_status_idx" ON "ssh_sessions"("status");

-- AddForeignKey
ALTER TABLE "ssh_endpoints" ADD CONSTRAINT "ssh_endpoints_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_key_deployments" ADD CONSTRAINT "ssh_key_deployments_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_key_deployments" ADD CONSTRAINT "ssh_key_deployments_credential_id_fkey" FOREIGN KEY ("credential_id") REFERENCES "ssh_credentials"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_host_keys" ADD CONSTRAINT "ssh_host_keys_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_host_keys" ADD CONSTRAINT "ssh_host_keys_endpoint_id_fkey" FOREIGN KEY ("endpoint_id") REFERENCES "ssh_endpoints"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_access_grants" ADD CONSTRAINT "ssh_access_grants_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_sessions" ADD CONSTRAINT "ssh_sessions_grant_id_fkey" FOREIGN KEY ("grant_id") REFERENCES "ssh_access_grants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ssh_sessions" ADD CONSTRAINT "ssh_sessions_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------
ALTER TABLE "ssh_credentials" ADD CONSTRAINT "ssh_credentials_kind_check"
  CHECK ("kind" IN ('generated','imported'));
ALTER TABLE "ssh_credentials" ADD CONSTRAINT "ssh_credentials_algorithm_check"
  CHECK ("algorithm" IN ('ssh-ed25519','rsa-sha2-512','ecdsa-sha2-nistp256'));
ALTER TABLE "ssh_credentials" ADD CONSTRAINT "ssh_credentials_status_check"
  CHECK ("status" IN ('active','rotated','revoked'));
-- the encrypted envelope format of common/crypto.ts (never plaintext key material)
ALTER TABLE "ssh_credentials" ADD CONSTRAINT "ssh_credentials_private_key_enc_check"
  CHECK ("private_key_enc" LIKE 'v1.%' AND "private_key_enc" NOT LIKE '%PRIVATE KEY%');
ALTER TABLE "ssh_endpoints" ADD CONSTRAINT "ssh_endpoints_path_check"
  CHECK ("path" IN ('private','public'));
ALTER TABLE "ssh_endpoints" ADD CONSTRAINT "ssh_endpoints_port_check"
  CHECK ("port" BETWEEN 1 AND 65535);
ALTER TABLE "ssh_endpoints" ADD CONSTRAINT "ssh_endpoints_no_root_check"
  CHECK (NOT ('root' = ANY ("allowed_users")));
ALTER TABLE "ssh_key_deployments" ADD CONSTRAINT "ssh_key_deployments_status_check"
  CHECK ("status" IN ('pending','installed','removing','removed','failed'));
ALTER TABLE "ssh_host_keys" ADD CONSTRAINT "ssh_host_keys_status_check"
  CHECK ("status" IN ('pending','trusted','rejected','superseded'));
ALTER TABLE "ssh_host_keys" ADD CONSTRAINT "ssh_host_keys_seen_via_check"
  CHECK ("seen_via" IN ('scan','connect'));
ALTER TABLE "ssh_access_grants" ADD CONSTRAINT "ssh_access_grants_status_check"
  CHECK ("status" IN ('awaiting_approval','active','expired','revoked','rejected'));
ALTER TABLE "ssh_access_grants" ADD CONSTRAINT "ssh_access_grants_endpoint_path_check"
  CHECK ("endpoint_path" IN ('private','public'));
ALTER TABLE "ssh_access_grants" ADD CONSTRAINT "ssh_access_grants_duration_check"
  CHECK ("duration_min" BETWEEN 15 AND 480);
ALTER TABLE "ssh_sessions" ADD CONSTRAINT "ssh_sessions_status_check"
  CHECK ("status" IN ('pending','open','closed','failed'));
ALTER TABLE "ssh_sessions" ADD CONSTRAINT "ssh_sessions_end_reason_check"
  CHECK ("end_reason" IS NULL OR "end_reason" IN ('client_closed','server_closed','idle_timeout',
    'max_duration','grant_expired','grant_revoked','credential_revoked','host_key_mismatch',
    'auth_failed','connect_failed','center_shutdown','center_restart','limit','terminated'));
-- at most one trusted host key per endpoint + algorithm
CREATE UNIQUE INDEX "ssh_host_keys_one_trusted_idx" ON "ssh_host_keys"("endpoint_id", "algorithm")
  WHERE "status" = 'trusted';
