-- ============================================================
-- LogVault — Phase 3 HOTFIX: integrity columns + audit_log only
-- ============================================================
-- For an EXISTING install that received the new collector/API code BEFORE the
-- full partition migration was run, so the live DB is missing the new objects.
-- This unblocks:
--   * collector flush errors  -> INSERT references prev_hash/entry_hash
--   * audit-write errors       -> api/auditLog.js INSERTs into audit_log
--
-- Idempotent + non-destructive. Does NOT partition syslog_entries (run
-- scripts/migration-phase3-partitioning.sql later for that). Run as postgres:
--   psql -U postgres -d logvault -f scripts/hotfix-phase3-columns.sql
-- ============================================================

-- 1. Integrity hash-chain columns the collector writes (nullable; legacy NULL).
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS prev_hash  BYTEA;
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS entry_hash BYTEA;

-- 2. Append-only audit trail the API writes to.
CREATE TABLE IF NOT EXISTS audit_log (
  id            BIGSERIAL PRIMARY KEY,
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_user_id TEXT,
  actor_role    TEXT,
  action        TEXT NOT NULL,
  target        TEXT,
  detail        JSONB,
  source_ip     TEXT,
  result        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_log (actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log (action, occurred_at DESC);

GRANT ALL ON audit_log TO logvault_user;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO logvault_user;
REVOKE UPDATE, DELETE ON audit_log FROM logvault_user;

-- Note: LOG_INTEGRITY_KEY env loading is already correct in code
-- (collector.js + verify-integrity.js both load dotenv before reading it).
-- If the hash chain is "disabled", set LOG_INTEGRITY_KEY in the collector's
-- NSSM AppEnvironmentExtra — that is a config gap, not a code change.
