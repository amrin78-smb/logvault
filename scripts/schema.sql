-- ============================================================
-- LogVault Database Schema
-- Standard PostgreSQL 16 (logvault database)
-- Run this as postgres superuser against the logvault database
-- ============================================================


-- ============================================================
-- CORE LOGS TABLE
-- Supported vendors: fortinet, cisco, paloalto, aruba, sangfor,
--                    forcepoint, checkpoint, juniper, windows, sonicwall, generic
--
-- Valid category values for syslog_entries.category:
--   authentication, vpn, firewall, interface, routing, configuration,
--   security, wireless, system, dns, web, email, dlp, network
-- (assigned by collector/taxonomy.js; 'network' is the fallback)
-- ============================================================
-- ------------------------------------------------------------
-- syslog_entries is TIME-PARTITIONED by RANGE (received_at) into daily
-- partitions (syslog_entries_pYYYYMMDD), managed by the partition functions
-- below and driven by scripts/cleanup.js (ensure ahead / drop old).
--
-- Partitioning notes for downstream workstreams (collector + API):
--   * Partition key (received_at) MUST be part of any PK/unique constraint,
--     so the primary key is the COMPOSITE (id, received_at). `id` is still
--     globally unique via the shared BIGSERIAL sequence.
--   * A standalone btree index on id alone keeps WHERE id = $1 lookups fast.
--   * A DEFAULT partition (syslog_entries_default) catches any row whose
--     received_at has no matching daily partition, so INSERTs never fail.
-- This CREATE TABLE is for FRESH installs only; converting an existing
-- populated table is done by scripts/migration-phase3-partitioning.sql.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS syslog_entries (
    id              BIGSERIAL,
    received_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    log_timestamp   TIMESTAMPTZ,                          -- timestamp from the log message itself
    source_ip       INET            NOT NULL,
    source_host     TEXT,                                  -- resolved hostname if available
    facility        SMALLINT,                              -- 0-23 syslog facility code
    severity        SMALLINT        NOT NULL DEFAULT 6,    -- 0=Emergency 7=Debug
    severity_label  TEXT,                                  -- 'emergency','alert','critical','error','warning','notice','info','debug'
    facility_label  TEXT,                                  -- 'kern','user','mail','daemon','auth','syslog',...
    vendor          TEXT            DEFAULT 'generic',     -- 'cisco','paloalto','fortinet','aruba','sangfor','generic'
    program         TEXT,                                  -- process/program name (syslog tag)
    pid             INTEGER,
    message         TEXT            NOT NULL,
    raw_message     TEXT,                                  -- original unprocessed syslog line
    structured_data JSONB,                                 -- RFC5424 SD-elements or vendor parsed fields
    is_parsed       BOOLEAN         DEFAULT FALSE,
    parser_version  TEXT,
    category        TEXT,                                  -- universal event taxonomy (auth, vpn, firewall, ...)
    risk_score      SMALLINT        DEFAULT 0,             -- 0-100 computed risk score
    prev_hash       BYTEA,                                 -- tamper-evidence: hash of previous entry (NULL for legacy)
    entry_hash      BYTEA,                                 -- tamper-evidence: hash of this entry (NULL for legacy)
    PRIMARY KEY (id, received_at)                          -- composite PK required for partition key
) PARTITION BY RANGE (received_at);

-- Universal taxonomy + risk scoring columns (idempotent for existing installs)
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS category   TEXT;
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS risk_score SMALLINT DEFAULT 0;

-- Tamper-evidence / integrity hash columns (idempotent for existing installs).
-- Written by the collector (separate workstream). Legacy rows stay NULL —
-- the hash chain starts fresh from the first row written after deployment.
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS prev_hash  BYTEA;
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS entry_hash BYTEA;

-- DEFAULT partition — safety net so an INSERT never fails when a daily
-- partition for received_at is missing (e.g. clock skew, late ensure run).
CREATE TABLE IF NOT EXISTS syslog_entries_default
  PARTITION OF syslog_entries DEFAULT;


-- Indexes for common query patterns.
-- NOTE: on a PARTITIONED parent, CREATE INDEX CONCURRENTLY is NOT allowed, so
-- every syslog_entries index is plain CREATE INDEX IF NOT EXISTS. These are
-- fast on fresh (empty) installs and propagate automatically to each partition.
-- (Existing live installs already have these indexes, so IF NOT EXISTS is a no-op.)

-- Standalone index on id for point lookups (WHERE id = $1) across partitions.
CREATE INDEX IF NOT EXISTS idx_syslog_id             ON syslog_entries (id);

CREATE INDEX IF NOT EXISTS idx_syslog_source_ip      ON syslog_entries (source_ip, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_severity       ON syslog_entries (severity, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_vendor         ON syslog_entries (vendor, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_source_host    ON syslog_entries (source_host, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_structured     ON syslog_entries USING GIN (structured_data);
CREATE INDEX IF NOT EXISTS idx_syslog_message        ON syslog_entries USING GIN (to_tsvector('english', message));
CREATE INDEX IF NOT EXISTS idx_syslog_received       ON syslog_entries (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_category       ON syslog_entries (category, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_risk_score     ON syslog_entries (risk_score DESC, received_at DESC);

-- Composite indexes for time-ordered dashboard stat queries (received_at DESC
-- leading column). Plain CREATE INDEX — CONCURRENTLY is not allowed on a
-- partitioned parent.
CREATE INDEX IF NOT EXISTS idx_syslog_received_vendor
  ON syslog_entries (received_at DESC, vendor);
CREATE INDEX IF NOT EXISTS idx_syslog_received_severity
  ON syslog_entries (received_at DESC, severity);
CREATE INDEX IF NOT EXISTS idx_syslog_received_category
  ON syslog_entries (received_at DESC, category);

-- Slow-query fixes (perf EXPLAIN audit). Plain CREATE INDEX on the partitioned
-- parent (CONCURRENTLY not allowed here); they cascade to every partition.

-- PROBLEM 1: /api/health/device-status (7-day aggregation) was scanning ~753K
-- rows via idx_syslog_source_ip when the real filter is received_at. Covering
-- index with received_at DESC as the leading column lets the aggregation seek
-- the 7-day window and read source_ip / source_host / vendor index-only.
CREATE INDEX IF NOT EXISTS idx_syslog_received_source
  ON syslog_entries (received_at DESC, source_ip, source_host, vendor);

-- PROBLEM 2: message ILIKE '%configured from%' (and other leading-wildcard
-- ILIKE/LIKE on message) cannot use a btree index. A GIN trigram index makes
-- substring ILIKE/LIKE on message fast.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_syslog_message_trgm
  ON syslog_entries USING GIN (message gin_trgm_ops);

-- PROBLEM 3: structured_data->>'subcategory' (MAC flap, config-change, STP, etc.)
-- had no index. Partial expression index over the non-null subcategory values.
CREATE INDEX IF NOT EXISTS idx_syslog_subcategory
  ON syslog_entries ((structured_data->>'subcategory'))
  WHERE structured_data->>'subcategory' IS NOT NULL;


-- ============================================================
-- DAILY PARTITION MANAGEMENT (SECURITY DEFINER)
-- These run as the function owner (postgres) so logvault_user can create/drop
-- partitions even after UPDATE/DELETE on syslog_entries is revoked from it.
-- Driven by scripts/cleanup.js on a schedule. Safe on a fresh/empty DB.
-- Daily partition naming convention: syslog_entries_pYYYYMMDD
-- ============================================================

-- Create daily partitions for today .. today+days_ahead (idempotent). Returns count created.
CREATE OR REPLACE FUNCTION ensure_syslog_partitions(days_ahead integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $func$
DECLARE
    d            date;
    part_name    text;
    created_cnt  integer := 0;
BEGIN
    IF days_ahead IS NULL OR days_ahead < 0 THEN
        days_ahead := 0;
    END IF;

    FOR d IN
        SELECT (current_date + g) FROM generate_series(0, days_ahead) AS g
    LOOP
        part_name := 'syslog_entries_p' || to_char(d, 'YYYYMMDD');
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = part_name
        ) THEN
            BEGIN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF syslog_entries FOR VALUES FROM (%L) TO (%L)',
                    part_name, d::text, (d + 1)::text
                );
                created_cnt := created_cnt + 1;
            EXCEPTION WHEN others THEN
                -- A daily partition can overlap a legacy partition (e.g. right
                -- after the Phase 3 migration, when the legacy partition still
                -- covers the migration day). Skip rather than abort the call.
                RAISE NOTICE 'Skipped partition % (%)', part_name, SQLERRM;
            END;
        END IF;
    END LOOP;

    RETURN created_cnt;
END;
$func$;

-- Drop daily partitions older than (current_date - retention_days). Returns count dropped.
-- Only drops dated syslog_entries_pYYYYMMDD partitions — NEVER the DEFAULT partition.
CREATE OR REPLACE FUNCTION drop_old_syslog_partitions(retention_days integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $func$
DECLARE
    rec          record;
    part_date    date;
    cutoff       date;
    dropped_cnt  integer := 0;
BEGIN
    IF retention_days IS NULL OR retention_days < 0 THEN
        retention_days := 30;
    END IF;
    cutoff := current_date - retention_days;

    FOR rec IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c       ON c.oid = i.inhrelid
        JOIN pg_class parent  ON parent.oid = i.inhparent
        WHERE parent.relname = 'syslog_entries'
          AND c.relname ~ '^syslog_entries_p[0-9]{8}$'
    LOOP
        -- Parse YYYYMMDD out of the partition name (skips the DEFAULT partition,
        -- which does not match the regex above).
        BEGIN
            part_date := to_date(right(rec.relname, 8), 'YYYYMMDD');
        EXCEPTION WHEN others THEN
            CONTINUE;
        END;

        IF part_date < cutoff THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', rec.relname);
            dropped_cnt := dropped_cnt + 1;
        END IF;
    END LOOP;

    RETURN dropped_cnt;
END;
$func$;

-- Allow the app role to invoke partition management (functions run as owner).
GRANT EXECUTE ON FUNCTION ensure_syslog_partitions(integer)   TO logvault_user;
GRANT EXECUTE ON FUNCTION drop_old_syslog_partitions(integer) TO logvault_user;







-- ============================================================
-- ALERT RULES TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS alert_rules (
    id              SERIAL PRIMARY KEY,
    name            TEXT            NOT NULL,
    description     TEXT,
    is_enabled      BOOLEAN         DEFAULT TRUE,
    match_severity  SMALLINT[],                            -- e.g. ARRAY[0,1,2] = Emergency/Alert/Critical
    match_vendor    TEXT[],                                -- e.g. ARRAY['fortinet','cisco'] or NULL=all
    match_host      TEXT,                                  -- ILIKE pattern or NULL=all
    match_pattern   TEXT,                                  -- regex pattern on message field
    threshold_count INTEGER         DEFAULT 1,             -- how many hits before firing
    threshold_window INTERVAL       DEFAULT '5 minutes',
    notify_email    TEXT,
    created_at      TIMESTAMPTZ     DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- MITRE ATT&CK techniques mapped to this rule (technique-level IDs, e.g. {T1110}).
-- Additive + idempotent. Covers BOTH user threshold rules and the auto-created
-- correlation rules — correlationEngine.js writes each rule's static technique
-- array here on first fire (and keeps it in sync). Operational correlation rules
-- (interface flap / loop / STP) intentionally store an empty array (no technique).
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[];

-- ============================================================
-- ALERT EVENTS TABLE (fired alerts)
-- ============================================================
CREATE TABLE IF NOT EXISTS alert_events (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         INTEGER         REFERENCES alert_rules(id) ON DELETE CASCADE,
    fired_at        TIMESTAMPTZ     DEFAULT NOW(),
    source_host     TEXT,
    source_ip       INET,
    match_count     INTEGER,
    sample_message  TEXT,
    acknowledged    BOOLEAN         DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT
);

-- Indexes for alert_events (Tier 1 perf migration).
-- The collector runs a dedup SELECT on every alert match; the dashboard runs
-- COUNT / recent-unacked / RBAC queries constantly. This table only grows.
-- Plain (non-CONCURRENT) here so a fresh install builds them in one pass;
-- on a live install with data, use scripts/migration-tier1-alert-events-indexes.sql
-- (CONCURRENTLY) instead to avoid locking.
CREATE INDEX IF NOT EXISTS idx_alert_events_open_dedup
  ON alert_events (rule_id, source_ip, fired_at DESC) WHERE acknowledged = FALSE;
CREATE INDEX IF NOT EXISTS idx_alert_events_ack_fired
  ON alert_events (acknowledged, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_events_source_ip
  ON alert_events (source_ip);

-- ============================================================
-- KNOWN HOSTS TABLE (for hostname resolution cache)
-- ============================================================
CREATE TABLE IF NOT EXISTS known_hosts (
    ip_address      INET            PRIMARY KEY,
    hostname        TEXT,
    vendor          TEXT,
    description     TEXT,
    last_seen       TIMESTAMPTZ     DEFAULT NOW(),
    created_at      TIMESTAMPTZ     DEFAULT NOW()
);

-- ============================================================
-- SEED: DEFAULT ALERT RULES
-- ============================================================
-- De-duplicate first. Historically this seed used `ON CONFLICT DO NOTHING` but
-- alert_rules had no UNIQUE(name), so the no-op conflict never triggered and every
-- deploy re-inserted the three default rules — accumulating dozens of duplicates
-- (each firing its own copy of every alert). The block below repoints fired alerts
-- onto the lowest-id rule of each name (alert_events.rule_id is ON DELETE CASCADE,
-- so we must re-parent BEFORE deleting to avoid dropping history), removes the
-- duplicate rules, then adds the UNIQUE(name) constraint so the seed can never
-- duplicate again. All steps are idempotent (no-ops once the DB is clean).
UPDATE alert_events ae
SET rule_id = canon.keep_id
FROM (SELECT id, MIN(id) OVER (PARTITION BY name) AS keep_id FROM alert_rules) canon
WHERE ae.rule_id = canon.id AND canon.id <> canon.keep_id;

DELETE FROM alert_rules a
USING (SELECT name, MIN(id) AS keep_id FROM alert_rules GROUP BY name) k
WHERE a.name = k.name AND a.id <> k.keep_id;

DO $$ BEGIN
  ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_name_key UNIQUE (name);
EXCEPTION WHEN duplicate_table OR duplicate_object THEN NULL;
END $$;

INSERT INTO alert_rules (name, description, match_severity, match_pattern, threshold_count, threshold_window)
VALUES
    ('Emergency Events',    'Any emergency-level syslog event',            ARRAY[0],       NULL, 1,  '1 minute'),
    ('Critical Threshold',  'Critical severity events from any device',     ARRAY[0,1,2],   NULL, 5,  '5 minutes'),
    ('Auth Failures',       'Repeated authentication failure messages',     NULL,
        'login fail|authentication fail|failed login|failed authentication|ssl-login-fail|logon fail', 10, '5 minutes')
ON CONFLICT (name) DO NOTHING;

-- Scope the (previously unfiltered) Auth Failures rule to real auth-failure
-- messages. Without a match_pattern it fired on ANY events — e.g. IPsec phase-1
-- negotiation noise — which contradicted the (correctly empty) Security > Auth
-- Failures tab. Only set it when still NULL so an operator's customisation sticks.
UPDATE alert_rules
SET match_pattern = 'login fail|authentication fail|failed login|failed authentication|ssl-login-fail|logon fail',
    updated_at = NOW()
WHERE name = 'Auth Failures' AND match_pattern IS NULL;

-- Remove historical FALSE-POSITIVE "Auth Failures" alerts created while the rule
-- was unfiltered — it fired on ordinary traffic (e.g. action=ip-conn "Connection
-- Failed", DNS) and IPsec negotiation, none of which are authentication failures.
-- Only rows whose message is NOT a genuine auth failure are removed, so any real
-- auth-failure alerts are always preserved. Idempotent: once the rule is scoped
-- (above), no new such rows are created, so subsequent runs match nothing.
DELETE FROM alert_events ae
USING alert_rules ar
WHERE ae.rule_id = ar.id
  AND ar.name = 'Auth Failures'
  AND (ae.sample_message IS NULL
       OR ae.sample_message !~* 'login fail|authentication fail|failed login|failed authentication|ssl-login-fail|logon fail');

-- ============================================================
-- USEFUL VIEWS
-- ============================================================

-- Current top talkers (last 24h)
CREATE OR REPLACE VIEW v_top_talkers_24h AS
SELECT
    COALESCE(source_host, source_ip::TEXT) AS host,
    source_ip,
    vendor,
    COUNT(*)        AS log_count,
    MAX(received_at) AS last_seen
FROM syslog_entries
WHERE received_at > NOW() - INTERVAL '24 hours'
GROUP BY source_host, source_ip, vendor
ORDER BY log_count DESC
LIMIT 20;

-- Severity distribution (last 24h)
CREATE OR REPLACE VIEW v_severity_distribution_24h AS
SELECT
    severity,
    severity_label,
    COUNT(*) AS log_count
FROM syslog_entries
WHERE received_at > NOW() - INTERVAL '24 hours'
GROUP BY severity, severity_label
ORDER BY severity;

-- Recent critical/error events
CREATE OR REPLACE VIEW v_recent_critical AS
SELECT
    received_at,
    source_host,
    source_ip,
    severity_label,
    vendor,
    message
FROM syslog_entries
WHERE severity <= 3
  AND received_at > NOW() - INTERVAL '24 hours'
ORDER BY received_at DESC
LIMIT 100;

-- ── App Settings (branding) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO app_settings (key, value) VALUES
  ('app_name',      'LogVault'),
  ('app_subtitle',  'Syslog & Log Analysis'),
  ('primary_color', '#C8102E'),
  ('sidebar_color', '#1a2744'),
  ('logo_url',      '')
ON CONFLICT (key) DO NOTHING;

-- ── NetVault asset enrichment columns ────────────────────────
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS site_name        TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS brand            TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS model            TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS device_status    TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS lifecycle_status TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS netvault_id      TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS synced_from_nv   BOOLEAN DEFAULT FALSE;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS last_synced      TIMESTAMPTZ;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS site_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_known_hosts_site_id ON known_hosts (site_id);

-- ── GeoIP / threat-intel enrichment columns ──────────────────
-- Populated by the collector's enrichment pass (GeoIP lookup + AbuseIPDB).
-- Known-bad = is_known_bad = TRUE OR abuse_score >= 50.
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS country_code  TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS country_name  TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS city          TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS asn           TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS asn_org       TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS is_external   BOOLEAN DEFAULT FALSE;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS abuse_score   SMALLINT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS is_known_bad  BOOLEAN DEFAULT FALSE;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS threat_tags   TEXT[];
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS last_enriched TIMESTAMPTZ;

-- RBAC: site filtering uses known_hosts.site_id (int) matching
--       NetVault user_sites.site_id. No additional LogVault tables needed —
--       roles and user→site assignments live in the NetVault DB.

-- GeoIP / threat-intel enrichment settings
INSERT INTO app_settings (key, value) VALUES ('abuseipdb_api_key', '') ON CONFLICT (key) DO NOTHING;

-- DNS lookup settings
INSERT INTO app_settings (key, value) VALUES ('dns_server', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('dns_lookup_enabled', 'true') ON CONFLICT (key) DO NOTHING;

-- SMTP / email alerting settings
INSERT INTO app_settings (key, value) VALUES ('smtp_host', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('smtp_port', '587') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('smtp_user', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('smtp_pass', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('smtp_from', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('smtp_enabled', 'false') ON CONFLICT (key) DO NOTHING;

-- Email notification preferences (granular alert email controls)
INSERT INTO app_settings (key, value) VALUES ('email_notify_enabled', 'true') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_severities', '["0","1","2","3"]') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_categories', '[]') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_vendors', '[]') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_min_risk', '40') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_digest_mode', 'instant') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_digest_hour', '8') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_recipients', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('email_notify_cooldown_mins', '30') ON CONFLICT (key) DO NOTHING;

-- Collector ingestion guard (allow-list + rate limit) — DEFAULT PERMISSIVE
-- collector_allowed_sources: comma-separated IPs/CIDRs; '' = allow ALL sources
-- collector_rate_limit_enabled: 'true' to enable per-source-IP rate limiting
-- collector_rate_limit_pps: max packets/sec per source IP; '0' = unlimited
INSERT INTO app_settings (key, value) VALUES ('collector_allowed_sources', '') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('collector_rate_limit_enabled', 'false') ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES ('collector_rate_limit_pps', '0') ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- AUDIT LOG TABLE (append-only security audit trail)
-- Records sensitive API actions (settings.update, logs.export,
-- alert.acknowledge, hosts.sync_netvault, system.update, ...).
-- Written + read by the API (api/auditLog.js); never updated or
-- deleted by the app (see REVOKE below). detail holds small
-- structured context only — NEVER secrets/full payloads.
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
  id            BIGSERIAL PRIMARY KEY,
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_user_id TEXT,             -- req.rbac.userId (NetVault user id as text), null if unknown
  actor_role    TEXT,
  action        TEXT NOT NULL,    -- e.g. 'settings.update','logs.export','alert.acknowledge','hosts.sync','system.update'
  target        TEXT,             -- optional object/identifier acted on
  detail        JSONB,            -- small structured context (NOT full payloads/secrets)
  source_ip     TEXT,             -- client IP if available
  result        TEXT              -- 'success' | 'error'
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_log (actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log (action, occurred_at DESC);

-- Grant permissions to logvault_user
GRANT ALL ON ALL TABLES IN SCHEMA public TO logvault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO logvault_user;

-- Audit log is append-only: the API inserts and reads rows but must never
-- update or delete them. Revoke those after the blanket GRANT ALL above
-- (order matters — this runs after the GRANT). INSERT + SELECT remain.
REVOKE UPDATE, DELETE ON audit_log FROM logvault_user;

-- ── Tamper prevention ────────────────────────────────────────
-- Logs are append-only for the app role: the collector INSERTs and the API
-- only SELECTs, so revoke UPDATE/DELETE on syslog_entries from logvault_user.
-- Row deletion for retention now happens via partition DROP (the SECURITY
-- DEFINER functions above run as the table owner, not as logvault_user).
-- The REVOKE cascades to every existing/future partition automatically.
REVOKE UPDATE, DELETE ON syslog_entries FROM logvault_user;

-- Note: alert_events is intentionally left writable — the API legitimately
-- UPDATEs it for acknowledgements. Only syslog_entries + audit_log are
-- locked down to append-only.

-- ============================================================
-- PHASE 2 — BEHAVIORAL BASELINING / ANOMALY DETECTION / UEBA
-- (on-prem intelligence engine — pure SQL/JS, no external calls)
-- Written by collector/analytics/{baselineBuilder,anomalyDetector,uebaRollup}.js.
-- All idempotent (CREATE TABLE IF NOT EXISTS) — this file is auto-applied on deploy.
-- ============================================================

-- Per-entity hour×day-of-week event-volume baselines.
-- entity_type is 'device' (entity_value = source_host || source_ip::text) or
-- 'user' (entity_value = structured_data->>'user'). avg/stddev are the AVG and
-- STDDEV_SAMP of per-hour event counts over the trailing baseline window.
CREATE TABLE IF NOT EXISTS entity_baselines (
  entity_type   TEXT        NOT NULL,
  entity_value  TEXT        NOT NULL,
  dow           SMALLINT    NOT NULL,             -- 0=Sunday .. 6=Saturday (EXTRACT(DOW))
  hour          SMALLINT    NOT NULL,             -- 0..23 (EXTRACT(HOUR))
  avg_count     REAL,
  stddev_count  REAL,
  sample_count  INT,
  updated_at    TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (entity_type, entity_value, dow, hour)
);

-- Detected behavioral / security anomalies (volume spikes, silent entities,
-- new geo, new service). Written by the anomaly detector with 1-hour dedup.
CREATE TABLE IF NOT EXISTS anomaly_events (
  id              BIGSERIAL PRIMARY KEY,
  detected_at     TIMESTAMPTZ DEFAULT NOW(),
  entity_type     TEXT,
  entity_value    TEXT,
  source_ip       INET,                            -- the entity's IP for device/IP entities; NULL for users
  anomaly_type    TEXT,                            -- 'volume_spike','silent','new_geo','new_service'
  severity        TEXT,                            -- 'info','warning','critical'
  score           REAL,
  title           TEXT,
  detail          JSONB,
  acknowledged    BOOLEAN     DEFAULT FALSE,
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_detected ON anomaly_events (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_ack      ON anomaly_events (acknowledged);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_entity   ON anomaly_events (entity_value);

-- Rolling per-entity UEBA risk (0-100, EWMA-smoothed). One row per entity.
-- factors is a jsonb array of {label, contribution} explaining the score.
CREATE TABLE IF NOT EXISTS entity_risk (
  entity_type   TEXT        NOT NULL,
  entity_value  TEXT        NOT NULL,
  source_ip     INET,
  risk_score    REAL,
  factors       JSONB,
  event_count   INT,
  anomaly_count INT,
  last_activity TIMESTAMPTZ,
  updated_at    TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (entity_type, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_entity_risk_score ON entity_risk (risk_score DESC);

-- Re-grant so the app role owns the new Phase 2 tables/sequences on existing
-- installs (idempotent; harmless on fresh installs where the GRANT ran above).
GRANT ALL ON ALL TABLES IN SCHEMA public TO logvault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO logvault_user;
