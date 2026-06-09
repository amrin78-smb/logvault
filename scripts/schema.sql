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
CREATE TABLE IF NOT EXISTS syslog_entries (
    id              BIGSERIAL PRIMARY KEY,
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
    risk_score      SMALLINT        DEFAULT 0              -- 0-100 computed risk score
);

-- Universal taxonomy + risk scoring columns (idempotent for existing installs)
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS category   TEXT;
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS risk_score SMALLINT DEFAULT 0;


-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_syslog_source_ip      ON syslog_entries (source_ip, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_severity       ON syslog_entries (severity, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_vendor         ON syslog_entries (vendor, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_source_host    ON syslog_entries (source_host, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_structured     ON syslog_entries USING GIN (structured_data);
CREATE INDEX IF NOT EXISTS idx_syslog_message        ON syslog_entries USING GIN (to_tsvector('english', message));
CREATE INDEX IF NOT EXISTS idx_syslog_received       ON syslog_entries (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_category       ON syslog_entries (category, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_risk_score     ON syslog_entries (risk_score DESC, received_at DESC);

-- Composite indexes for time-ordered dashboard stat queries (received_at DESC leading
-- column). Created CONCURRENTLY on the live server to avoid locking the large table;
-- run these manually (CONCURRENTLY cannot run inside a transaction block).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_syslog_received_vendor
  ON syslog_entries (received_at DESC, vendor);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_syslog_received_severity
  ON syslog_entries (received_at DESC, severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_syslog_received_category
  ON syslog_entries (received_at DESC, category);

-- Slow-query fixes (perf EXPLAIN audit). All CONCURRENTLY — run one at a time
-- on the live server, never inside a transaction block.

-- PROBLEM 1: /api/health/device-status (7-day aggregation) was scanning ~753K
-- rows via idx_syslog_source_ip when the real filter is received_at. Covering
-- index with received_at DESC as the leading column lets the aggregation seek
-- the 7-day window and read source_ip / source_host / vendor index-only.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_syslog_received_source
  ON syslog_entries (received_at DESC, source_ip, source_host, vendor);

-- PROBLEM 2: message ILIKE '%configured from%' (and other leading-wildcard
-- ILIKE/LIKE on message) cannot use a btree index. A GIN trigram index makes
-- substring ILIKE/LIKE on message fast.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_syslog_message_trgm
  ON syslog_entries USING GIN (message gin_trgm_ops);

-- PROBLEM 3: structured_data->>'subcategory' (MAC flap, config-change, STP, etc.)
-- had no index. Partial expression index over the non-null subcategory values.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_syslog_subcategory
  ON syslog_entries ((structured_data->>'subcategory'))
  WHERE structured_data->>'subcategory' IS NOT NULL;







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
INSERT INTO alert_rules (name, description, match_severity, threshold_count, threshold_window)
VALUES
    ('Emergency Events',    'Any emergency-level syslog event',            ARRAY[0],       1,  '1 minute'),
    ('Critical Threshold',  'Critical severity events from any device',     ARRAY[0,1,2],   5,  '5 minutes'),
    ('Auth Failures',       'Repeated authentication failure messages',     NULL,           10, '5 minutes')
ON CONFLICT DO NOTHING;

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

-- RBAC: site filtering uses known_hosts.site_id (int) matching
--       NetVault user_sites.site_id. No additional LogVault tables needed —
--       roles and user→site assignments live in the NetVault DB.

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

-- Grant permissions to logvault_user
GRANT ALL ON ALL TABLES IN SCHEMA public TO logvault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO logvault_user;
