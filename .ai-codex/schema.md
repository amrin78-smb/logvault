# LogVault Database Schema

Raw PostgreSQL 16, `scripts/schema.sql` — idempotent (CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN IF NOT EXISTS throughout), auto-applied on every deploy. NOT Prisma. Columns added later via ALTER (not in the original CREATE TABLE block) are marked `[ALTER]` below — the CREATE TABLE block alone is NOT the full current schema for `syslog_entries` and `known_hosts`.

## Core

syslog_entries  id(PK,BIGSERIAL+received_at composite) | received_at(TIMESTAMPTZ,NOT NULL,partition key) | log_timestamp(TIMESTAMPTZ) | source_ip(INET,NOT NULL) | source_host(TEXT) | facility(SMALLINT) | severity(SMALLINT,NOT NULL,default 6) | severity_label(TEXT) | facility_label(TEXT) | vendor(TEXT,default 'generic') | program(TEXT) | pid(INTEGER) | message(TEXT,NOT NULL) | raw_message(TEXT) | structured_data(JSONB) | is_parsed(BOOLEAN) | parser_version(TEXT) | category(TEXT) | risk_score(SMALLINT,default 0) | prev_hash(BYTEA) | entry_hash(BYTEA) | srcip(TEXT) [ALTER, perf-pass indexed column, COALESCE(structured_data.srcip, source_ip)]
  — PARTITIONED BY RANGE(received_at), daily partitions `syslog_entries_pYYYYMMDD` + `syslog_entries_default` catch-all. UPDATE/DELETE REVOKEd from logvault_user (append-only, tamper-evidence via prev_hash/entry_hash chain). Retention via partition DROP (ensure_syslog_partitions/drop_old_syslog_partitions SECURITY DEFINER functions, driven by scripts/cleanup.js).

known_hosts  ip_address(PK,INET) | hostname(TEXT) | vendor(TEXT) | description(TEXT) | last_seen(TIMESTAMPTZ) | created_at(TIMESTAMPTZ) | site_name(TEXT)[ALTER] | brand(TEXT)[ALTER] | model(TEXT)[ALTER] | device_status(TEXT)[ALTER] | lifecycle_status(TEXT)[ALTER] | netvault_id(TEXT)[ALTER] | synced_from_nv(BOOLEAN)[ALTER] | last_synced(TIMESTAMPTZ)[ALTER] | site_id(INTEGER)[ALTER, FK->NetVault sites, no local FK constraint — cross-DB] | country_code/country_name/city/asn/asn_org(TEXT)[ALTER, GeoIP] | is_external(BOOLEAN)[ALTER] | abuse_score(SMALLINT)[ALTER] | is_known_bad(BOOLEAN)[ALTER] | threat_tags(TEXT[])[ALTER] | last_enriched(TIMESTAMPTZ)[ALTER]
  — known-bad = is_known_bad=TRUE OR abuse_score>=50. site_id matches NetVault's user_sites.site_id (cross-DB, no FK).

## Hourly rollup tables (perf pass, Phase 1-4, 2026-07) — recompute-window model, NOT increment-on-insert

syslog_stats_rollup  hour_bucket(TIMESTAMPTZ) | severity(SMALLINT) | severity_label(TEXT) | category(TEXT) | vendor(TEXT) | site_id(INTEGER,nullable) | log_count(BIGINT) — no PK (nullable site_id), COALESCE-wrapped UNIQUE INDEX instead
syslog_talker_rollup  hour_bucket | srcip(TEXT,NOT NULL) | vendor | site_id | log_count — top-talkers (source IP)
syslog_security_event_rollup  hour_bucket | event_type(TEXT,NOT NULL) | site_id | log_count — pre-filtered severity<=4
syslog_dest_event_rollup  hour_bucket | event_class(TEXT,'blocked'|'failure') | dstip(TEXT,NOT NULL) | service(TEXT,default '') | vendor | site_id | log_count
syslog_vpn_rollup  hour_bucket | site_id | total(BIGINT) | failures(BIGINT) | successes(BIGINT) | ssl_alerts(BIGINT) — 4 independent FILTER sums, not a GROUP BY dimension
syslog_dest_rollup  hour_bucket | dstip(TEXT,NOT NULL) | vendor | site_id | log_count — top-destinations, symmetric to syslog_talker_rollup
syslog_source_host_rollup  hour_bucket | source_host(TEXT,NOT NULL) | source_ip(TEXT,MAX() representative not grouping key) | site_id | log_count — silent-device detection
syslog_distinct_value_rollup  hour_bucket | dimension(TEXT,'country'|'user'|'source'|'service') | value(TEXT,NOT NULL) | site_id | log_count — What's New/Changed; 'source' value is COALESCE(srcip,source_ip::text) WITHOUT host() — intentionally keeps the /32 mask suffix, matches old behavior
syslog_known_bad_hit_rollup  hour_bucket | ip_address(TEXT,NOT NULL) | site_id | hit_count(BIGINT) — scoped ONLY to currently known-bad/abuse_score>=50 IPs at build time (unlike other rollups, deliberately NOT comprehensive)
syslog_fortinet_field_rollup  hour_bucket | dimension(TEXT,'action'|'type'|'subtype'|'service') | value(TEXT,NOT NULL) | site_id | log_count — built with action='blocked' (correct value), NOT 'deny' (see Known schema debt)
syslog_device_status_rollup  hour_bucket | source_ip(TEXT,NOT NULL) | source_host(TEXT,MAX() representative) | vendor | site_id | log_count | critical_count(severity<=2) | error_count(severity=3) | last_seen(TIMESTAMPTZ,NOT NULL) — 24h fields only; /api/health/device-status's logs_1h intentionally bypasses this table (see gotchas.md, hour-bucket-SUM edge-effect bug)
syslog_entity_activity_rollup  hour_bucket | entity_type(TEXT,'device'|'user'|'srcip') | entity_value(TEXT,NOT NULL) | category(TEXT,nullable) | site_id | log_count | failed_login_count | last_seen(NOT NULL) — entity_value normalization MUST stay byte-identical to collector/analytics/baselineBuilder.js + uebaRollup.js

None of the rollup tables store geo/threat enrichment (country/ASN/abuse/known-bad) — that always stays a LIVE join to known_hosts at read time, by design, so enrichment reflects current threat intel not a rollup-time snapshot. Maintenance: collector/collector.js's recomputeRollupBucket → recomputePhase2/3/4RollupBucket, every 5 min, rolling ROLLUP_LOOKBACK_HOURS window (default 24h). scripts/backfill-rollups.js mirrors the same SQL for one-time historical backfill — MUST run after any new rollup table's schema lands.

## Alerts

alert_rules  id(PK,SERIAL) | name(TEXT,NOT NULL,UNIQUE) | description(TEXT) | is_enabled(BOOLEAN) | match_severity(SMALLINT[]) | match_vendor(TEXT[]) | match_host(TEXT,ILIKE pattern) | match_pattern(TEXT,regex) | threshold_count(INTEGER) | threshold_window(INTERVAL) | notify_email(TEXT) | created_at | updated_at | mitre_techniques(TEXT[])[ALTER]
alert_events  id(PK,BIGSERIAL) | rule_id(FK->alert_rules,ON DELETE CASCADE) | fired_at | source_host(TEXT) | source_ip(INET) | match_count(INTEGER) | sample_message(TEXT) | acknowledged(BOOLEAN) | acknowledged_at | acknowledged_by(TEXT, NetVault user id as text) — writable (not append-only, API legitimately UPDATEs for ack)

## Settings / audit

app_settings  key(PK,TEXT) | value(TEXT,NOT NULL) | updated_at — includes SMTP creds, AbuseIPDB API key, DNS settings, email-notify prefs, collector ingestion guard settings
audit_log  id(PK,BIGSERIAL) | occurred_at | actor_user_id(TEXT) | actor_role(TEXT) | action(TEXT,NOT NULL) | target(TEXT) | detail(JSONB,small context ONLY never secrets) | source_ip(TEXT) | result('success'|'error') — UPDATE/DELETE REVOKEd (append-only)

## UEBA / anomaly detection (Phase 2 intelligence engine)

entity_baselines  entity_type+entity_value+dow+hour(composite PK) | avg_count(REAL) | stddev_count(REAL) | sample_count(INT) | updated_at — hour×day-of-week volume baseline per entity
anomaly_events  id(PK,BIGSERIAL) | detected_at | entity_type | entity_value | source_ip(INET,nullable for users) | anomaly_type('volume_spike'|'silent'|'new_geo'|'new_service') | severity('info'|'warning'|'critical') | score(REAL) | title(TEXT) | detail(JSONB) | acknowledged | acknowledged_at | acknowledged_by
entity_risk  entity_type+entity_value(composite PK) | source_ip(INET) | risk_score(REAL,0-100,EWMA-smoothed) | factors(JSONB array of {label,contribution}) | event_count | anomaly_count | last_activity | updated_at

## Reporting engine

saved_reports  id(PK,SERIAL) | name(TEXT,NOT NULL) | report_type(TEXT,NOT NULL) | params(JSONB) | created_by(TEXT) | created_at | updated_at
report_run_history  id(PK,BIGSERIAL) | report_type(TEXT,NOT NULL) | format('json'|'csv'|'pdf') | params(JSONB) | row_count(INTEGER) | status(TEXT,default 'success') | trigger_type(TEXT,default 'manual') | generated_by(TEXT) | generated_at

## Views (read-only convenience, not tables)

v_top_talkers_24h, v_severity_distribution_24h, v_recent_critical — all scan raw syslog_entries directly, predate the rollup-table work; nothing in the app currently queries these views (verify before relying on them — they were NOT updated when the rollup tables were added).

## Known schema debt

- `/api/security/firewall-denies` and `/api/security/summary`'s firewall_denies sub-query filtered `structured_data->>'action' = 'deny'` for a long time, but this deployment's Fortinet parser never emits `'deny'` — the real value is `'blocked'` (verified live: 702 rows/24h for 'blocked', 0 for 'deny', always). That card silently showed "0" since it shipped. Fixed in the Phase 4 rollup/live-query rewrite (syslog_fortinet_field_rollup is built with 'blocked') — if you see 'deny' reappear anywhere, that's a regression, not a restoration.
- `/api/health/device-status`'s `logs_1h` field intentionally does NOT read syslog_device_status_rollup like its sibling 24h fields do — an hour-bucket SUM approach has a ±59-minute edge effect that IS the whole window on a 1h range (verified up to 91% undercount 5 minutes past each hour, reads as devices going silent hourly). Kept as a live rolling-window subquery instead. Don't "fix" this by making it match the other fields' rollup pattern.
- `syslog_entries.srcip` and `syslog_entries.category`/`risk_score`/`prev_hash`/`entry_hash` are NOT in the original CREATE TABLE block — they're ALTER TABLE ADD COLUMN additions further down schema.sql. A future reader diffing just the CREATE TABLE block against the live DB will think these columns are missing; they're not, they're just added later in the same file.
- Live-verified: `syslog_entries.id` is BIGINT, `srcip` is TEXT, `known_hosts.site_id` is INTEGER, `known_hosts.ip_address`/`syslog_entries.source_ip`/`alert_events.source_ip` are all INET — no observed type divergence between schema.sql and the live DB as of this audit.

## Privilege notes

- `syslog_entries` and `audit_log`: UPDATE/DELETE REVOKEd from `logvault_user` (the app role) — append-only, tamper-evidence model. `alert_events` is deliberately LEFT writable (the API legitimately UPDATEs it for acknowledgement) — don't lock it down to match the other two.
- `app_settings` holds SMTP password (`smtp_pass`) and the AbuseIPDB API key (`abuseipdb_api_key`) in plaintext `value`, mixed into the same generic key/value table as harmless cosmetic settings. FIXED 2026-07: `nocvault_readonly`/`claude_readonly` no longer get table-level SELECT on `app_settings` at all — they read `app_settings_public` (an ALLOWLIST view, only `app_name`/`app_subtitle`/`logo_url`/`primary_color`/`sidebar_color`) instead. A REVOKE+view-GRANT block runs immediately after the blanket grant below, every time schema.sql runs, so this can't be silently re-opened by a future deploy. A new settings key defaults to HIDDEN from these two roles until deliberately added to the view.
- Cross-suite read access: `nocvault_readonly` (used by the NocVault Hub for cross-DB dashboards) gets `GRANT SELECT ON ALL TABLES` + `ALTER DEFAULT PRIVILEGES FOR ROLE postgres ... GRANT SELECT` so future tables are auto-covered — SELECT only, never INSERT/UPDATE/DELETE, and does NOT touch the append-only REVOKEs above. This grant is idempotent and safe to re-run; it's a no-op on a standalone LogVault install with no such role. **This blanket grant is exactly why the `app_settings_public` fix above must always run AFTER it in file order** — a table-level GRANT SELECT overrides any column/view-level restriction that came before it in PostgreSQL; REVOKE-then-view-GRANT only works if it's the LAST statement touching that role's privileges.
- schema.sql runs as `postgres` superuser (tables are owned by postgres, not logvault_user) — this is WHY the ALTER DEFAULT PRIVILEGES rule above targets `FOR ROLE postgres`, not `FOR ROLE logvault_user`. Both the installer's one-time grant and this file's re-grant must stay in sync or a table added between them becomes invisible to the Hub.
- `scripts/backfill-rollups.js` requires the `postgres` superuser (not `logvault_user`) — it UPDATEs the append-only `syslog_entries.srcip` column, which `logvault_user` cannot do post-REVOKE.
- No separate schema-grants.sql in this repo (unlike some sibling apps) — grants are inline in schema.sql itself, applied as part of the same postgres-run script.
