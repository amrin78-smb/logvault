-- ============================================================
-- LogVault — Tier 1 migration: alert_events indexes
-- ============================================================
-- alert_events had NO indexes beyond its primary key. The collector
-- runs a dedup SELECT against it on EVERY alert match, and the
-- dashboard runs COUNT(*) / recent-unacked queries on it constantly.
-- This table only grows (alerts are not aged out by retention the way
-- syslog is), so it will become a seq-scan bottleneck first.
--
-- These indexes are tiny (alert_events is small vs syslog_entries) and
-- add negligible write cost. Safe to run on the live server.
--
-- CONCURRENTLY = no table lock. IF NOT EXISTS = re-runnable.
-- IMPORTANT: CONCURRENTLY cannot run inside a transaction block.
--   Run with psql -f (each statement autocommits). Do NOT wrap in BEGIN.
--
-- How to run:
--   $env:PGPASSWORD = "NVAdmin@2026"
--   & "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U logvault_user -d logvault -f C:\Apps\logvault\scripts\migration-tier1-alert-events-indexes.sql
-- ============================================================

-- Dedup hot path: collector fireAlert() / correlationEngine
--   WHERE rule_id = $1 AND acknowledged = FALSE AND source_ip = $2
--         AND fired_at > NOW() - INTERVAL '2 hours' ORDER BY fired_at DESC LIMIT 1
-- Partial index on the open (unacknowledged) rows only — keeps it small.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_events_open_dedup
  ON alert_events (rule_id, source_ip, fired_at DESC)
  WHERE acknowledged = FALSE;

-- Dashboard counts + recent-unacked + acknowledge-all + /api/alerts/events ordering
--   WHERE acknowledged = FALSE ... ORDER BY fired_at DESC
--   COUNT(*) WHERE fired_at > NOW() - 24h
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_events_ack_fired
  ON alert_events (acknowledged, fired_at DESC);

-- RBAC site filter on /api/alerts/events:  ae.source_ip IN (SELECT ip_address ...)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_events_source_ip
  ON alert_events (source_ip);

-- Verify they were created:
--   \d alert_events
