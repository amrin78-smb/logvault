-- ============================================================
-- LogVault — Performance verification (READ-ONLY)
-- ============================================================
-- Run this on the LIVE server (192.168.6.111) to confirm which
-- queries are actually slow BEFORE adding Tier 2 (JSONB) indexes.
-- Nothing here writes data — it only runs EXPLAIN (ANALYZE, BUFFERS).
--
-- How to run:
--   $env:PGPASSWORD = "NVAdmin@2026"
--   & "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U logvault_user -d logvault -f C:\Apps\logvault\scripts\perf-explain.sql > C:\Apps\logvault\logs\perf-explain.txt
--
-- Then send back perf-explain.txt. The numbers that matter:
--   * "actual time" total (ms) per query block
--   * "Rows Removed by Filter" (high = JSONB heap-filtering, what Tier 2 fixes)
--   * "Seq Scan" vs "Index Scan" on the big tables
--   * "shared read"/"shared hit" buffer counts (read = off disk)
-- ============================================================

\echo '=== 1. /api/health/device-status (7-day aggregation over ALL hosts) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT
  COALESCE(kh.hostname, se.source_host, se.source_ip::TEXT) AS host,
  se.source_ip::TEXT,
  kh.vendor AS known_vendor, se.vendor, kh.description,
  MAX(se.received_at) AS last_seen,
  COUNT(*) FILTER (WHERE se.received_at > NOW() - make_interval(hours => 1))   AS logs_1h,
  COUNT(*) FILTER (WHERE se.received_at > NOW() - make_interval(hours => 24))  AS logs_24h,
  COUNT(*) FILTER (WHERE se.severity <= 2 AND se.received_at > NOW() - make_interval(hours => 24)) AS critical_24h,
  COUNT(*) FILTER (WHERE se.severity = 3  AND se.received_at > NOW() - make_interval(hours => 24)) AS error_24h,
  EXTRACT(EPOCH FROM (NOW() - MAX(se.received_at)))/60 AS minutes_since_last_log
FROM syslog_entries se
LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
WHERE se.received_at > NOW() - make_interval(days => 7)
GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, kh.description, se.vendor
ORDER BY last_seen DESC;

\echo ''
\echo '=== 2a. /api/health/summary  -> interface count (cisco + JSONB category) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT COUNT(*) AS count FROM syslog_entries
WHERE received_at > NOW() - make_interval(hours => 24)
  AND vendor='cisco' AND structured_data->>'category'='interface';

\echo ''
\echo '=== 2b. /api/health/summary  -> stp/loop count ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT COUNT(*) AS count FROM syslog_entries
WHERE received_at > NOW() - make_interval(hours => 24)
  AND vendor='cisco' AND structured_data->>'category' IN ('stp','loop');

\echo ''
\echo '=== 2c. /api/health/summary  -> mac_flap count (subcategory, no vendor filter) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT COUNT(*) AS count FROM syslog_entries
WHERE received_at > NOW() - make_interval(hours => 24)
  AND structured_data->>'subcategory'='mac_flap';

\echo ''
\echo '=== 2d. /api/health/summary  -> config-change count (JSONB OR message ILIKE) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT COUNT(*) AS count FROM syslog_entries
WHERE received_at > NOW() - make_interval(hours => 24)
  AND (structured_data->>'subcategory'='config_change' OR message ILIKE '%configured from%');

\echo ''
\echo '=== 3. /api/health/flaps (cisco interface, GROUP BY + HAVING) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT
  COALESCE(source_host, source_ip::TEXT) AS host,
  structured_data->>'interface' AS interface,
  COUNT(*) AS event_count,
  COUNT(*) FILTER (WHERE structured_data->>'link_state' = 'down') AS down_count,
  COUNT(*) FILTER (WHERE structured_data->>'link_state' = 'up')   AS up_count,
  MIN(received_at) AS first_seen, MAX(received_at) AS last_seen
FROM syslog_entries
WHERE received_at > NOW() - make_interval(hours => 24)
  AND vendor = 'cisco'
  AND structured_data->>'category' = 'interface'
  AND structured_data->>'interface' IS NOT NULL
GROUP BY source_host, source_ip, structured_data->>'interface'
HAVING COUNT(*) >= 2
ORDER BY event_count DESC LIMIT 50;

\echo ''
\echo '=== 4. alert_events dedup SELECT (collector runs this on every alert match) ==='
\echo '    NOTE: replace rule_id / source_ip below with a real value if you have one;'
\echo '    the plan shape (Seq Scan vs Index Scan) is what matters either way.'
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, match_count FROM alert_events
WHERE rule_id = 1
  AND acknowledged = FALSE
  AND source_ip = '192.168.6.1'::inet
  AND fired_at > NOW() - INTERVAL '2 hours'
ORDER BY fired_at DESC
LIMIT 1;

\echo ''
\echo '=== Table sizes (context for the numbers above) ==='
SELECT
  relname AS table,
  pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
  n_live_tup AS approx_rows
FROM pg_stat_user_tables
WHERE relname IN ('syslog_entries','alert_events','known_hosts')
ORDER BY pg_total_relation_size(relid) DESC;
