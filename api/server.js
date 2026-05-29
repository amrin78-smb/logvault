/**
 * LogVault API Server
 * REST API + WebSocket for the LogVault Next.js frontend
 * Port: 3005 (internal)
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const http     = require('http');
const { WebSocketServer } = require('ws');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

// ── Crash resilience ──────────────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught exception:', err.message, err.stack);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled rejection:', reason);
});

const app  = express();
const port = parseInt(process.env.LV_API_PORT || '3005');

// ── CORS — restrict to frontend origin only ───────────────────
const allowedOrigin = process.env.LV_APP_URL || 'http://localhost:3004';
app.use(cors({ origin: allowedOrigin, credentials: true }));
app.use(express.json({ limit: '1mb' }));

const pool = new Pool({
  host:     process.env.DB_HOST    || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME || 'logvault',
  user:     process.env.LV_DB_USER || 'logvault_user',
  password: process.env.LV_DB_PASS,
  max:      10,
  idleTimeoutMillis: 30000,
});

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ── Input validation helpers ──────────────────────────────────
function safeHours(val, max = 720) {
  const n = Math.min(parseInt(val || '24') || 24, max);
  return isNaN(n) || n <= 0 ? 24 : n;
}
function safeInt(val, def = 10, max = 500) {
  const n = parseInt(val || String(def));
  return isNaN(n) || n <= 0 ? def : Math.min(n, max);
}

// ── DASHBOARD STATS ──────────────────────────────────────────

app.get('/api/stats/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT severity, severity_label, COUNT(*) AS log_count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
    GROUP BY severity, severity_label ORDER BY severity
  `, [hours]);
  res.json({ hours, data: rows });
}));

app.get('/api/stats/timeline', asyncHandler(async (req, res) => {
  const hours  = safeHours(req.query.hours);
  const bucket = hours <= 6 ? '5 minutes' : hours <= 48 ? '1 hour' : '6 hours';
  const trunc  = hours <= 6 ? 'minute' : 'hour';
  const mod    = hours <= 6 ? 5 : hours <= 48 ? 1 : 6;
  const { rows } = await pool.query(`
    SELECT
      date_trunc('${trunc}', received_at)
        - (EXTRACT(${trunc === 'minute' ? 'MINUTE' : 'HOUR'} FROM received_at)::int % $2) * INTERVAL '1 ${trunc}' AS bucket,
      severity_label,
      COUNT(*) AS log_count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
    GROUP BY bucket, severity_label
    ORDER BY bucket
  `, [hours, mod]);
  res.json({ hours, bucket, data: rows });
}));

app.get('/api/stats/top-talkers', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const limit = safeInt(req.query.limit, 10, 50);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(kh.hostname, se.source_host, se.source_ip::TEXT) AS host,
      se.source_ip::TEXT AS source_ip,
      COALESCE(kh.vendor, se.vendor) AS vendor,
      COUNT(*) AS log_count,
      MAX(se.received_at) AS last_seen
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - make_interval(hours => $1)
    GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, se.vendor
    ORDER BY log_count DESC
    LIMIT $2
  `, [hours, limit]);
  res.json({ hours, data: rows });
}));

app.get('/api/stats/by-vendor', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      vendor, COUNT(*) AS log_count,
      COUNT(*) FILTER (WHERE severity <= 2) AS critical_count,
      COUNT(*) FILTER (WHERE severity = 3)  AS error_count,
      COUNT(*) FILTER (WHERE severity = 4)  AS warning_count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
    GROUP BY vendor ORDER BY log_count DESC
  `, [hours]);
  res.json({ hours, data: rows });
}));

app.get('/api/stats/top-security-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      CASE
        WHEN message ILIKE '%ssl-alert%'     THEN 'SSL Alert'
        WHEN message ILIKE '%ssl exit error%' THEN 'SSL Exit Error'
        WHEN message ILIKE '%ipsec%phase 1%'  THEN 'IPSec Phase 1 Error'
        WHEN message ILIKE '%login failed%'   THEN 'Login Failed'
        WHEN message ILIKE '%action=deny%'    THEN 'Traffic Denied'
        WHEN message ILIKE '%utm/ips%'        THEN 'IPS Threat'
        WHEN message ILIKE '%negotiate%'      THEN 'VPN Negotiate'
        WHEN structured_data->>'subtype' IS NOT NULL THEN structured_data->>'subtype'
        ELSE 'Other'
      END AS event_type,
      COUNT(*) AS count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND severity <= 4
    GROUP BY event_type
    ORDER BY count DESC
    LIMIT 7
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/stats/top-failures', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(structured_data->>'dstip', 'unknown') AS dst_ip,
      COALESCE(structured_data->>'service', '') AS service,
      COUNT(*) AS fail_count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND (
        -- Fortinet connection failures
        (vendor = 'fortinet' AND message ILIKE '%Connection Failed%')
        OR
        -- Palo Alto session end with no bytes
        (vendor = 'paloalto' AND message ILIKE '%session_end%' AND message ILIKE '%bytes%0%')
        OR
        -- Cisco TCP unreachable / timeout
        (vendor = 'cisco' AND (
          message ILIKE '%unreachable%'
          OR message ILIKE '%timed out%'
        ))
        OR
        -- Generic connection failure indicators
        (vendor NOT IN ('fortinet','paloalto','cisco') AND (
          message ILIKE '%connection failed%'
          OR message ILIKE '%connection refused%'
          OR message ILIKE '%host unreachable%'
          OR message ILIKE '%timed out%'
        ))
      )
      AND structured_data->>'dstip' IS NOT NULL
    GROUP BY structured_data->>'dstip', structured_data->>'service'
    ORDER BY fail_count DESC
    LIMIT 5
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/stats/top-blocked', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(structured_data->>'dstip', 'unknown') AS dst_ip,
      COALESCE(structured_data->>'service', '') AS service,
      vendor,
      COUNT(*) AS deny_count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND (
        -- Fortinet: policy deny or UTM block
        (vendor = 'fortinet' AND (
          structured_data->>'action' = 'deny'
          OR structured_data->>'action' = 'blocked'
          OR message ILIKE '%action=deny%'
          OR message ILIKE '%action=blocked%'
        ))
        OR
        -- Palo Alto: deny or drop in traffic logs
        (vendor = 'paloalto' AND (
          structured_data->>'action' = 'deny'
          OR structured_data->>'action' = 'drop'
          OR message ILIKE '%action=deny%'
          OR message ILIKE '%action=drop%'
        ))
        OR
        -- Cisco: ACL deny messages
        (vendor = 'cisco' AND (
          message ILIKE '%denied%'
          OR message ILIKE '%ACL%deny%'
        ))
        OR
        -- Generic: any vendor with explicit deny/block action
        (vendor NOT IN ('fortinet','paloalto','cisco') AND (
          structured_data->>'action' IN ('deny','block','drop','blocked')
          OR message ILIKE '%action=deny%'
          OR message ILIKE '%action=block%'
          OR message ILIKE '%denied%'
        ))
      )
      AND structured_data->>'dstip' IS NOT NULL
    GROUP BY structured_data->>'dstip', structured_data->>'service', vendor
    ORDER BY deny_count DESC
    LIMIT 5
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/stats/vpn-summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE message ILIKE '%fail%' OR message ILIKE '%error%') AS failures,
      COUNT(*) FILTER (WHERE message ILIKE '%success%' OR message ILIKE '%connected%') AS successes,
      COUNT(*) FILTER (WHERE message ILIKE '%ssl-alert%' OR message ILIKE '%ssl alert%') AS ssl_alerts
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'fortinet'
      AND (structured_data->>'subtype' = 'vpn' OR message ILIKE '%vpn%'
        OR message ILIKE '%ipsec%' OR message ILIKE '%ssl%')
  `, [hours]);
  res.json(rows[0]);
}));

app.get('/api/stats/alerts-summary', asyncHandler(async (req, res) => {
  const [unacked, total24h, recent] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM alert_events WHERE acknowledged = FALSE`),
    pool.query(`SELECT COUNT(*) AS count FROM alert_events WHERE fired_at > NOW() - make_interval(hours => 24)`),
    pool.query(`SELECT ae.fired_at, ar.name AS rule_name FROM alert_events ae LEFT JOIN alert_rules ar ON ar.id = ae.rule_id WHERE ae.acknowledged = FALSE ORDER BY ae.fired_at DESC LIMIT 3`),
  ]);
  res.json({ unacknowledged: parseInt(unacked.rows[0].count), total_24h: parseInt(total24h.rows[0].count), recent: recent.rows });
}));

app.get('/api/stats/top-services', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT COALESCE(structured_data->>'service', 'unknown') AS service, COUNT(*) AS count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'fortinet'
      AND structured_data->>'service' IS NOT NULL
      AND structured_data->>'service' != ''
    GROUP BY structured_data->>'service'
    ORDER BY count DESC LIMIT 8
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/stats/firewall-actions', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT COALESCE(structured_data->>'action', 'unknown') AS action, COUNT(*) AS count
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'fortinet'
      AND structured_data->>'action' IS NOT NULL
    GROUP BY structured_data->>'action'
    ORDER BY count DESC LIMIT 10
  `, [hours]);
  res.json({ data: rows });
}));

// ── STORAGE STATS ────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 ** 3)   return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

app.get('/api/stats/storage', asyncHandler(async (req, res) => {
  const [sizes, growth, oldest, retention] = await Promise.all([
    pool.query(`SELECT pg_size_pretty(pg_database_size('logvault')) AS db_size, pg_database_size('logvault') AS db_size_bytes, pg_size_pretty(pg_total_relation_size('syslog_entries')) AS table_size, pg_total_relation_size('syslog_entries') AS table_size_bytes, (SELECT COUNT(*) FROM syslog_entries) AS total_rows, (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => 24)) AS rows_24h, (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - make_interval(days => 7)) AS rows_7d`),
    pool.query(`SELECT DATE_TRUNC('day', received_at) AS day, COUNT(*) AS log_count FROM syslog_entries WHERE received_at > NOW() - make_interval(days => 7) GROUP BY day ORDER BY day`),
    pool.query(`SELECT MIN(received_at) AS oldest_log FROM syslog_entries`),
    pool.query(`SELECT EXTRACT(DAY FROM (NOW() - MIN(received_at))) AS days_stored FROM syslog_entries`),
  ]);
  const s = sizes.rows[0];
  const avgPerDay = s.rows_7d > 0 ? Math.round(parseInt(s.table_size_bytes) / Math.max(parseFloat(retention.rows[0]?.days_stored || 1), 1)) : 0;
  res.json({ db_size: s.db_size, db_size_bytes: parseInt(s.db_size_bytes), table_size: s.table_size, table_size_bytes: parseInt(s.table_size_bytes), total_rows: parseInt(s.total_rows), rows_24h: parseInt(s.rows_24h), rows_7d: parseInt(s.rows_7d), oldest_log: oldest.rows[0]?.oldest_log, days_stored: parseFloat(retention.rows[0]?.days_stored || 0).toFixed(1), avg_bytes_per_day: avgPerDay, avg_size_per_day: avgPerDay > 0 ? formatBytes(avgPerDay) : 'N/A', daily_breakdown: growth.rows });
}));

// ── LOG SEARCH ───────────────────────────────────────────────

app.get('/api/logs', asyncHandler(async (req, res) => {
  const { q, vendor, severity, host, ip } = req.query;
  const hours  = safeHours(req.query.hours, 720);
  const page   = Math.max(parseInt(req.query.page || '1'), 1);
  const limit  = safeInt(req.query.limit, 100, 500);
  const offset = (page - 1) * limit;

  const conditions = [`se.received_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (q)        { conditions.push(`to_tsvector('english', se.message) @@ plainto_tsquery('english', $${p++})`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                        params.push(vendor); }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => !isNaN(n) && n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`);     params.push(sevs); }
  }
  if (host)     {
    conditions.push(`(se.source_host ILIKE $${p++} OR kh.hostname ILIKE $${p++} OR se.source_ip::TEXT ILIKE $${p++})`);
    params.push(`%${host}%`, `%${host}%`, `%${host}%`); p += 2;
  }
  if (ip)       { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`);           params.push(`%${ip}%`); }

  params.push(limit, offset);

  const { rows } = await pool.query(`
    SELECT se.id, se.received_at, se.log_timestamp, se.source_ip::TEXT,
      COALESCE(kh.hostname, se.source_host) AS source_host,
      se.facility_label, se.severity, se.severity_label, se.vendor,
      se.program, se.message, se.structured_data, se.is_parsed
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE ${conditions.join(' AND ')}
    ORDER BY se.received_at DESC
    LIMIT $${p++} OFFSET $${p++}
  `, params);

  const countRes = await pool.query(
    `SELECT COUNT(*) AS total FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip WHERE ${conditions.join(' AND ')}`,
    params.slice(0, -2)
  );

  res.json({ total: parseInt(countRes.rows[0].total), page, limit, data: rows });
}));

app.get('/api/logs/recent-critical', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host,
      se.source_ip::TEXT, se.severity_label, se.vendor, se.message
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.severity <= 3 AND se.received_at > NOW() - make_interval(hours => $1)
    ORDER BY se.received_at DESC LIMIT 50
  `, [hours]);
  res.json({ data: rows });
}));

// ── ALERT RULES ──────────────────────────────────────────────

app.get('/api/alerts/rules', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM alert_rules ORDER BY id');
  res.json({ data: rows });
}));

app.post('/api/alerts/rules', asyncHandler(async (req, res) => {
  const { name, description, match_severity, match_vendor, match_host,
          match_pattern, threshold_count, threshold_window, notify_email } = req.body;

  // Input validation
  if (!name || typeof name !== 'string' || name.length > 200)
    return res.status(400).json({ error: 'Invalid name' });
  if (threshold_count !== undefined && (isNaN(parseInt(threshold_count)) || parseInt(threshold_count) < 1))
    return res.status(400).json({ error: 'threshold_count must be a positive integer' });
  if (match_severity && (!Array.isArray(match_severity) || match_severity.some(s => s < 0 || s > 7)))
    return res.status(400).json({ error: 'match_severity must be array of integers 0-7' });
  if (match_pattern) {
    try { new RegExp(match_pattern); } catch { return res.status(400).json({ error: 'Invalid match_pattern regex' }); }
  }

  const { rows } = await pool.query(`
    INSERT INTO alert_rules (name, description, match_severity, match_vendor, match_host,
      match_pattern, threshold_count, threshold_window, notify_email)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
  `, [name, description, match_severity, match_vendor, match_host,
      match_pattern, threshold_count || 1, threshold_window || '5 minutes', notify_email]);
  res.status(201).json({ data: rows[0] });
}));

app.patch('/api/alerts/rules/:id', asyncHandler(async (req, res) => {
  const { is_enabled } = req.body;
  const { rows } = await pool.query(
    'UPDATE alert_rules SET is_enabled=$1, updated_at=NOW() WHERE id=$2 RETURNING *',
    [is_enabled, req.params.id]
  );
  res.json({ data: rows[0] });
}));

app.get('/api/alerts/events', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT ae.*, ar.name AS rule_name
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    ORDER BY ae.acknowledged ASC, ae.fired_at DESC
    LIMIT 500
  `);
  res.json({ data: rows });
}));

app.patch('/api/alerts/events/:id/acknowledge', asyncHandler(async (req, res) => {
  await pool.query('UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW() WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

app.patch('/api/alerts/events/acknowledge-all', asyncHandler(async (req, res) => {
  const { ids } = req.body;
  if (ids && Array.isArray(ids) && ids.length > 0) {
    await pool.query('UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW() WHERE id = ANY($1::int[])', [ids]);
  } else {
    await pool.query('UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW() WHERE acknowledged=FALSE');
  }
  res.json({ ok: true });
}));

// Alert banner — most recent unacknowledged alerts
app.get('/api/alerts/events/recent-unacked', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT ae.id, ae.fired_at, ae.source_host, ae.source_ip, ae.sample_message AS message,
      ar.name AS rule_name
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE ae.acknowledged = FALSE
    ORDER BY ae.fired_at DESC
    LIMIT 5
  `);
  res.json({ data: rows });
}));

// CSV export
app.get('/api/logs/export', asyncHandler(async (req, res) => {
  const { q, vendor, severity, host, ip } = req.query;
  const hours = safeHours(req.query.hours, 720);

  const conditions = [`se.received_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (q)        { conditions.push(`to_tsvector('english', se.message) @@ plainto_tsquery('english', $${p++})`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                   params.push(vendor); }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => !isNaN(n) && n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`); params.push(sevs); }
  }
  if (host) {
    conditions.push(`(se.source_host ILIKE $${p++} OR kh.hostname ILIKE $${p++} OR se.source_ip::TEXT ILIKE $${p++})`);
    params.push(`%${host}%`, `%${host}%`, `%${host}%`); p += 2;
  }
  if (ip) { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`); params.push(`%${ip}%`); }

  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host,
      se.source_ip::TEXT, se.severity_label, se.vendor, se.program, se.message
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE ${conditions.join(' AND ')}
    ORDER BY se.received_at DESC
    LIMIT 10000
  `, params);

  // Build CSV
  const header = 'Time,Host,Source IP,Severity,Vendor,Program,Message\n';
  const csvRows = rows.map(r => [
    r.received_at, r.source_host || '', r.source_ip || '',
    r.severity_label, r.vendor, r.program || '',
    `"${(r.message || '').replace(/"/g, '""')}"`,
  ].join(','));

  const csv = header + csvRows.join('\n');
  const filename = `logvault-export-${new Date().toISOString().slice(0, 10)}.csv`;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csv);
}));

// ── KNOWN HOSTS ──────────────────────────────────────────────

app.get('/api/hosts', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT ip_address::TEXT, hostname, vendor, description,
      site_name, brand, model, device_status, lifecycle_status,
      synced_from_nv, last_synced, last_seen
    FROM known_hosts
    ORDER BY synced_from_nv DESC, last_seen DESC
  `);
  res.json({ data: rows });
}));

app.put('/api/hosts', asyncHandler(async (req, res) => {
  const { ip_address, hostname, vendor, description } = req.body;
  if (!ip_address) return res.status(400).json({ error: 'ip_address required' });
  const { rows } = await pool.query(`
    INSERT INTO known_hosts (ip_address, hostname, vendor, description, last_seen)
    VALUES ($1,$2,$3,$4,NOW())
    ON CONFLICT (ip_address) DO UPDATE
      SET hostname=EXCLUDED.hostname, vendor=EXCLUDED.vendor,
          description=EXCLUDED.description, last_seen=NOW()
    RETURNING *
  `, [ip_address, hostname, vendor, description]);
  res.json({ data: rows[0] });
}));

// Manual trigger for NetVault sync
const { syncFromNetVault } = require('./netvaultSync');
app.post('/api/hosts/sync-netvault', asyncHandler(async (req, res) => {
  try {
    const result = await syncFromNetVault(pool);
    res.json({ ok: true, synced: result?.synced || 0 });
  } catch (err) {
    console.error('[SyncNV] Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
}));

// ── NETWORK HEALTH ───────────────────────────────────────────

app.get('/api/health/interfaces', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, message,
      structured_data->>'interface'   AS interface,
      structured_data->>'link_state'  AS link_state,
      structured_data->>'subcategory' AS subcategory
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'cisco'
      AND structured_data->>'category' = 'interface'
    ORDER BY received_at DESC LIMIT 200
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/health/flaps', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(source_host, source_ip::TEXT) AS host,
      structured_data->>'interface' AS interface,
      COUNT(*) AS event_count,
      COUNT(*) FILTER (WHERE structured_data->>'link_state' = 'down') AS down_count,
      COUNT(*) FILTER (WHERE structured_data->>'link_state' = 'up')   AS up_count,
      MIN(received_at) AS first_seen, MAX(received_at) AS last_seen
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'cisco'
      AND structured_data->>'category' = 'interface'
      AND structured_data->>'interface' IS NOT NULL
    GROUP BY source_host, source_ip, structured_data->>'interface'
    HAVING COUNT(*) >= 2
    ORDER BY event_count DESC LIMIT 50
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/health/stp', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'subcategory' AS subcategory,
      structured_data->>'interface'   AS interface,
      structured_data->>'mac_address' AS mac_address
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'cisco'
      AND structured_data->>'category' IN ('stp','loop')
    ORDER BY received_at DESC LIMIT 200
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/health/macflaps', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(source_host, source_ip::TEXT) AS host,
      structured_data->>'mac_address' AS mac_address,
      COUNT(*) AS flap_count,
      MIN(received_at) AS first_seen, MAX(received_at) AS last_seen,
      STRING_AGG(DISTINCT structured_data->>'interface', ', ') AS interfaces
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND structured_data->>'subcategory' = 'mac_flap'
    GROUP BY source_host, source_ip, structured_data->>'mac_address'
    ORDER BY flap_count DESC LIMIT 50
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/health/config-changes', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, message, vendor
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND (
        (vendor = 'cisco' AND structured_data->>'subcategory' = 'config_change')
        OR message ILIKE '%configured from%'
        OR message ILIKE '%configuration changed%'
        OR message ILIKE '%config edit%'
      )
    ORDER BY received_at DESC LIMIT 100
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/health/routing', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'subcategory' AS protocol
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1)
      AND vendor = 'cisco'
      AND structured_data->>'category' = 'routing'
    ORDER BY received_at DESC LIMIT 100
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/health/device-status', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`
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
    ORDER BY last_seen DESC
  `);
  res.json({ data: rows });
}));

app.get('/api/health/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const [iface, stp, mac, cfg, rt] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='cisco' AND structured_data->>'category'='interface'`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='cisco' AND structured_data->>'category' IN ('stp','loop')`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory'='mac_flap'`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (structured_data->>'subcategory'='config_change' OR message ILIKE '%configured from%')`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='cisco' AND structured_data->>'category'='routing'`, [hours]),
  ]);
  res.json({ hours, interface_events: parseInt(iface.rows[0].count), stp_loop_events: parseInt(stp.rows[0].count), mac_flap_events: parseInt(mac.rows[0].count), config_changes: parseInt(cfg.rows[0].count), routing_events: parseInt(rt.rows[0].count) });
}));

// ── SECURITY ─────────────────────────────────────────────────

app.get('/api/security/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const [authFail, denies, vpn, ips, afterHours, bruteSuccess] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND ((vendor='cisco' AND structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force')) OR (vendor='fortinet' AND message ILIKE '%failed%' AND message ILIKE '%login%') OR (vendor='aruba' AND message ILIKE '%authentication failed%') OR message ILIKE '%authentication failure%')`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action' = 'deny'`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND (structured_data->>'subtype' = 'vpn' OR message ILIKE '%vpn%')`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type' = 'utm'`, [hours]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') OR message ILIKE '%login failed%' OR message ILIKE '%configured from%') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19`, [hours]),
    pool.query(`SELECT COUNT(DISTINCT a.source_ip) AS count
      FROM syslog_entries a
      INNER JOIN syslog_entries b ON b.source_ip = a.source_ip
        AND b.vendor = 'cisco'
        AND b.structured_data->>'subcategory' = 'login_failed'
        AND b.received_at > NOW() - make_interval(hours => $1)
      WHERE a.received_at > NOW() - make_interval(hours => $1)
        AND a.vendor = 'cisco'
        AND a.structured_data->>'subcategory' = 'login_success'`, [hours]),
  ]);
  res.json({
    hours,
    auth_failures:       parseInt(authFail.rows[0].count),
    firewall_denies:     parseInt(denies.rows[0].count),
    vpn_events:          parseInt(vpn.rows[0].count),
    ips_events:          parseInt(ips.rows[0].count),
    after_hours_events:  parseInt(afterHours.rows[0].count),
    brute_force_success: parseInt(bruteSuccess.rows[0].count),
  });
}));

app.get('/api/security/auth-failures', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT se.source_ip::TEXT, COALESCE(kh.hostname, se.source_host) AS source_host,
      COUNT(*) AS failure_count, MIN(se.received_at) AS first_attempt, MAX(se.received_at) AS last_attempt, se.vendor,
      ARRAY_AGG(DISTINCT LEFT(se.message, 150)) FILTER (WHERE LENGTH(se.message) < 200) AS sample_messages
    FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - make_interval(hours => $1)
      AND ((se.vendor='cisco' AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force'))
        OR (se.vendor='fortinet' AND se.message ILIKE '%failed%' AND se.message ILIKE '%login%')
        OR (se.vendor='aruba' AND se.message ILIKE '%authentication failed%')
        OR se.message ILIKE '%authentication failure%' OR se.message ILIKE '%login failed%')
    GROUP BY se.source_ip, se.source_host, kh.hostname, se.vendor
    ORDER BY failure_count DESC LIMIT 50
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/security/brute-force', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    WITH failures AS (
      SELECT source_ip, MIN(received_at) AS first_fail, MAX(received_at) AS last_fail, COUNT(*) AS fail_count
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1)
        AND ((vendor='cisco' AND structured_data->>'subcategory' IN ('login_failed','auth_failed'))
          OR message ILIKE '%login failed%' OR message ILIKE '%authentication fail%')
      GROUP BY source_ip
    ),
    successes AS (
      SELECT source_ip, MIN(received_at) AS success_time, message AS success_msg
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1)
        AND ((vendor='cisco' AND structured_data->>'subcategory' = 'login_success')
          OR message ILIKE '%login success%' OR message ILIKE '%authenticated%')
      GROUP BY source_ip, message
    )
    SELECT f.source_ip::TEXT, COALESCE(kh.hostname, f.source_ip::TEXT) AS host,
      f.fail_count, f.first_fail, f.last_fail, s.success_time, s.success_msg,
      CASE WHEN s.success_time IS NOT NULL THEN TRUE ELSE FALSE END AS success_after_failure
    FROM failures f
    LEFT JOIN successes s ON s.source_ip = f.source_ip AND s.success_time > f.first_fail
    LEFT JOIN known_hosts kh ON kh.ip_address = f.source_ip
    WHERE f.fail_count >= 3
    ORDER BY success_after_failure DESC, f.fail_count DESC LIMIT 50
  `, [hours, hours]);
  res.json({ data: rows });
}));

app.get('/api/security/firewall-denies', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const [bySrc, byDst, bySvc] = await Promise.all([
    pool.query(`SELECT structured_data->>'srcip' AS src_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'dstip') FILTER (WHERE structured_data->>'dstip' IS NOT NULL) AS destinations FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='deny' AND structured_data->>'srcip' IS NOT NULL GROUP BY structured_data->>'srcip' ORDER BY deny_count DESC LIMIT 15`, [hours]),
    pool.query(`SELECT structured_data->>'dstip' AS dst_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'srcip') FILTER (WHERE structured_data->>'srcip' IS NOT NULL) AS sources FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='deny' AND structured_data->>'dstip' IS NOT NULL GROUP BY structured_data->>'dstip' ORDER BY deny_count DESC LIMIT 15`, [hours]),
    pool.query(`SELECT COALESCE(structured_data->>'service','unknown') AS service, COUNT(*) AS deny_count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='deny' GROUP BY structured_data->>'service' ORDER BY deny_count DESC LIMIT 10`, [hours]),
  ]);
  res.json({ by_source: bySrc.rows, by_destination: byDst.rows, by_service: bySvc.rows });
}));

app.get('/api/security/vpn-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'srcip' AS vpn_src_ip, structured_data->>'msg' AS detail,
      CASE WHEN message ILIKE '%fail%' OR message ILIKE '%error%' THEN 'failure'
           WHEN message ILIKE '%success%' OR message ILIKE '%connected%' THEN 'success'
           ELSE 'info' END AS event_type
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet'
      AND (structured_data->>'subtype'='vpn' OR message ILIKE '%ssl vpn%' OR message ILIKE '%ipsec%' OR message ILIKE '%vpn%')
    ORDER BY received_at DESC LIMIT 100
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/security/ips-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const [events, byThreat] = await Promise.all([
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, severity_label, message, structured_data->>'srcip' AS src_ip, structured_data->>'dstip' AS dst_ip, structured_data->>'msg' AS threat_name, structured_data->>'action' AS action, structured_data->>'subtype' AS subtype FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type'='utm' ORDER BY received_at DESC LIMIT 100`, [hours]),
    pool.query(`SELECT COALESCE(structured_data->>'msg','Unknown') AS threat, structured_data->>'subtype' AS subtype, COUNT(*) AS hit_count, COUNT(DISTINCT structured_data->>'srcip') AS unique_sources FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type'='utm' GROUP BY structured_data->>'msg', structured_data->>'subtype' ORDER BY hit_count DESC LIMIT 20`, [hours]),
  ]);
  res.json({ events: events.rows, by_threat: byThreat.rows });
}));

app.get('/api/security/after-hours', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours, 720);
  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host, se.source_ip::TEXT,
      se.vendor, se.severity_label, se.message, EXTRACT(HOUR FROM se.received_at) AS hour_of_day,
      CASE WHEN se.structured_data->>'subcategory'='config_change' THEN 'Config Change'
           WHEN se.structured_data->>'subcategory' IN ('login_failed','auth_failed') THEN 'Auth Failure'
           WHEN se.structured_data->>'subcategory'='login_success' THEN 'Login Success'
           WHEN se.message ILIKE '%vpn%' THEN 'VPN' ELSE 'Security Event' END AS event_type
    FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - make_interval(hours => $1)
      AND (se.structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed','login_success')
        OR se.message ILIKE '%login%' OR se.message ILIKE '%configured from%' OR se.message ILIKE '%vpn%')
      AND EXTRACT(HOUR FROM se.received_at) NOT BETWEEN 7 AND 19
    ORDER BY se.received_at DESC LIMIT 100
  `, [hours]);
  res.json({ data: rows });
}));

app.get('/api/security/wireless-auth', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const [failures, summary] = await Promise.all([
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, message, severity_label FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='aruba' AND message ILIKE '%authentication failed%' ORDER BY received_at DESC LIMIT 50`, [hours]),
    pool.query(`SELECT COUNT(*) FILTER (WHERE message ILIKE '%failed%') AS failures, COUNT(*) FILTER (WHERE message ILIKE '%success%' OR message ILIKE '%authenticated%') AS successes, COUNT(DISTINCT source_ip) AS devices FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='aruba' AND (message ILIKE '%authentication%' OR message ILIKE '%802.1x%')`, [hours]),
  ]);
  res.json({ failures: failures.rows, summary: summary.rows[0] });
}));

// ── DISK SPACE ───────────────────────────────────────────────
const { execSync } = require('child_process');

app.get('/api/stats/disk', asyncHandler(async (req, res) => {
  try {
    // Use PowerShell to get real disk info for C: drive
    const ps = `powershell.exe -NonInteractive -Command "` +
      `$d = Get-PSDrive C; ` +
      `$used = $d.Used; $free = $d.Free; $total = $used + $free; ` +
      `Write-Output ($used.ToString() + ',' + $free.ToString() + ',' + $total.ToString())" `;
    const output = execSync(ps, { encoding: 'utf8', timeout: 10000 }).trim();
    const [usedBytes, freeBytes, totalBytes] = output.split(',').map(v => parseInt(v.trim()));

    const toGB = (b) => Math.round((b / 1024 / 1024 / 1024) * 100) / 100;

    res.json({
      drive:      'C:',
      used_bytes:  usedBytes,
      free_bytes:  freeBytes,
      total_bytes: totalBytes,
      used_gb:     toGB(usedBytes),
      free_gb:     toGB(freeBytes),
      total_gb:    toGB(totalBytes),
      used_pct:    Math.round((usedBytes / totalBytes) * 100),
    });
  } catch (err) {
    console.error('[Disk] PowerShell error:', err.message);
    // Fallback — return null so frontend can handle gracefully
    res.json({ drive: 'C:', used_gb: null, free_gb: null, total_gb: null, used_pct: null, error: 'Unable to read disk info' });
  }
}));

// ── APP SETTINGS ─────────────────────────────────────────────

app.get('/api/settings', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM app_settings');
  const data = Object.fromEntries(rows.map(r => [r.key, r.value]));
  res.json({ data });
}));

app.post('/api/settings', asyncHandler(async (req, res) => {
  const allowed = ['app_name', 'app_subtitle', 'primary_color', 'sidebar_color', 'logo_url', 'dns_server', 'dns_lookup_enabled'];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      await pool.query(
        `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, req.body[key]]
      );
    }
  }
  res.json({ ok: true });
}));

// ── HEALTH CHECK ─────────────────────────────────────────────

app.get('/api/health', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`SELECT COUNT(*) AS total FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => 1)`);
  res.json({ status: 'ok', logs_last_hour: parseInt(rows[0].total) });
}));

// ── ERROR HANDLER ─────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[API Error]', err.message, err.stack);
  // Return generic error to client — don't leak internals
  res.status(500).json({ error: 'Internal server error' });
});

// ── WebSocket: Live Tail ──────────────────────────────────────
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws/live' });

let lastId    = BigInt(0);
let lastIdSet = false;

async function initLastId() {
  try {
    const { rows } = await pool.query('SELECT MAX(id) AS max_id FROM syslog_entries');
    if (rows[0].max_id) { lastId = BigInt(rows[0].max_id); lastIdSet = true; }
    console.log(`[WS] Live Tail starting from log ID ${lastId}`);
  } catch (err) { console.error('[WS] Failed to init lastId:', err.message); }
}

async function broadcastNewLogs() {
  if (wss.clients.size === 0) return;
  if (!lastIdSet) { await initLastId(); return; }
  try {
    const { rows } = await pool.query(`
      SELECT se.id, se.received_at,
        COALESCE(kh.hostname, se.source_host) AS source_host,
        se.source_ip::TEXT, se.severity_label, se.vendor, se.program, se.message
      FROM syslog_entries se
      LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
      WHERE se.id > $1
      ORDER BY se.id ASC LIMIT 50
    `, [lastId.toString()]);
    if (rows.length > 0) {
      lastId = BigInt(rows[rows.length - 1].id);
      const payload = JSON.stringify({ type: 'logs', data: rows });
      wss.clients.forEach(client => { if (client.readyState === 1) client.send(payload); });
    }
  } catch (err) { console.error('[WS] Broadcast error:', err.message); }
}

initLastId().then(() => { setInterval(broadcastNewLogs, 2000); });

server.listen(port, () => {
  console.log(`LogVault API + WebSocket running on port ${port}`);
});
