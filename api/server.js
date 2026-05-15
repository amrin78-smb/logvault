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

const app  = express();
const port = parseInt(process.env.LV_API_PORT || '3005');

app.use(cors());
app.use(express.json());

const pool = new Pool({
  host:     process.env.DB_HOST    || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME || 'logvault',
  user:     process.env.LV_DB_USER || 'logvault_user',
  password: process.env.LV_DB_PASS,
  max:      10,
});

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ── DASHBOARD STATS ──────────────────────────────────────────

app.get('/api/stats/summary', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT severity, severity_label, COUNT(*) AS log_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY severity, severity_label ORDER BY severity
  `);
  res.json({ hours, data: rows });
}));

app.get('/api/stats/timeline', asyncHandler(async (req, res) => {
  const hours  = Math.min(parseInt(req.query.hours || '24'), 168);
  const bucket = hours <= 6 ? '5 minutes' : hours <= 48 ? '1 hour' : '6 hours';
  const { rows } = await pool.query(`
    SELECT
      date_trunc('${bucket === '5 minutes' ? 'minute' : bucket === '1 hour' ? 'hour' : 'hour'}',
        received_at ${bucket === '5 minutes' ? '- (EXTRACT(MINUTE FROM received_at)::int % 5) * interval \'1 minute\'' : bucket === '6 hours' ? '- (EXTRACT(HOUR FROM received_at)::int % 6) * interval \'1 hour\'' : ''}) AS bucket,
      severity_label,
      COUNT(*) AS log_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY bucket, severity_label
    ORDER BY bucket
  `);
  res.json({ hours, bucket, data: rows });
}));

app.get('/api/stats/top-talkers', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const limit = Math.min(parseInt(req.query.limit || '10'), 50);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(kh.hostname, se.source_host, se.source_ip::TEXT) AS host,
      se.source_ip::TEXT AS source_ip,
      COALESCE(kh.vendor, se.vendor) AS vendor,
      COUNT(*) AS log_count,
      MAX(se.received_at) AS last_seen
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, se.vendor
    ORDER BY log_count DESC
    LIMIT $1
  `, [limit]);
  res.json({ hours, data: rows });
}));

app.get('/api/stats/by-vendor', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      vendor, COUNT(*) AS log_count,
      COUNT(*) FILTER (WHERE severity <= 2) AS critical_count,
      COUNT(*) FILTER (WHERE severity = 3)  AS error_count,
      COUNT(*) FILTER (WHERE severity = 4)  AS warning_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY vendor ORDER BY log_count DESC
  `);
  res.json({ hours, data: rows });
}));

// ── LOG SEARCH ───────────────────────────────────────────────

app.get('/api/logs', asyncHandler(async (req, res) => {
  const { q, vendor, severity, host, ip, hours = '1', page = '1', limit = '100' } = req.query;
  const conditions = [`se.received_at > NOW() - INTERVAL '${Math.min(parseInt(hours), 720)} hours'`];
  const params = [];
  let p = 1;

  if (q)        { conditions.push(`to_tsvector('english', se.message) @@ plainto_tsquery('english', $${p++})`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                     params.push(vendor); }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`);  params.push(sevs); }
  }
  if (host)     { conditions.push(`(se.source_host ILIKE $${p++} OR kh.hostname ILIKE $${p++} OR se.source_ip::TEXT ILIKE $${p++})`); params.push(`%${host}%`); params.push(`%${host}%`); params.push(`%${host}%`); p += 2; }
  if (ip)       { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`);        params.push(`%${ip}%`); }

  const offset = (Math.max(parseInt(page), 1) - 1) * Math.min(parseInt(limit), 500);
  const lim    = Math.min(parseInt(limit), 500);
  params.push(lim, offset);

  const { rows } = await pool.query(`
    SELECT
      se.id, se.received_at, se.log_timestamp,
      se.source_ip::TEXT,
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

  res.json({ total: parseInt(countRes.rows[0].total), page: parseInt(page), limit: lim, data: rows });
}));

app.get('/api/logs/recent-critical', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host,
      se.source_ip::TEXT, se.severity_label, se.vendor, se.message
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.severity <= 3 AND se.received_at > NOW() - INTERVAL '${hours} hours'
    ORDER BY se.received_at DESC LIMIT 50
  `);
  res.json({ data: rows });
}));

// ── ALERT RULES ──────────────────────────────────────────────

app.get('/api/alerts/rules', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM alert_rules ORDER BY id');
  res.json({ data: rows });
}));

app.post('/api/alerts/rules', asyncHandler(async (req, res) => {
  const { name, description, match_severity, match_vendor, match_host, match_pattern,
          threshold_count, threshold_window, notify_email } = req.body;
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
    ORDER BY ae.fired_at DESC LIMIT 100
  `);
  res.json({ data: rows });
}));

app.patch('/api/alerts/events/:id/acknowledge', asyncHandler(async (req, res) => {
  await pool.query('UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW() WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ── KNOWN HOSTS ──────────────────────────────────────────────

app.get('/api/hosts', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT ip_address::TEXT, hostname, vendor, description, last_seen FROM known_hosts ORDER BY last_seen DESC');
  res.json({ data: rows });
}));

app.put('/api/hosts', asyncHandler(async (req, res) => {
  const { ip_address, hostname, vendor, description } = req.body;
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

// ── NETWORK HEALTH ───────────────────────────────────────────

app.get('/api/health/interfaces', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, message,
      structured_data->>'interface'   AS interface,
      structured_data->>'link_state'  AS link_state,
      structured_data->>'subcategory' AS subcategory
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'cisco'
      AND structured_data->>'category' = 'interface'
    ORDER BY received_at DESC LIMIT 200
  `);
  res.json({ data: rows });
}));

app.get('/api/health/flaps', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(source_host, source_ip::TEXT) AS host,
      structured_data->>'interface' AS interface,
      COUNT(*) AS event_count,
      COUNT(*) FILTER (WHERE structured_data->>'link_state' = 'down') AS down_count,
      COUNT(*) FILTER (WHERE structured_data->>'link_state' = 'up')   AS up_count,
      MIN(received_at) AS first_seen, MAX(received_at) AS last_seen
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'cisco'
      AND structured_data->>'category' = 'interface'
      AND structured_data->>'interface' IS NOT NULL
    GROUP BY source_host, source_ip, structured_data->>'interface'
    HAVING COUNT(*) >= 2
    ORDER BY event_count DESC LIMIT 50
  `);
  res.json({ data: rows });
}));

app.get('/api/health/stp', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'subcategory' AS subcategory,
      structured_data->>'interface'   AS interface,
      structured_data->>'mac_address' AS mac_address
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'cisco'
      AND structured_data->>'category' IN ('stp','loop')
    ORDER BY received_at DESC LIMIT 200
  `);
  res.json({ data: rows });
}));

app.get('/api/health/macflaps', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(source_host, source_ip::TEXT) AS host,
      structured_data->>'mac_address' AS mac_address,
      COUNT(*) AS flap_count,
      MIN(received_at) AS first_seen, MAX(received_at) AS last_seen,
      STRING_AGG(DISTINCT structured_data->>'interface', ', ') AS interfaces
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND structured_data->>'subcategory' = 'mac_flap'
    GROUP BY source_host, source_ip, structured_data->>'mac_address'
    ORDER BY flap_count DESC LIMIT 50
  `);
  res.json({ data: rows });
}));

app.get('/api/health/config-changes', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, message, vendor
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND (
        (vendor = 'cisco' AND structured_data->>'subcategory' = 'config_change')
        OR message ILIKE '%configured from%'
        OR message ILIKE '%configuration changed%'
        OR message ILIKE '%config edit%'
        OR (vendor = 'fortinet' AND message ILIKE '%config edit%')
      )
    ORDER BY received_at DESC LIMIT 100
  `);
  res.json({ data: rows });
}));

app.get('/api/health/routing', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'subcategory' AS protocol
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'cisco'
      AND structured_data->>'category' = 'routing'
    ORDER BY received_at DESC LIMIT 100
  `);
  res.json({ data: rows });
}));

app.get('/api/health/device-status', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      COALESCE(kh.hostname, se.source_host, se.source_ip::TEXT) AS host,
      se.source_ip::TEXT,
      kh.vendor AS known_vendor, se.vendor, kh.description,
      MAX(se.received_at) AS last_seen,
      COUNT(*) FILTER (WHERE se.received_at > NOW() - INTERVAL '1 hour')   AS logs_1h,
      COUNT(*) FILTER (WHERE se.received_at > NOW() - INTERVAL '24 hours') AS logs_24h,
      COUNT(*) FILTER (WHERE se.severity <= 2 AND se.received_at > NOW() - INTERVAL '24 hours') AS critical_24h,
      COUNT(*) FILTER (WHERE se.severity = 3  AND se.received_at > NOW() - INTERVAL '24 hours') AS error_24h,
      EXTRACT(EPOCH FROM (NOW() - MAX(se.received_at)))/60 AS minutes_since_last_log
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - INTERVAL '7 days'
    GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, kh.description
    ORDER BY last_seen DESC
  `);
  res.json({ data: rows });
}));

app.get('/api/health/summary', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const [iface, stp, mac, cfg, rt] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='cisco' AND structured_data->>'category'='interface'`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='cisco' AND structured_data->>'category' IN ('stp','loop')`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND structured_data->>'subcategory'='mac_flap'`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND (structured_data->>'subcategory'='config_change' OR message ILIKE '%configured from%')`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='cisco' AND structured_data->>'category'='routing'`),
  ]);
  res.json({
    hours,
    interface_events: parseInt(iface.rows[0].count),
    stp_loop_events:  parseInt(stp.rows[0].count),
    mac_flap_events:  parseInt(mac.rows[0].count),
    config_changes:   parseInt(cfg.rows[0].count),
    routing_events:   parseInt(rt.rows[0].count),
  });
}));

// ── SECURITY ANALYSIS ────────────────────────────────────────

app.get('/api/security/summary', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const [authFail, denies, vpn, ips, afterHours, bruteSuccess] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND ((vendor='cisco' AND structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force')) OR (vendor='fortinet' AND message ILIKE '%failed%' AND message ILIKE '%login%') OR (vendor='aruba' AND message ILIKE '%authentication failed%') OR message ILIKE '%authentication failure%')`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'action' = 'deny'`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND (structured_data->>'subtype' = 'vpn' OR message ILIKE '%vpn%')`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'type' = 'utm'`),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND (structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') OR message ILIKE '%login failed%' OR message ILIKE '%configured from%') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19`),
    pool.query(`SELECT COUNT(DISTINCT source_ip) AS count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='cisco' AND structured_data->>'subcategory' = 'login_success' AND source_ip IN (SELECT DISTINCT source_ip FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='cisco' AND structured_data->>'subcategory' = 'login_failed')`),
  ]);
  res.json({ hours, auth_failures: parseInt(authFail.rows[0].count), firewall_denies: parseInt(denies.rows[0].count), vpn_events: parseInt(vpn.rows[0].count), ips_events: parseInt(ips.rows[0].count), after_hours_events: parseInt(afterHours.rows[0].count), brute_force_success: parseInt(bruteSuccess.rows[0].count) });
}));

app.get('/api/security/auth-failures', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT se.source_ip::TEXT, COALESCE(kh.hostname, se.source_host) AS source_host,
      COUNT(*) AS failure_count, MIN(se.received_at) AS first_attempt, MAX(se.received_at) AS last_attempt, se.vendor,
      ARRAY_AGG(DISTINCT LEFT(se.message, 150)) FILTER (WHERE LENGTH(se.message) < 200) AS sample_messages
    FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - INTERVAL '${hours} hours'
      AND ((se.vendor='cisco' AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force'))
        OR (se.vendor='fortinet' AND se.message ILIKE '%failed%' AND se.message ILIKE '%login%')
        OR (se.vendor='aruba' AND se.message ILIKE '%authentication failed%')
        OR se.message ILIKE '%authentication failure%' OR se.message ILIKE '%login failed%')
    GROUP BY se.source_ip, se.source_host, kh.hostname, se.vendor
    ORDER BY failure_count DESC LIMIT 50
  `);
  res.json({ data: rows });
}));

app.get('/api/security/brute-force', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    WITH failures AS (
      SELECT source_ip, MIN(received_at) AS first_fail, MAX(received_at) AS last_fail, COUNT(*) AS fail_count
      FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours'
        AND ((vendor='cisco' AND structured_data->>'subcategory' IN ('login_failed','auth_failed'))
          OR message ILIKE '%login failed%' OR message ILIKE '%authentication fail%')
      GROUP BY source_ip
    ),
    successes AS (
      SELECT source_ip, MIN(received_at) AS success_time, message AS success_msg
      FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours'
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
  `);
  res.json({ data: rows });
}));

app.get('/api/security/firewall-denies', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const [bySrc, byDst, bySvc] = await Promise.all([
    pool.query(`SELECT structured_data->>'srcip' AS src_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'dstip') FILTER (WHERE structured_data->>'dstip' IS NOT NULL) AS destinations FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'action'='deny' AND structured_data->>'srcip' IS NOT NULL GROUP BY structured_data->>'srcip' ORDER BY deny_count DESC LIMIT 15`),
    pool.query(`SELECT structured_data->>'dstip' AS dst_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'srcip') FILTER (WHERE structured_data->>'srcip' IS NOT NULL) AS sources FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'action'='deny' AND structured_data->>'dstip' IS NOT NULL GROUP BY structured_data->>'dstip' ORDER BY deny_count DESC LIMIT 15`),
    pool.query(`SELECT COALESCE(structured_data->>'service', 'unknown') AS service, COUNT(*) AS deny_count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'action'='deny' GROUP BY structured_data->>'service' ORDER BY deny_count DESC LIMIT 10`),
  ]);
  res.json({ by_source: bySrc.rows, by_destination: byDst.rows, by_service: bySvc.rows });
}));

app.get('/api/security/vpn-events', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'srcip' AS vpn_src_ip, structured_data->>'msg' AS detail,
      CASE WHEN message ILIKE '%fail%' OR message ILIKE '%error%' OR severity <= 4 THEN 'failure'
           WHEN message ILIKE '%success%' OR message ILIKE '%login%' OR message ILIKE '%connected%' THEN 'success'
           ELSE 'info' END AS event_type
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet'
      AND (structured_data->>'subtype'='vpn' OR message ILIKE '%ssl vpn%' OR message ILIKE '%ipsec%' OR message ILIKE '%vpn%')
    ORDER BY received_at DESC LIMIT 100
  `);
  res.json({ data: rows });
}));

app.get('/api/security/ips-events', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const [events, byThreat] = await Promise.all([
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, severity_label, message, structured_data->>'srcip' AS src_ip, structured_data->>'dstip' AS dst_ip, structured_data->>'msg' AS threat_name, structured_data->>'action' AS action, structured_data->>'subtype' AS subtype FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'type'='utm' ORDER BY received_at DESC LIMIT 100`),
    pool.query(`SELECT COALESCE(structured_data->>'msg','Unknown') AS threat, structured_data->>'subtype' AS subtype, COUNT(*) AS hit_count, COUNT(DISTINCT structured_data->>'srcip') AS unique_sources FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='fortinet' AND structured_data->>'type'='utm' GROUP BY structured_data->>'msg', structured_data->>'subtype' ORDER BY hit_count DESC LIMIT 20`),
  ]);
  res.json({ events: events.rows, by_threat: byThreat.rows });
}));

app.get('/api/security/after-hours', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '168'), 720);
  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host, se.source_ip::TEXT,
      se.vendor, se.severity_label, se.message, EXTRACT(HOUR FROM se.received_at) AS hour_of_day,
      CASE WHEN se.structured_data->>'subcategory'='config_change' THEN 'Config Change'
           WHEN se.structured_data->>'subcategory' IN ('login_failed','auth_failed') THEN 'Auth Failure'
           WHEN se.structured_data->>'subcategory'='login_success' THEN 'Login Success'
           WHEN se.message ILIKE '%vpn%' THEN 'VPN' ELSE 'Security Event' END AS event_type
    FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at > NOW() - INTERVAL '${hours} hours'
      AND (se.structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed','login_success')
        OR se.message ILIKE '%login%' OR se.message ILIKE '%configured from%' OR se.message ILIKE '%vpn%')
      AND EXTRACT(HOUR FROM se.received_at) NOT BETWEEN 7 AND 19
    ORDER BY se.received_at DESC LIMIT 100
  `);
  res.json({ data: rows });
}));

app.get('/api/security/wireless-auth', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const [failures, summary] = await Promise.all([
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, message, severity_label FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='aruba' AND message ILIKE '%authentication failed%' ORDER BY received_at DESC LIMIT 50`),
    pool.query(`SELECT COUNT(*) FILTER (WHERE message ILIKE '%failed%') AS failures, COUNT(*) FILTER (WHERE message ILIKE '%success%' OR message ILIKE '%authenticated%') AS successes, COUNT(DISTINCT source_ip) AS devices FROM syslog_entries WHERE received_at > NOW() - INTERVAL '${hours} hours' AND vendor='aruba' AND (message ILIKE '%authentication%' OR message ILIKE '%802.1x%')`),
  ]);
  res.json({ failures: failures.rows, summary: summary.rows[0] });
}));

// ── DASHBOARD WIDGET STATS ────────────────────────────────────

app.get('/api/stats/top-security-events', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(
        CASE
          WHEN message ILIKE '%ssl-alert%'    THEN 'SSL Alert'
          WHEN message ILIKE '%ssl exit error%' THEN 'SSL Exit Error'
          WHEN message ILIKE '%ipsec%phase 1%' THEN 'IPSec Phase 1 Error'
          WHEN message ILIKE '%login failed%' THEN 'Login Failed'
          WHEN message ILIKE '%action=deny%'  THEN 'Traffic Denied'
          WHEN message ILIKE '%utm/ips%'      THEN 'IPS Threat'
          WHEN message ILIKE '%negotiate%'    THEN 'VPN Negotiate'
          WHEN structured_data->>'subtype' IS NOT NULL THEN structured_data->>'subtype'
          ELSE 'Other'
        END
      ) AS event_type,
      COUNT(*) AS count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND severity <= 4
    GROUP BY event_type
    ORDER BY count DESC
    LIMIT 7
  `);
  res.json({ data: rows });
}));

app.get('/api/stats/top-blocked', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(structured_data->>'dstip', 'unknown') AS dst_ip,
      COALESCE(structured_data->>'service', '') AS service,
      COUNT(*) AS deny_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'fortinet'
      AND (structured_data->>'action' = 'deny' OR message ILIKE '%action=deny%')
      AND structured_data->>'dstip' IS NOT NULL
    GROUP BY structured_data->>'dstip', structured_data->>'service'
    ORDER BY deny_count DESC
    LIMIT 5
  `);
  res.json({ data: rows });
}));

app.get('/api/stats/vpn-summary', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE message ILIKE '%fail%' OR message ILIKE '%error%') AS failures,
      COUNT(*) FILTER (WHERE message ILIKE '%success%' OR message ILIKE '%connected%') AS successes,
      COUNT(*) FILTER (WHERE message ILIKE '%ssl-alert%' OR message ILIKE '%ssl alert%') AS ssl_alerts
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'fortinet'
      AND (structured_data->>'subtype' = 'vpn' OR message ILIKE '%vpn%'
        OR message ILIKE '%ipsec%' OR message ILIKE '%ssl%')
  `);
  res.json(rows[0]);
}));

app.get('/api/stats/alerts-summary', asyncHandler(async (req, res) => {
  const [unacked, total24h, recent] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM alert_events WHERE acknowledged = FALSE`),
    pool.query(`SELECT COUNT(*) AS count FROM alert_events WHERE fired_at > NOW() - INTERVAL '24 hours'`),
    pool.query(`SELECT ae.fired_at, ar.name AS rule_name FROM alert_events ae LEFT JOIN alert_rules ar ON ar.id = ae.rule_id WHERE ae.acknowledged = FALSE ORDER BY ae.fired_at DESC LIMIT 3`),
  ]);
  res.json({ unacknowledged: parseInt(unacked.rows[0].count), total_24h: parseInt(total24h.rows[0].count), recent: recent.rows });
}));

app.get('/api/stats/top-services', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(structured_data->>'service', 'unknown') AS service,
      COUNT(*) AS count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'fortinet'
      AND structured_data->>'service' IS NOT NULL
      AND structured_data->>'service' != ''
    GROUP BY structured_data->>'service'
    ORDER BY count DESC
    LIMIT 8
  `);
  res.json({ data: rows });
}));

app.get('/api/stats/firewall-actions', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(structured_data->>'action', 'unknown') AS action,
      COUNT(*) AS count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
      AND vendor = 'fortinet'
      AND structured_data->>'action' IS NOT NULL
    GROUP BY structured_data->>'action'
    ORDER BY count DESC
    LIMIT 10
  `);
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
    pool.query(`SELECT pg_size_pretty(pg_database_size('logvault')) AS db_size, pg_database_size('logvault') AS db_size_bytes, pg_size_pretty(pg_total_relation_size('syslog_entries')) AS table_size, pg_total_relation_size('syslog_entries') AS table_size_bytes, (SELECT COUNT(*) FROM syslog_entries) AS total_rows, (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - INTERVAL '24 hours') AS rows_24h, (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - INTERVAL '7 days') AS rows_7d`),
    pool.query(`SELECT DATE_TRUNC('day', received_at) AS day, COUNT(*) AS log_count FROM syslog_entries WHERE received_at > NOW() - INTERVAL '7 days' GROUP BY day ORDER BY day`),
    pool.query(`SELECT MIN(received_at) AS oldest_log FROM syslog_entries`),
    pool.query(`SELECT EXTRACT(DAY FROM (NOW() - MIN(received_at))) AS days_stored FROM syslog_entries`),
  ]);
  const s = sizes.rows[0];
  const avgPerDay = s.rows_7d > 0 ? Math.round(parseInt(s.table_size_bytes) / Math.max(parseFloat(retention.rows[0]?.days_stored || 1), 1)) : 0;
  res.json({ db_size: s.db_size, db_size_bytes: parseInt(s.db_size_bytes), table_size: s.table_size, table_size_bytes: parseInt(s.table_size_bytes), total_rows: parseInt(s.total_rows), rows_24h: parseInt(s.rows_24h), rows_7d: parseInt(s.rows_7d), oldest_log: oldest.rows[0]?.oldest_log, days_stored: parseFloat(retention.rows[0]?.days_stored || 0).toFixed(1), avg_bytes_per_day: avgPerDay, avg_size_per_day: avgPerDay > 0 ? formatBytes(avgPerDay) : 'N/A', daily_breakdown: growth.rows });
}));

// ── HEALTH CHECK ─────────────────────────────────────────────

app.get('/api/health', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`SELECT COUNT(*) AS total FROM syslog_entries WHERE received_at > NOW() - INTERVAL '1 hour'`);
  res.json({ status: 'ok', logs_last_hour: parseInt(rows[0].total) });
}));

// ── ERROR HANDLER ────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[API Error]', err.message);
  res.status(500).json({ error: err.message });
});

// ── WebSocket: Live Tail ─────────────────────────────────────
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws/live' });

// Start from the latest log ID so Live Tail shows only new logs
let lastId    = BigInt(0);
let lastIdSet = false;

async function initLastId() {
  try {
    const { rows } = await pool.query('SELECT MAX(id) AS max_id FROM syslog_entries');
    if (rows[0].max_id) {
      lastId    = BigInt(rows[0].max_id);
      lastIdSet = true;
      console.log(`[WS] Live Tail starting from log ID ${lastId}`);
    }
  } catch (err) {
    console.error('[WS] Failed to init lastId:', err.message);
  }
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
  } catch (err) {
    console.error('[WS] Broadcast error:', err.message);
  }
}

// Init lastId on startup then poll every 2 seconds
initLastId().then(() => {
  setInterval(broadcastNewLogs, 2000);
});

server.listen(port, () => {
  console.log(`LogVault API + WebSocket running on port ${port}`);
});
