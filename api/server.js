/**
 * LogVault API Server
 * REST API for the LogVault Next.js frontend
 * Port: 3004 (shared with Next.js via internal routing)
 *
 * Run with: node api/server.js
 * Managed by NSSM as a Windows service: LogVaultAPI
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const http     = require('http');
const { WebSocketServer } = require('ws');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const app  = express();
const port = parseInt(process.env.LV_API_PORT || '3005'); // internal API port, Next.js is on 3004

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

// ── Helper ───────────────────────────────────────────────────
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ── DASHBOARD STATS ──────────────────────────────────────────

// GET /api/stats/summary - total counts by severity for last N hours
app.get('/api/stats/summary', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      severity,
      severity_label,
      COUNT(*) AS log_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY severity, severity_label
    ORDER BY severity
  `);
  res.json({ hours, data: rows });
}));

// GET /api/stats/timeline - log volume over time (for chart)
app.get('/api/stats/timeline', asyncHandler(async (req, res) => {
  const hours    = Math.min(parseInt(req.query.hours || '24'), 168);
  const bucket   = hours <= 6 ? '5 minutes' : hours <= 48 ? '1 hour' : '6 hours';
  const { rows } = await pool.query(`
    SELECT
      time_bucket($1, received_at) AS bucket,
      severity_label,
      COUNT(*) AS log_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY bucket, severity_label
    ORDER BY bucket
  `, [bucket]);
  res.json({ hours, bucket, data: rows });
}));

// GET /api/stats/top-talkers - top sources by volume
app.get('/api/stats/top-talkers', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const limit = Math.min(parseInt(req.query.limit || '10'), 50);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(source_host, source_ip::TEXT) AS host,
      source_ip::TEXT AS source_ip,
      vendor,
      COUNT(*) AS log_count,
      MAX(received_at) AS last_seen
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY source_host, source_ip, vendor
    ORDER BY log_count DESC
    LIMIT $1
  `, [limit]);
  res.json({ hours, data: rows });
}));

// GET /api/stats/by-vendor - breakdown by vendor
app.get('/api/stats/by-vendor', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT
      vendor,
      COUNT(*) AS log_count,
      COUNT(*) FILTER (WHERE severity <= 2) AS critical_count,
      COUNT(*) FILTER (WHERE severity = 3)  AS error_count,
      COUNT(*) FILTER (WHERE severity = 4)  AS warning_count
    FROM syslog_entries
    WHERE received_at > NOW() - INTERVAL '${hours} hours'
    GROUP BY vendor
    ORDER BY log_count DESC
  `);
  res.json({ hours, data: rows });
}));

// ── LOG SEARCH ───────────────────────────────────────────────

// GET /api/logs - search and filter logs
app.get('/api/logs', asyncHandler(async (req, res) => {
  const {
    q,                           // full-text search
    vendor,                      // filter by vendor
    severity,                    // filter by severity (0-7 or comma-separated)
    host,                        // filter by source_host ILIKE
    ip,                          // filter by source_ip
    hours   = '1',
    page    = '1',
    limit   = '100',
  } = req.query;

  const conditions = [`received_at > NOW() - INTERVAL '${Math.min(parseInt(hours), 720)} hours'`];
  const params     = [];
  let p = 1;

  if (q) {
    conditions.push(`to_tsvector('english', message) @@ plainto_tsquery('english', $${p++})`);
    params.push(q);
  }
  if (vendor)   { conditions.push(`vendor = $${p++}`);               params.push(vendor); }
  if (severity) {
    const sevs = severity.split(',').map(Number).filter(n => n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`severity = ANY($${p++})`);   params.push(sevs); }
  }
  if (host)     { conditions.push(`source_host ILIKE $${p++}`);      params.push(`%${host}%`); }
  if (ip)       { conditions.push(`source_ip::TEXT ILIKE $${p++}`);  params.push(`%${ip}%`); }

  const offset = (Math.max(parseInt(page), 1) - 1) * Math.min(parseInt(limit), 500);
  const lim    = Math.min(parseInt(limit), 500);

  params.push(lim, offset);

  const { rows } = await pool.query(`
    SELECT
      id, received_at, log_timestamp, source_ip::TEXT, source_host,
      facility_label, severity, severity_label, vendor, program, message,
      structured_data, is_parsed
    FROM syslog_entries
    WHERE ${conditions.join(' AND ')}
    ORDER BY received_at DESC
    LIMIT $${p++} OFFSET $${p++}
  `, params);

  // Count query (drop ORDER/LIMIT)
  const countRes = await pool.query(
    `SELECT COUNT(*) AS total FROM syslog_entries WHERE ${conditions.join(' AND ')}`,
    params.slice(0, -2)
  );

  res.json({
    total: parseInt(countRes.rows[0].total),
    page:  parseInt(page),
    limit: lim,
    data:  rows,
  });
}));

// GET /api/logs/recent-critical - last 50 critical/error events
app.get('/api/logs/recent-critical', asyncHandler(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours || '24'), 168);
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, vendor, message
    FROM syslog_entries
    WHERE severity <= 3 AND received_at > NOW() - INTERVAL '${hours} hours'
    ORDER BY received_at DESC
    LIMIT 50
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

// GET /api/alerts/events - recent fired alerts
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
  await pool.query(
    'UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW() WHERE id=$1',
    [req.params.id]
  );
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

// ── HEALTH ───────────────────────────────────────────────────

app.get('/api/health', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT COUNT(*) AS total FROM syslog_entries WHERE received_at > NOW() - INTERVAL \'1 hour\'');
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

// Poll DB every 2s for new logs and broadcast to all connected clients
let lastId = BigInt(0);

async function broadcastNewLogs() {
  if (wss.clients.size === 0) return;
  try {
    const { rows } = await pool.query(`
      SELECT id, received_at, source_host, source_ip::TEXT, severity_label, vendor, program, message
      FROM syslog_entries
      WHERE id > $1
      ORDER BY id ASC
      LIMIT 50
    `, [lastId.toString()]);

    if (rows.length > 0) {
      lastId = BigInt(rows[rows.length - 1].id);
      const payload = JSON.stringify({ type: 'logs', data: rows });
      wss.clients.forEach(client => {
        if (client.readyState === 1) client.send(payload);
      });
    }
  } catch (err) {
    console.error('[WS] Broadcast error:', err.message);
  }
}

setInterval(broadcastNewLogs, 2000);

// ── Start ────────────────────────────────────────────────────
server.listen(port, () => {
  console.log(`LogVault API + WebSocket running on port ${port}`);
});
