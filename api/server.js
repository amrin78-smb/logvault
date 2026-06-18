/**
 * LogVault API Server
 * REST API + WebSocket for the LogVault Next.js frontend
 * Port: 3005 (internal)
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const { Pool } = require('pg');
const http     = require('http');
const { WebSocketServer } = require('ws');
const { testEmail } = require('../collector/emailer');
const { rbacMiddleware, requireSuperAdmin, requireAdmin, getSiteFilter } = require('./rbac');
const { getLicense, getLicenseState } = require('./licenseCheck');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

// App version — single source of truth is the root package.json.
const { version } = require('../package.json');
// Raw GitHub base for remote version/changelog checks (no auth, public repo).
const GH_RAW = 'https://raw.githubusercontent.com/amrin78-smb/logvault/main';

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

// RBAC — attaches req.rbac (role + allowed site IDs) from the proxy's
// X-User-Id / X-User-Role headers. Must run before any route handler.
app.use(rbacMiddleware);

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

// ── In-memory stat cache ──────────────────────────────────────
// Dashboard stat endpoints scan ~1.9M rows on every dashboard load. Cache their
// results for a short TTL so repeated loads don't re-run the same heavy query.
const statCache = new Map();
async function getCached(key, ttlMs, fn) {
  const cached = statCache.get(key);
  if (cached && Date.now() - cached.at < ttlMs) return cached.data;
  const data = await fn();
  statCache.set(key, { data, at: Date.now() });
  return data;
}

// RBAC scope suffix for cache keys — keeps site-restricted results from leaking
// across users. null allowedSiteIds (admins) = 'all'; otherwise the sorted site list.
function rbacCacheKey(rbac) {
  if (!rbac || rbac.allowedSiteIds == null) return 'all';
  return 'sites:' + [...rbac.allowedSiteIds].sort((a, b) => a - b).join(',');
}

// ── Input validation helpers ──────────────────────────────────
function safeHours(val, max = 720) {
  const n = Math.min(parseInt(val || '24') || 24, max);
  return isNaN(n) || n <= 0 ? 24 : n;
}
function safeInt(val, def = 10, max = 500) {
  const n = parseInt(val || String(def));
  return isNaN(n) || n <= 0 ? def : Math.min(n, max);
}

// ── LICENSE ENFORCEMENT ──────────────────────────────────────
// Pulls the license from the NocVault hub (24h server cache). Never blocks on
// network failure — an unreachable hub means full access.
getLicense(true).then(lic => {
  const state = getLicenseState(lic);
  console.log(`[License] Status: ${lic?.status || 'unreachable'}, mode: ${state.mode}`);
});
setInterval(() => getLicense(true), 24 * 60 * 60 * 1000);

// License status endpoint — exempt from enforcement (read-only, GET).
app.get('/api/license-status', asyncHandler(async (req, res) => {
  const license = await getLicense();
  const state   = getLicenseState(license);
  res.json({ license, state });
}));

// Enforce license on business routes. Runs after rbacMiddleware, before routes.
async function enforceLicense(req, res, next) {
  const license = await getLicense();
  const state   = getLicenseState(license);
  req.licenseState = state;
  req.license      = license;

  if (!state.canWrite && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    // Alert acknowledgement must remain available during the grace period.
    // LogVault's acknowledge routes are PATCH (not POST as in DDIVault), so the
    // method is intentionally not constrained here.
    const isAck = req.path.includes('acknowledge');
    if (!isAck) {
      return res.status(402).json({
        error: 'License expired — write operations disabled',
        license_status: license?.status,
        days_remaining: license?.daysRemaining,
      });
    }
  }

  const exemptPaths = ['/api/health', '/api/stats', '/api/license-status', '/api/system/update-available'];
  if (state.disabled && !exemptPaths.some(p => req.path.startsWith(p))) {
    return res.status(402).json({
      error: 'License has expired. Please renew your NocVault license.',
      license_status: license?.status,
    });
  }
  next();
}

app.use(enforceLicense);

// ── DASHBOARD STATS ──────────────────────────────────────────

app.get('/api/stats/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const cacheKey = `summary:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT severity, severity_label, COUNT(*) AS log_count
      FROM syslog_entries
      WHERE received_at > NOW() - make_interval(hours => $1)
      ${sf.clause}
      GROUP BY severity, severity_label ORDER BY severity
    `, [hours, ...sf.params]);
    return { hours, data: rows };
  });
  res.json(data);
}));

app.get('/api/stats/timeline', asyncHandler(async (req, res) => {
  const hours  = safeHours(req.query.hours);
  const bucket = hours <= 6 ? '5 minutes' : hours <= 48 ? '1 hour' : '6 hours';
  const trunc  = hours <= 6 ? 'minute' : 'hour';
  const mod    = hours <= 6 ? 5 : hours <= 48 ? 1 : 6;
  const sf = getSiteFilter(req.rbac, 3, 'syslog_entries');
  const cacheKey = `timeline:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        date_trunc('${trunc}', received_at)
          - (EXTRACT(${trunc === 'minute' ? 'MINUTE' : 'HOUR'} FROM received_at)::int % $2) * INTERVAL '1 ${trunc}' AS bucket,
        severity_label,
        COUNT(*) AS log_count
      FROM syslog_entries
      WHERE received_at > NOW() - make_interval(hours => $1)
      ${sf.clause}
      GROUP BY bucket, severity_label
      ORDER BY bucket
    `, [hours, mod, ...sf.params]);
    return { hours, bucket, data: rows };
  });
  res.json(data);
}));

app.get('/api/stats/top-talkers', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const limit = safeInt(req.query.limit, 10, 50);
  const sf = getSiteFilter(req.rbac, 3, 'se');
  const cacheKey = `top-talkers:${hours}:${limit}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
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
      ${sf.clause}
      GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, se.vendor
      ORDER BY log_count DESC
      LIMIT $2
    `, [hours, limit, ...sf.params]);
    return { hours, data: rows };
  });
  res.json(data);
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
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const cacheKey = `top-security-events:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
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
      ${sf.clause}
      GROUP BY event_type
      ORDER BY count DESC
      LIMIT 7
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/stats/top-failures', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const cacheKey = `top-failures:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
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
      ${sf.clause}
      GROUP BY structured_data->>'dstip', structured_data->>'service'
      ORDER BY fail_count DESC
      LIMIT 5
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/stats/top-blocked', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const cacheKey = `top-blocked:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
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
      ${sf.clause}
      GROUP BY structured_data->>'dstip', structured_data->>'service', vendor
      ORDER BY deny_count DESC
      LIMIT 5
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
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

// Lightweight count for the header notifications bell badge
app.get('/api/alerts/unacked-count', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`SELECT COUNT(*) AS count FROM alert_events WHERE acknowledged = FALSE`);
  res.json({ count: parseInt(rows[0].count) });
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
  const { q, vendor, severity, host, ip, category } = req.query;
  const hours  = safeHours(req.query.hours, 720);
  const page   = Math.max(parseInt(req.query.page || '1'), 1);
  const limit  = safeInt(req.query.limit, 100, 500);
  const offset = (page - 1) * limit;

  const conditions = [`se.received_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (q)        { conditions.push(`to_tsvector('english', se.message) @@ plainto_tsquery('english', $${p++})`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                        params.push(vendor); }
  if (category) { conditions.push(`se.category = $${p++}`);                      params.push(category); }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => !isNaN(n) && n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`);     params.push(sevs); }
  }
  if (host)     {
    conditions.push(`(se.source_host ILIKE $${p++} OR kh.hostname ILIKE $${p++} OR se.source_ip::TEXT ILIKE $${p++})`);
    params.push(`%${host}%`, `%${host}%`, `%${host}%`); p += 2;
  }
  if (ip)       { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`);           params.push(`%${ip}%`); }

  // RBAC site filter — restrict to the user's allowed sites
  const sf = getSiteFilter(req.rbac, p, 'se');
  if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }

  params.push(limit, offset);

  const { rows } = await pool.query(`
    SELECT se.id, se.received_at, se.log_timestamp, se.source_ip::TEXT,
      COALESCE(kh.hostname, se.source_host) AS source_host,
      se.facility_label, se.severity, se.severity_label, se.vendor,
      se.program, se.message, se.structured_data, se.is_parsed,
      se.category, se.risk_score
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
  const sf = getSiteFilter(req.rbac, 2, 'se');
  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host,
      se.source_ip::TEXT, se.severity_label, se.vendor, se.message
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.severity <= 3 AND se.received_at > NOW() - make_interval(hours => $1)
    ${sf.clause}
    ORDER BY se.received_at DESC LIMIT 50
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

// ── ALERT RULES ──────────────────────────────────────────────

app.get('/api/alerts/rules', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM alert_rules ORDER BY id');
  res.json({ data: rows });
}));

// Lightweight alert-rule list for per-rule email configuration in Settings.
app.get('/api/alert-rules', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, name, description, notify_email, is_enabled FROM alert_rules ORDER BY id'
  );
  res.json({ data: rows });
}));

// Update the per-rule notification recipient(s) for one alert rule.
app.put('/api/alert-rules/:id/notify', requireAdmin, asyncHandler(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id < 1) return res.status(400).json({ error: 'Invalid rule id' });
  let { notify_email } = req.body;
  if (notify_email == null) notify_email = '';
  if (typeof notify_email !== 'string' || notify_email.length > 500)
    return res.status(400).json({ error: 'Invalid notify_email' });
  const { rows } = await pool.query(
    'UPDATE alert_rules SET notify_email = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, description, notify_email, is_enabled',
    [notify_email.trim(), id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Rule not found' });
  res.json({ data: rows[0] });
}));

app.post('/api/alerts/rules', requireAdmin, asyncHandler(async (req, res) => {
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

app.patch('/api/alerts/rules/:id', requireAdmin, asyncHandler(async (req, res) => {
  const { is_enabled } = req.body;
  const { rows } = await pool.query(
    'UPDATE alert_rules SET is_enabled=$1, updated_at=NOW() WHERE id=$2 RETURNING *',
    [is_enabled, req.params.id]
  );
  res.json({ data: rows[0] });
}));

app.get('/api/alerts/events', asyncHandler(async (req, res) => {
  const sf = getSiteFilter(req.rbac, 1, 'ae');
  const { rows } = await pool.query(`
    SELECT ae.*, ar.name AS rule_name
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE TRUE
    ${sf.clause}
    ORDER BY ae.acknowledged ASC, ae.fired_at DESC
    LIMIT 500
  `, sf.params);
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
  const sf = getSiteFilter(req.rbac, 1, 'ae');
  const { rows } = await pool.query(`
    SELECT ae.id, ae.fired_at, ae.source_host, ae.source_ip, ae.sample_message AS message,
      ar.name AS rule_name
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE ae.acknowledged = FALSE
    ${sf.clause}
    ORDER BY ae.fired_at DESC
    LIMIT 5
  `, sf.params);
  res.json({ data: rows });
}));

// CSV export
app.get('/api/logs/export', asyncHandler(async (req, res) => {
  const { q, vendor, severity, host, ip, category } = req.query;
  const hours = safeHours(req.query.hours, 720);

  const conditions = [`se.received_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (q)        { conditions.push(`to_tsvector('english', se.message) @@ plainto_tsquery('english', $${p++})`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                   params.push(vendor); }
  if (category) { conditions.push(`se.category = $${p++}`);                 params.push(category); }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => !isNaN(n) && n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`); params.push(sevs); }
  }
  if (host) {
    conditions.push(`(se.source_host ILIKE $${p++} OR kh.hostname ILIKE $${p++} OR se.source_ip::TEXT ILIKE $${p++})`);
    params.push(`%${host}%`, `%${host}%`, `%${host}%`); p += 2;
  }
  if (ip) { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`); params.push(`%${ip}%`); }

  // RBAC site filter — restrict export to the user's allowed sites
  const sf = getSiteFilter(req.rbac, p, 'se');
  if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }

  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host,
      se.source_ip::TEXT, se.severity_label, se.vendor, se.program,
      se.category, se.risk_score, se.message
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE ${conditions.join(' AND ')}
    ORDER BY se.received_at DESC
    LIMIT 10000
  `, params);

  // Build CSV
  const header = 'Time,Host,Source IP,Severity,Vendor,Program,Category,Risk Score,Message\n';
  const csvRows = rows.map(r => [
    r.received_at, r.source_host || '', r.source_ip || '',
    r.severity_label, r.vendor, r.program || '',
    r.category || '', r.risk_score != null ? r.risk_score : '',
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
  // known_hosts carries site_id directly, so filter on it rather than via the
  // source_ip subquery getSiteFilter builds. Admins (null) see all; a user with
  // no sites ([]) sees none; otherwise restrict to the user's assigned sites.
  const rbac = req.rbac;
  let where = '';
  let params = [];
  if (rbac && rbac.allowedSiteIds !== null && rbac.allowedSiteIds !== undefined) {
    if (rbac.allowedSiteIds.length === 0) {
      where = 'WHERE 1=0';
    } else {
      where = 'WHERE site_id = ANY($1::int[])';
      params = [rbac.allowedSiteIds];
    }
  }
  const { rows } = await pool.query(`
    SELECT ip_address::TEXT, hostname, vendor, description,
      site_name, brand, model, device_status, lifecycle_status,
      synced_from_nv, last_synced, last_seen
    FROM known_hosts
    ${where}
    ORDER BY synced_from_nv DESC, last_seen DESC
  `, params);
  res.json({ data: rows });
}));

app.put('/api/hosts', requireAdmin, asyncHandler(async (req, res) => {
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
app.post('/api/hosts/sync-netvault', requireSuperAdmin, asyncHandler(async (req, res) => {
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
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-interfaces:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT received_at, source_host, source_ip::TEXT, message,
        structured_data->>'interface'   AS interface,
        structured_data->>'link_state'  AS link_state,
        structured_data->>'subcategory' AS subcategory
      FROM syslog_entries
      WHERE received_at > NOW() - make_interval(hours => $1)
        AND vendor = 'cisco'
        AND structured_data->>'category' = 'interface'
      ${sf.clause}
      ORDER BY received_at DESC LIMIT 200
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/flaps', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-flaps:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
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
      ${sf.clause}
      GROUP BY source_host, source_ip, structured_data->>'interface'
      HAVING COUNT(*) >= 2
      ORDER BY event_count DESC LIMIT 50
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/stp', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-stp:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
        structured_data->>'subcategory' AS subcategory,
        structured_data->>'interface'   AS interface,
        structured_data->>'mac_address' AS mac_address
      FROM syslog_entries
      WHERE received_at > NOW() - make_interval(hours => $1)
        AND vendor = 'cisco'
        AND structured_data->>'category' IN ('stp','loop')
      ${sf.clause}
      ORDER BY received_at DESC LIMIT 200
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/macflaps', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-macflaps:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
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
      ${sf.clause}
      GROUP BY source_host, source_ip, structured_data->>'mac_address'
      ORDER BY flap_count DESC LIMIT 50
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/config-changes', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-config-changes:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
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
      ${sf.clause}
      ORDER BY received_at DESC LIMIT 100
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/routing', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-routing:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
        structured_data->>'subcategory' AS protocol
      FROM syslog_entries
      WHERE received_at > NOW() - make_interval(hours => $1)
        AND vendor = 'cisco'
        AND structured_data->>'category' = 'routing'
      ${sf.clause}
      ORDER BY received_at DESC LIMIT 100
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/device-status', asyncHandler(async (req, res) => {
  // Heavy aggregation over the syslog table — cache for 60s (device status
  // changes slowly) so dashboard refreshes don't re-run it on every load.
  // 24h window (was 7 days): scans ~100K rows instead of ~750K. The only
  // cache-key variation is the RBAC scope.
  const hours = 24; // fixed 24h window for this endpoint
  const sf = getSiteFilter(req.rbac, 1, 'se');
  const cacheKey = `device-status:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
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
      WHERE se.received_at > NOW() - make_interval(hours => 24)
      ${sf.clause}
      GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, kh.description, se.vendor
      ORDER BY last_seen DESC
    `, sf.params);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/health/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const data = await getCached(`health-summary:${hours}:${rbacCacheKey(req.rbac)}`, 30000, async () => {
    const [iface, stp, mac, cfg, rt] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='cisco' AND structured_data->>'category'='interface' ${sf.clause}`, [hours, ...sf.params]),
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='cisco' AND structured_data->>'category' IN ('stp','loop') ${sf.clause}`, [hours, ...sf.params]),
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory'='mac_flap' ${sf.clause}`, [hours, ...sf.params]),
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (structured_data->>'subcategory'='config_change' OR message ILIKE '%configured from%') ${sf.clause}`, [hours, ...sf.params]),
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='cisco' AND structured_data->>'category'='routing' ${sf.clause}`, [hours, ...sf.params]),
    ]);
    return { hours, interface_events: parseInt(iface.rows[0].count), stp_loop_events: parseInt(stp.rows[0].count), mac_flap_events: parseInt(mac.rows[0].count), config_changes: parseInt(cfg.rows[0].count), routing_events: parseInt(rt.rows[0].count) };
  });
  res.json(data);
}));

// ── SECURITY ─────────────────────────────────────────────────

app.get('/api/security/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf  = getSiteFilter(req.rbac, 2, 'syslog_entries'); // bare-table subqueries
  const sfA = getSiteFilter(req.rbac, 2, 'a');               // alias 'a' subquery
  const [authFail, denies, vpn, ips, afterHours, bruteSuccess] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND ((vendor='cisco' AND structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force')) OR (vendor='fortinet' AND message ILIKE '%failed%' AND message ILIKE '%login%') OR (vendor='aruba' AND message ILIKE '%authentication failed%') OR message ILIKE '%authentication failure%') ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action' = 'deny' ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND (structured_data->>'subtype' = 'vpn' OR message ILIKE '%vpn%') ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type' = 'utm' ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') OR message ILIKE '%login failed%' OR message ILIKE '%configured from%') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19 ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(DISTINCT a.source_ip) AS count
      FROM syslog_entries a
      INNER JOIN syslog_entries b ON b.source_ip = a.source_ip
        AND b.vendor = 'cisco'
        AND b.structured_data->>'subcategory' = 'login_failed'
        AND b.received_at > NOW() - make_interval(hours => $1)
      WHERE a.received_at > NOW() - make_interval(hours => $1)
        AND a.vendor = 'cisco'
        AND a.structured_data->>'subcategory' = 'login_success'
      ${sfA.clause}`, [hours, ...sfA.params]),
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
  const sf = getSiteFilter(req.rbac, 2, 'se');
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
    ${sf.clause}
    GROUP BY se.source_ip, se.source_host, kh.hostname, se.vendor
    ORDER BY failure_count DESC LIMIT 50
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

app.get('/api/security/brute-force', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 3, 'syslog_entries');
  const { rows } = await pool.query(`
    WITH failures AS (
      SELECT source_ip, MIN(received_at) AS first_fail, MAX(received_at) AS last_fail, COUNT(*) AS fail_count
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1)
        AND ((vendor='cisco' AND structured_data->>'subcategory' IN ('login_failed','auth_failed'))
          OR message ILIKE '%login failed%' OR message ILIKE '%authentication fail%')
      ${sf.clause}
      GROUP BY source_ip
    ),
    successes AS (
      SELECT source_ip, MIN(received_at) AS success_time, message AS success_msg
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $2)
        AND ((vendor='cisco' AND structured_data->>'subcategory' = 'login_success')
          OR message ILIKE '%login success%' OR message ILIKE '%authenticated%')
      ${sf.clause}
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
  `, [hours, hours, ...sf.params]);
  res.json({ data: rows });
}));

app.get('/api/security/firewall-denies', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const [bySrc, byDst, bySvc] = await Promise.all([
    pool.query(`SELECT structured_data->>'srcip' AS src_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'dstip') FILTER (WHERE structured_data->>'dstip' IS NOT NULL) AS destinations FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='deny' AND structured_data->>'srcip' IS NOT NULL ${sf.clause} GROUP BY structured_data->>'srcip' ORDER BY deny_count DESC LIMIT 15`, [hours, ...sf.params]),
    pool.query(`SELECT structured_data->>'dstip' AS dst_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'srcip') FILTER (WHERE structured_data->>'srcip' IS NOT NULL) AS sources FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='deny' AND structured_data->>'dstip' IS NOT NULL ${sf.clause} GROUP BY structured_data->>'dstip' ORDER BY deny_count DESC LIMIT 15`, [hours, ...sf.params]),
    pool.query(`SELECT COALESCE(structured_data->>'service','unknown') AS service, COUNT(*) AS deny_count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='deny' ${sf.clause} GROUP BY structured_data->>'service' ORDER BY deny_count DESC LIMIT 10`, [hours, ...sf.params]),
  ]);
  res.json({ by_source: bySrc.rows, by_destination: byDst.rows, by_service: bySvc.rows });
}));

app.get('/api/security/vpn-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'srcip' AS vpn_src_ip, structured_data->>'msg' AS detail,
      CASE WHEN message ILIKE '%fail%' OR message ILIKE '%error%' THEN 'failure'
           WHEN message ILIKE '%success%' OR message ILIKE '%connected%' THEN 'success'
           ELSE 'info' END AS event_type
    FROM syslog_entries
    WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet'
      AND (structured_data->>'subtype'='vpn' OR message ILIKE '%ssl vpn%' OR message ILIKE '%ipsec%' OR message ILIKE '%vpn%')
    ${sf.clause}
    ORDER BY received_at DESC LIMIT 100
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

app.get('/api/security/ips-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const [events, byThreat] = await Promise.all([
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, severity_label, message, structured_data->>'srcip' AS src_ip, structured_data->>'dstip' AS dst_ip, structured_data->>'msg' AS threat_name, structured_data->>'action' AS action, structured_data->>'subtype' AS subtype FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type'='utm' ${sf.clause} ORDER BY received_at DESC LIMIT 100`, [hours, ...sf.params]),
    pool.query(`SELECT COALESCE(structured_data->>'msg','Unknown') AS threat, structured_data->>'subtype' AS subtype, COUNT(*) AS hit_count, COUNT(DISTINCT structured_data->>'srcip') AS unique_sources FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type'='utm' ${sf.clause} GROUP BY structured_data->>'msg', structured_data->>'subtype' ORDER BY hit_count DESC LIMIT 20`, [hours, ...sf.params]),
  ]);
  res.json({ events: events.rows, by_threat: byThreat.rows });
}));

app.get('/api/security/after-hours', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours, 720);
  const sf = getSiteFilter(req.rbac, 2, 'se');
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
    ${sf.clause}
    ORDER BY se.received_at DESC LIMIT 100
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

app.get('/api/security/wireless-auth', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  const [failures, summary] = await Promise.all([
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, message, severity_label FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='aruba' AND message ILIKE '%authentication failed%' ${sf.clause} ORDER BY received_at DESC LIMIT 50`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) FILTER (WHERE message ILIKE '%failed%') AS failures, COUNT(*) FILTER (WHERE message ILIKE '%success%' OR message ILIKE '%authenticated%') AS successes, COUNT(DISTINCT source_ip) AS devices FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='aruba' AND (message ILIKE '%authentication%' OR message ILIKE '%802.1x%') ${sf.clause}`, [hours, ...sf.params]),
  ]);
  res.json({ failures: failures.rows, summary: summary.rows[0] });
}));

// ── DISK SPACE ───────────────────────────────────────────────
const { execSync } = require('child_process');
const path = require('path');

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

// ── SYSTEM UPDATES (Check for Updates) ───────────────────────
// Compares the local checkout against origin/main via git, and launches the
// updater through a one-time Windows Scheduled Task running as SYSTEM (fully
// detached from this service's process tree, so it survives the service stop).
// Super-admin only. No RBAC site filtering applies to these endpoints.
const appRoot = path.join(__dirname, '..');

// ── Git-commit-based update check (commit hash + package.json) ───────────────
// Update detection compares the local git commit hash against the latest commit
// on GitHub's main branch — ANY new commit counts as an update, even when the
// package.json version is unchanged (fixes updates being missed when code is
// pushed without bumping the version). The version + release notes are display-only.
// Never blocks on network failure.

// Local short git commit hash for the deployed checkout, or null if git is
// unavailable (e.g. a non-git deploy). Update detection degrades gracefully.
function localCommitHash() {
  try {
    return execSync('git rev-parse HEAD', { cwd: appRoot })
      .toString().trim().slice(0, 7);
  } catch {
    return null;
  }
}

// Structured release notes keyed by version. The update-status endpoint surfaces
// these as a bullet list in the Settings UI — there is no CHANGELOG.md. When
// bumping the version, add a matching entry here with 3-5 bullets.
const releaseNotes = {
  '1.3.3': [
    'Adopted the suite-standard colored nav icon chips (only the active item is colored)',
    'Nav labels bumped to 14px for suite parity',
    'Larger 38px header icon-buttons (notifications bell + dark-mode toggle)',
  ],
  '1.2.0': [
    'Enterprise dashboard with health score and charts',
    'Animated login page redesign',
    'Server status monitoring',
    'Automatic versioning across suite',
  ],
  '1.2.1': [
    'More reliable auto-reload after applying an update',
    'Extended the update recovery window so slower builds finish cleanly',
    'Cleaner update screen with structured release notes',
    'Removed the legacy CHANGELOG file',
  ],
  '1.2.2': [
    'Standardized Settings page styling to match NocVault suite',
    'Underline-style settings tabs replace the filled pill bar',
    'Primary buttons now use the brand crimson instead of off-brand blue',
    'Uniform card, section-header, and input styling across the Settings page',
  ],
  '1.2.3': [
    'Standardized Settings menu (renamed System to General, reordered tabs)',
    'General is now the first tab and the default Settings landing tab',
  ],
  '1.2.5': [
    'Standardized Updates and About tabs to NocVault suite spec',
    'Unified update warning, confirm, and overlay wording across the suite',
    'License-blocked updates now show the standard "Manage License" link',
    'About tab heading and tech-spec rows aligned to the suite standard',
  ],
  '1.2.6': [
    'Tightened card corners and elevation for a cleaner operations-console look',
    'Calibrated radii to the NocVault suite standard (8px cards/panels, 6px controls)',
    'Downgraded heavy drop shadows on cards, dropdowns, and modals to a subtle border + faint shadow',
    'Trimmed overly generous card padding by one step for a denser, enterprise feel',
    'Kept pills, badges, status dots, and avatars rounded — visual-only calibration, no layout changes',
  ],
  '1.2.7': [
    'Standardized typography on the NocVault suite-wide 7-step type scale',
    'Collapsed ~23 ad-hoc font sizes onto 7 shared scale tokens for consistent log density',
    'Unified all monospace text on a single shared font token across log and detail views',
    'Replaced hardcoded colors that duplicated theme tokens, fixing dark-mode color bugs',
    'Preserved intentional severity/vendor palettes and display-size numbers',
  ],
  '1.2.8': [
    'Aligned the neutral color palette to the NocVault suite for a consistent look when switching apps',
    'Switched the page background and neutral text/border tokens to the shared suite slate ramp',
    'Swept leftover hardcoded gray colors in dashboards, alerts, and log views onto theme tokens',
    'Improved dark-mode consistency by removing off-token surface and text colors',
    'Kept severity, vendor, and chart-series palettes intentionally untouched',
  ],
  '1.2.9': [
    'Fixed active tabs/pills and range-preset buttons rendering invisible (white-on-white) in dark mode after the palette alignment',
    'Restored the intentional dark fill on active section-nav pills so they stay dark in both light and dark themes',
    'No change to light-mode appearance; only the wrong-direction theme mapping was reverted',
  ],
  '1.2.10': [
    'Fixed the Total Logs KPI value being unreadable (dark-on-dark) in dark mode — it now uses an adapting text color',
    'Top Blocked Destinations list now scrolls within its card instead of overflowing the bottom border',
    'Top Blocked Destinations panel now matches the padding/height of its sibling dashboard widgets',
  ],
  '1.3.0': [
    'Sidebar is now collapsible (240↔64px) with a chevron toggle, matching the rest of the NocVault suite',
    'Collapse state is remembered across refreshes; collapsed view shows icon-only nav with tooltips',
    'Pinned the sidebar to the viewport so the version/footer stays at the bottom of the screen instead of the bottom of a long dashboard',
  ],
  '1.3.1': [
    'Tightened the dashboard KPI tiles — shorter cards and a smaller stat number for a denser, cleaner header row',
    'Added an accent-colored icon to each KPI tile (Total, Critical, Errors, Warnings)',
    'Aligned the KPI number to the shared suite type scale',
  ],
  '1.3.2': [
    'Top bar is now sticky — it stays visible while scrolling instead of disappearing, matching the rest of the NocVault suite',
    'Aligned the pinned sidebar to the 72px header height so the two tuck together cleanly while scrolling',
  ],
  '1.3.4': [
    'Alert and update banners now span only the main content area instead of the full screen, so the sidebar stays full-height beside them — matching the rest of the NocVault suite',
  ],
  'default': [
    'Bug fixes and performance improvements',
  ],
};

// Cached result for the slim update-notifier banner. { current, latest } when an
// update exists, else null. Refreshed on startup + every 24h.
let updateAvailable = null;

async function checkForUpdates() {
  try {
    const localHash = localCommitHash();
    const [commitRes, pkgRes] = await Promise.all([
      fetch('https://api.github.com/repos/amrin78-smb/logvault/commits/main', {
        headers: { 'Accept': 'application/vnd.github.v3+json' },
        cache: 'no-store',
      }),
      fetch(`${GH_RAW}/package.json?cb=${Date.now()}`, { cache: 'no-store' }),
    ]);
    const commit = await commitRes.json();
    const remoteHash = commit && commit.sha ? String(commit.sha).slice(0, 7) : null;
    const remotePkg = await pkgRes.json();

    // Any differing commit = update available. If either hash is missing,
    // keep the last known state so a blip never shows a false banner.
    updateAvailable = (localHash && remoteHash && remoteHash !== localHash)
      ? { current: version, latest: remotePkg.version }
      : null;
  } catch {
    // never block on network failure — keep the last known state
  }
}

// Lightweight, unauthenticated endpoint feeding the update-notifier banner.
app.get('/api/system/update-available', (_req, res) => {
  if (updateAvailable) {
    res.json({ available: true, current: updateAvailable.current, latest: updateAvailable.latest });
  } else {
    res.json({ available: false });
  }
});

// Compares the local git commit hash against the latest commit on GitHub's main
// branch. ANY differing commit counts as an update available — package.json
// version is for display only. Never 500s the Settings page — a fetch failure
// degrades to "up to date" with an error string.
app.get('/api/system/update-status', requireSuperAdmin, asyncHandler(async (req, res) => {
  const localVersion = version;
  const localHash = localCommitHash();
  try {
    // Cache-bust so GitHub's raw CDN can't return a stale copy — the Settings
    // "Re-check" button must reflect a freshly pushed commit immediately.
    const bust = Date.now();
    const [commitRes, pkgRes] = await Promise.all([
      fetch('https://api.github.com/repos/amrin78-smb/logvault/commits/main', {
        headers: { 'Accept': 'application/vnd.github.v3+json' },
        cache: 'no-store',
      }),
      fetch(`${GH_RAW}/package.json?cb=${bust}`, { cache: 'no-store' }),
    ]);
    const commit = await commitRes.json();
    const remoteHash = commit && commit.sha ? String(commit.sha).slice(0, 7) : null;
    const remotePkg = await pkgRes.json();
    const remoteVersion = remotePkg.version;

    // Release notes keyed by the latest version, with a generic fallback.
    const release_notes = releaseNotes[remoteVersion] || releaseNotes['default'];

    // Any differing commit = update available. If either hash is missing
    // (e.g. git unavailable or API error), treat as up to date to avoid
    // false alarms.
    const updateAvail = !!remoteHash && !!localHash && remoteHash !== localHash;
    // Keep the cached banner state in sync with this on-demand check.
    updateAvailable = updateAvail ? { current: localVersion, latest: remoteVersion } : null;
    res.json({
      current_version:  localVersion,
      latest_version:   remoteVersion,
      current_commit:   localHash,
      latest_commit:    remoteHash,
      current_hash:     localHash,
      latest_hash:      remoteHash,
      up_to_date:       !updateAvail,
      update_available: updateAvail,
      release_notes,
      release_date:     new Date().toISOString().slice(0, 10),
    });
  } catch (err) {
    console.error('[update-status] version check failed:', err.message);
    res.json({ current_version: localVersion, up_to_date: true, error: 'Could not check for updates' });
  }
}));

app.post('/api/system/update', requireSuperAdmin, asyncHandler(async (req, res) => {
  // Block updates when the license is expired/disabled or in the grace period.
  const license = await getLicense();
  const state   = getLicenseState(license);

  if (state.disabled) {
    return res.status(402).json({
      error: 'License expired — updates disabled. Please renew your NocVault license.',
      license_status: license?.status,
    });
  }

  if (state.mode === 'grace') {
    return res.status(402).json({
      error: 'License is in grace period — updates disabled. Please renew your NocVault license.',
      license_status: license?.status,
      days_remaining: license?.daysRemaining,
    });
  }

  const serverIp = process.env.SERVER_IP || '';
  if (!serverIp) {
    return res.status(400).json({ error: 'SERVER_IP not configured in .env.local' });
  }

  const scriptPath = path.join(appRoot, 'installer', 'Update-LogVault.ps1').replace(/\//g, '\\');
  try {
    // Remove any leftover task from a previous run (ignore "not found").
    try { execSync('schtasks /delete /tn "LogVaultUpdate" /f', { stdio: 'ignore' }); } catch (_e) { /* none */ }

    // Create a one-time task under the SYSTEM account (full permissions, detached).
    execSync(
      `schtasks /create /tn "LogVaultUpdate" ` +
      `/tr "powershell.exe -NonInteractive -ExecutionPolicy Bypass ` +
      `-File \\"${scriptPath}\\" -InstallDir \\"C:\\\\Apps\\\\logvault\\" ` +
      `-ServerIp \\"${serverIp}\\"" ` +
      `/sc once /st 00:00 /f /ru SYSTEM`,
      { stdio: 'pipe' }
    );

    // Run it immediately.
    execSync('schtasks /run /tn "LogVaultUpdate"', { stdio: 'pipe' });

    console.log('[Update] Task scheduled under SYSTEM, ServerIp:', serverIp);
    res.json({ started: true });
  } catch (err) {
    console.error('[Update] schtasks error:', err.message);
    res.status(500).json({ error: 'Failed to schedule update: ' + err.message });
  }
}));

// ── APP SETTINGS ─────────────────────────────────────────────

app.get('/api/settings', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM app_settings');
  const data = Object.fromEntries(rows.map(r => [r.key, r.value]));
  // Never expose the SMTP password to anyone but a super_admin (only role that
  // can edit it). Settings writes are already super_admin-gated.
  if (!req.rbac || !req.rbac.isSuperAdmin) {
    delete data.smtp_pass;
  }
  res.json({ data });
}));

app.post('/api/settings', requireSuperAdmin, asyncHandler(async (req, res) => {
  const allowed = ['app_name', 'app_subtitle', 'primary_color', 'sidebar_color', 'logo_url',
    'dns_server', 'dns_lookup_enabled',
    'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_from', 'smtp_enabled',
    'email_notify_enabled', 'email_notify_severities', 'email_notify_categories',
    'email_notify_vendors', 'email_notify_min_risk', 'email_notify_digest_mode',
    'email_notify_digest_hour', 'email_notify_recipients', 'email_notify_cooldown_mins'];
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

// Send a test email immediately using the provided (unsaved) SMTP settings.
app.post('/api/settings/test-email', requireSuperAdmin, asyncHandler(async (req, res) => {
  const { to, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from } = req.body;
  if (!to || typeof to !== 'string') {
    return res.status(400).json({ error: 'Recipient address (to) is required' });
  }
  const override = smtp_host
    ? { host: smtp_host, port: smtp_port, user: smtp_user, pass: smtp_pass, from: smtp_from }
    : undefined;
  const result = await testEmail(to, pool, override);
  if (result.ok) {
    res.json({ ok: true });
  } else {
    res.status(400).json({ error: result.error || 'Failed to send test email' });
  }
}));

// ── HEALTH CHECK ─────────────────────────────────────────────

app.get('/api/health', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`SELECT COUNT(*) AS total FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => 1)`);
  res.json({ status: 'ok', version, logs_last_hour: parseInt(rows[0].total) });
}));

// ── PUBLIC STATS ──────────────────────────────────────────────
// No-auth, read-only summary counters for external/cross-origin dashboards.
// Same access level as /api/health (license-exempt). Permissive CORS since the
// global cors() middleware restricts to the frontend origin only. Never 500s:
// on any DB error, returns zeros with HTTP 200.
app.get('/api/stats', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  try {
    const [logsToday, sources, alerts] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS c FROM syslog_entries WHERE received_at > NOW() - INTERVAL '24 hours'`),
      pool.query(`SELECT COUNT(DISTINCT source_ip) AS c FROM syslog_entries WHERE received_at > NOW() - INTERVAL '24 hours'`),
      pool.query(`SELECT COUNT(*) AS c FROM alert_events WHERE acknowledged = FALSE`),
    ]);
    res.json({
      logs_today:    parseInt(logsToday.rows[0].c, 10),
      log_sources:   parseInt(sources.rows[0].c, 10),
      active_alerts: parseInt(alerts.rows[0].c, 10),
    });
  } catch (err) {
    console.error('[API /api/stats]', err.message);
    res.json({ logs_today: 0, log_sources: 0, active_alerts: 0 });
  }
});

// ── WEBSOCKET AUTH TICKET ─────────────────────────────────────
// The Live Tail WebSocket connects directly to this API (port 3005), bypassing
// the Next proxy, so it never receives the verified X-User-* headers — and we
// deliberately cannot decode the next-auth JWE cookie here. Instead the client
// first calls GET /api/ws-ticket THROUGH the authenticated proxy (which stamps
// the verified role), and we issue a short-lived HMAC-signed ticket carrying the
// user's role + allowed site IDs. The WS upgrade then presents that ticket. The
// signing key is random per-process (issue + verify happen in this same
// process), so a client can neither forge a ticket nor tamper with its role.
const WS_TICKET_KEY = crypto.randomBytes(32);
const WS_TICKET_TTL_MS = 30 * 1000; // ticket must be used within 30s of issue

function issueWsTicket(rbac) {
  const payload = {
    role:  rbac ? rbac.role : 'user',
    // null = admin (all sites); [] = no sites; [..] = specific sites
    sites: rbac ? (rbac.allowedSiteIds ?? null) : [],
    exp:   Date.now() + WS_TICKET_TTL_MS,
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', WS_TICKET_KEY).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyWsTicket(ticket) {
  if (!ticket || typeof ticket !== 'string') return null;
  const dot = ticket.indexOf('.');
  if (dot < 1) return null;
  const body = ticket.slice(0, dot);
  const sig  = ticket.slice(dot + 1);
  const expected = crypto.createHmac('sha256', WS_TICKET_KEY).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return null; }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  return payload;
}

// Issues a Live Tail ticket scoped to the caller's RBAC. req.rbac is set from
// the proxy-verified headers, so role/sites here cannot be spoofed by the client.
app.get('/api/ws-ticket', asyncHandler(async (req, res) => {
  res.json({ ticket: issueWsTicket(req.rbac) });
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

// Authenticate + scope every Live Tail client via its signed ticket. Fail
// CLOSED: a missing/invalid/expired ticket, or any error resolving the client's
// site scope, disconnects the socket rather than streaming logs.
wss.on('connection', async (ws, req) => {
  ws.ready = false;
  let ticket = null;
  try { ticket = new URL(req.url, 'http://localhost').searchParams.get('ticket'); } catch { /* no url */ }

  const auth = verifyWsTicket(ticket);
  if (!auth) { try { ws.close(1008, 'Unauthorized'); } catch { /* already closed */ } return; }

  try {
    if (auth.sites == null) {
      ws.allowedIps = null;        // admin / super_admin → all logs
    } else if (!Array.isArray(auth.sites) || auth.sites.length === 0) {
      ws.allowedIps = new Set();   // user with no sites → nothing
    } else {
      const { rows } = await pool.query(
        `SELECT ip_address::TEXT AS ip FROM known_hosts WHERE site_id = ANY($1::int[])`,
        [auth.sites]
      );
      ws.allowedIps = new Set(rows.map(r => r.ip));
    }
    ws.ready = true;
  } catch (err) {
    console.error('[WS] Failed to resolve site scope:', err.message);
    try { ws.close(1011, 'Server error'); } catch { /* already closed */ }
  }
});

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
      wss.clients.forEach(client => {
        if (client.readyState !== 1 || !client.ready) return;
        // allowedIps null = admin (all); otherwise only logs from the client's
        // assigned sites. An empty set sends nothing (fail-closed).
        const out = client.allowedIps === null
          ? rows
          : rows.filter(r => client.allowedIps.has(r.source_ip));
        if (out.length > 0) client.send(JSON.stringify({ type: 'logs', data: out }));
      });
    }
  } catch (err) { console.error('[WS] Broadcast error:', err.message); }
}

initLastId().then(() => { setInterval(broadcastNewLogs, 2000); });

// Update check: on startup + every 24h (cached for the notifier banner).
checkForUpdates();
setInterval(checkForUpdates, 24 * 60 * 60 * 1000);

server.listen(port, () => {
  console.log(`LogVault API + WebSocket running on port ${port} (v${version})`);
});
