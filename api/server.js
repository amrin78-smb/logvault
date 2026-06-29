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
const { rbacMiddleware, requireSuperAdmin, requireAdmin, getSiteFilter, getStatsSiteFilter, getAlertSiteFilter } = require('./rbac');
const { getLicense, getLicenseState } = require('./licenseCheck');
const { writeAudit } = require('./auditLog');
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
  const sf = getStatsSiteFilter(req.rbac, 2, 'syslog_entries');
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
  const sf = getStatsSiteFilter(req.rbac, 3, 'syslog_entries');
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
  const sf = getStatsSiteFilter(req.rbac, 3, 'se');
  const cacheKey = `top-talkers:${hours}:${limit}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    // Group by the REAL actor (structured_data.srcip), falling back to the syslog
    // sender only when no srcip was parsed. Joining/grouping on source_ip alone
    // collapses every relayed log to the single forwarding device (the firewall),
    // so the geo/known-bad enrichment is attributed to the relay, not the actor.
    const { rows } = await pool.query(`
      SELECT
        COALESCE(kh.hostname, src.actor) AS host,
        src.actor AS source_ip,
        COALESCE(kh.vendor, MAX(src.vendor)) AS vendor,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        COUNT(*) AS log_count,
        MAX(src.received_at) AS last_seen
      FROM (
        SELECT COALESCE(NULLIF(btrim(se.structured_data->>'srcip'), ''), host(se.source_ip)) AS actor,
               se.vendor, se.received_at, se.source_ip
        FROM syslog_entries se
        WHERE se.received_at > NOW() - make_interval(hours => $1)
        ${sf.clause}
      ) src
      LEFT JOIN known_hosts kh ON src.actor ~ '^[0-9.]+$' AND host(kh.ip_address) = src.actor
      GROUP BY src.actor, kh.hostname, kh.vendor, kh.country_code, kh.country_name,
        kh.asn_org, kh.abuse_score, kh.is_known_bad, kh.is_external
      ORDER BY log_count DESC
      LIMIT $2
    `, [hours, limit, ...sf.params]);
    return { hours, data: rows };
  });
  res.json(data);
}));

// Top Destinations (outbound) — mirrors top-talkers but on the DESTINATION IP
// (structured_data.dstip), the external side of firewall logs. Surfaces outbound
// C2/exfil signal. Geo/threat enrichment is joined from known_hosts on the dstip
// (the collector enriches BOTH source and destination external IPs), exactly like
// top-blocked/top-failures. Efficient on the big partitioned table: the inner
// scan is bounded by received_at (the partition key) and only touches the dstip
// JSONB field; the geo join is a LEFT JOIN on a shape-guarded text key.
app.get('/api/stats/top-destinations', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const limit = safeInt(req.query.limit, 10, 50);
  const sf = getStatsSiteFilter(req.rbac, 3, 'se');
  const cacheKey = `top-destinations:${hours}:${limit}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(kh.hostname, dst.dstip) AS host,
        dst.dstip AS dst_ip,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        COUNT(*) AS log_count,
        MAX(dst.received_at) AS last_seen
      FROM (
        SELECT btrim(se.structured_data->>'dstip') AS dstip, se.received_at
        FROM syslog_entries se
        WHERE se.received_at > NOW() - make_interval(hours => $1)
          AND se.structured_data->>'dstip' ~ '^[0-9.]+$'
        ${sf.clause}
      ) dst
      -- Join geo/threat on the destination IP (the external side). host() strips
      -- the /32 that known_hosts.ip_address (INET) renders. LEFT JOIN keeps rows
      -- with no enrichment (geo cols NULL).
      LEFT JOIN known_hosts kh ON host(kh.ip_address) = dst.dstip
      WHERE dst.dstip IS NOT NULL AND dst.dstip <> ''
      GROUP BY dst.dstip, kh.hostname, kh.country_code, kh.country_name,
        kh.asn_org, kh.abuse_score, kh.is_known_bad, kh.is_external
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
  const sf = getStatsSiteFilter(req.rbac, 2, 'syslog_entries');
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
  const sf = getStatsSiteFilter(req.rbac, 2, 'syslog_entries');
  const cacheKey = `top-failures:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(structured_data->>'dstip', 'unknown') AS dst_ip,
        COALESCE(structured_data->>'service', '') AS service,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        COUNT(*) AS fail_count
      FROM syslog_entries
      -- This widget displays the DESTINATION IP, so join geo/threat on dstip (the
      -- external IP in firewall logs), not source_ip (the internal device). Use
      -- host(ip_address): known_hosts.ip_address is INET and is stored WITH a /32
      -- mask (e.g. 17.248.154.174/32), so ip_address::text renders "…/32" and never
      -- matched the unmasked dstip string. host() strips the mask to the bare
      -- address and works on any inet. The IPv4-shape guard limits the join to
      -- address-shaped dstip values. This is a LEFT JOIN, so rows are kept even when
      -- no known_hosts match (geo cols NULL).
      LEFT JOIN known_hosts kh
        ON structured_data->>'dstip' ~ '^[0-9.]+$'
       AND host(kh.ip_address) = structured_data->>'dstip'
      WHERE received_at > NOW() - make_interval(hours => $1)
        AND (
          -- Fortinet connection failures
          (syslog_entries.vendor = 'fortinet' AND message ILIKE '%Connection Failed%')
          OR
          -- Palo Alto session end with no bytes
          (syslog_entries.vendor = 'paloalto' AND message ILIKE '%session_end%' AND message ILIKE '%bytes%0%')
          OR
          -- Cisco TCP unreachable / timeout
          (syslog_entries.vendor = 'cisco' AND (
            message ILIKE '%unreachable%'
            OR message ILIKE '%timed out%'
          ))
          OR
          -- Generic connection failure indicators
          (syslog_entries.vendor NOT IN ('fortinet','paloalto','cisco') AND (
            message ILIKE '%connection failed%'
            OR message ILIKE '%connection refused%'
            OR message ILIKE '%host unreachable%'
            OR message ILIKE '%timed out%'
          ))
        )
        AND structured_data->>'dstip' IS NOT NULL
      ${sf.clause}
      GROUP BY structured_data->>'dstip', structured_data->>'service',
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external
      ORDER BY fail_count DESC
      LIMIT 5
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

app.get('/api/stats/top-blocked', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getStatsSiteFilter(req.rbac, 2, 'syslog_entries');
  const cacheKey = `top-blocked:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(structured_data->>'dstip', 'unknown') AS dst_ip,
        COALESCE(structured_data->>'service', '') AS service,
        syslog_entries.vendor,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        COUNT(*) AS deny_count
      FROM syslog_entries
      -- This widget displays the DESTINATION IP, so join geo/threat on dstip (the
      -- external IP in firewall logs), not source_ip (the internal device). Use
      -- host(ip_address): known_hosts.ip_address is INET and is stored WITH a /32
      -- mask (e.g. 17.248.154.174/32), so ip_address::text renders "…/32" and never
      -- matched the unmasked dstip string. host() strips the mask to the bare
      -- address and works on any inet. The IPv4-shape guard limits the join to
      -- address-shaped dstip values. This is a LEFT JOIN, so rows are kept even when
      -- no known_hosts match (geo cols NULL).
      LEFT JOIN known_hosts kh
        ON structured_data->>'dstip' ~ '^[0-9.]+$'
       AND host(kh.ip_address) = structured_data->>'dstip'
      WHERE received_at > NOW() - make_interval(hours => $1)
        AND (
          -- Vendor-AGNOSTIC block detection. The old per-vendor branches missed real
          -- data (e.g. Fortinet logs the action 'blocked', Palo Alto 'deny'/'drop')
          -- and silently returned nothing. Match the actual action values seen in the
          -- data (case-insensitive), with message fallbacks for vendors (e.g. Cisco
          -- ACLs) that don't set a structured action field.
          LOWER(structured_data->>'action') IN ('deny','denied','block','blocked','drop','dropped')
          OR message ILIKE '%action=deny%'
          OR message ILIKE '%action=block%'
          OR message ILIKE '%action=blocked%'
          OR message ILIKE '%action=drop%'
          OR message ILIKE '%denied%'
          OR message ILIKE '%ACL%deny%'
        )
        AND structured_data->>'dstip' IS NOT NULL
      ${sf.clause}
      GROUP BY structured_data->>'dstip', structured_data->>'service', syslog_entries.vendor,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external
      ORDER BY deny_count DESC
      LIMIT 5
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

// MITRE ATT&CK coverage — counts of log events per technique over the window,
// derived from the event-level technique tags in structured_data.mitre. RBAC
// site-filtered on se.source_ip like every other stat endpoint. The frontend
// groups techniques into tactics via the shared catalog.
app.get('/api/stats/mitre-coverage', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  // Two RBAC site filters: one for the event branch (se.source_ip → relay → site),
  // one for the alert branch. The alert branch is scoped by the SAME relay
  // (ae.source_host → known_hosts.hostname → site) instead of ae.source_ip — the
  // internal triggering-host srcip is almost never registered with a site, so
  // keying alerts on it collapsed every alert-derived technique to zero for
  // site-scoped users while admins saw them (DB-confirmed: 1 of 50 distinct alert
  // source_ips has a site, but all alerts carry the relay in source_host). Scoping
  // by the relay keeps alert visibility consistent with event visibility and never
  // leaks another site's data. The alert filter's params start AFTER the event
  // filter's so the $-placeholders never collide.
  const sfEvents = getSiteFilter(req.rbac, 2, 'se');
  const sfAlerts = getAlertSiteFilter(req.rbac, 2 + sfEvents.params.length, 'ae');
  const cacheKey = `mitre-coverage:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      WITH event_tech AS (
        -- Event-level tags written at ingest by collector/mitreMapper.js.
        SELECT t.technique AS technique, COUNT(*)::bigint AS events
        FROM syslog_entries se,
             LATERAL jsonb_array_elements_text(
               CASE WHEN jsonb_typeof(se.structured_data->'mitre') = 'array'
                    THEN se.structured_data->'mitre' ELSE '[]'::jsonb END
             ) AS t(technique)
        WHERE se.received_at > NOW() - make_interval(hours => $1)
        ${sfEvents.clause}
        GROUP BY t.technique
      ),
      alert_tech AS (
        -- Fold in techniques from alerts FIRED in the window. alert_rules.mitre_techniques
        -- carries the static technique set for BOTH threshold rules and correlation
        -- rules (correlationEngine.js persists MITRE_BY_RULE onto that column), so a
        -- technique that only ever surfaces at the correlation altitude still lights up
        -- the coverage matrix. Counts fired alerts.
        SELECT tech AS technique, COUNT(*)::bigint AS alerts
        FROM alert_events ae
        JOIN alert_rules ar ON ar.id = ae.rule_id,
             LATERAL unnest(ar.mitre_techniques) AS tech
        WHERE ae.fired_at > NOW() - make_interval(hours => $1)
          AND ar.mitre_techniques IS NOT NULL
        ${sfAlerts.clause}
        GROUP BY tech
      )
      SELECT COALESCE(e.technique, a.technique) AS technique,
             COALESCE(e.events, 0)::bigint AS events,
             COALESCE(a.alerts, 0)::bigint AS alerts,
             (COALESCE(e.events, 0) + COALESCE(a.alerts, 0))::bigint AS count
      FROM event_tech e
      FULL OUTER JOIN alert_tech a ON a.technique = e.technique
      ORDER BY count DESC
    `, [hours, ...sfEvents.params, ...sfAlerts.params]);
    return { hours, data: rows };
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
    // table_size must SUM the partition tree: syslog_entries is a PARTITIONED parent
    // (Phase 3), so pg_total_relation_size() on the parent alone returns 0 bytes — the
    // rows live in the daily child partitions (+ syslog_entries_legacy). pg_partition_tree
    // includes the parent and every partition; GREATEST falls back to the plain size if
    // the table is somehow not partitioned (returns no tree rows -> NULL -> 0).
    pool.query(`SELECT pg_size_pretty(pg_database_size('logvault')) AS db_size, pg_database_size('logvault') AS db_size_bytes, pg_size_pretty(GREATEST(pg_total_relation_size('syslog_entries'), COALESCE((SELECT SUM(pg_total_relation_size(relid)) FROM pg_partition_tree('syslog_entries')), 0))) AS table_size, GREATEST(pg_total_relation_size('syslog_entries'), COALESCE((SELECT SUM(pg_total_relation_size(relid)) FROM pg_partition_tree('syslog_entries')), 0)) AS table_size_bytes, (SELECT COUNT(*) FROM syslog_entries) AS total_rows, (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => 24)) AS rows_24h, (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - make_interval(days => 7)) AS rows_7d`),
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
  const { q, vendor, severity, host, ip, category, technique, threat } = req.query;
  const hours  = safeHours(req.query.hours, 720);
  const page   = Math.max(parseInt(req.query.page || '1'), 1);
  const limit  = safeInt(req.query.limit, 100, 500);
  const offset = (page - 1) * limit;

  const conditions = [`se.received_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (q)        { const qp = p++; conditions.push(`(to_tsvector('english', se.message) @@ plainto_tsquery('english', $${qp}) OR se.message ILIKE '%'||$${qp}||'%' OR se.structured_data->>'user' ILIKE '%'||$${qp}||'%' OR se.structured_data->>'srccountry' ILIKE '%'||$${qp}||'%' OR se.structured_data->>'service' ILIKE '%'||$${qp}||'%')`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                        params.push(vendor); }
  if (category) { conditions.push(`se.category = $${p++}`);                      params.push(category); }
  // MITRE ATT&CK technique filter — JSONB containment on structured_data.mitre,
  // served by the existing GIN index on structured_data. Validate the ID shape so
  // we never build a bad jsonb literal from arbitrary input.
  if (technique && /^T\d{4}(\.\d{3})?$/.test(String(technique))) {
    conditions.push(`se.structured_data @> jsonb_build_object('mitre', jsonb_build_array($${p++}::text))`);
    params.push(technique);
  }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => !isNaN(n) && n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`);     params.push(sevs); }
  }
  if (host)     {
    // Match the host/IP against the syslog sender AND the parsed source/dest IPs
    // (structured_data.srcip/dstip/remip), so drilling by a real client/attacker IP
    // — not just the reporting device — finds its events. One placeholder, reused.
    const hp = p++;
    conditions.push(`(se.source_host ILIKE $${hp} OR kh.hostname ILIKE $${hp} OR se.source_ip::TEXT ILIKE $${hp} OR se.structured_data->>'srcip' ILIKE $${hp} OR se.structured_data->>'dstip' ILIKE $${hp} OR se.structured_data->>'remip' ILIKE $${hp})`);
    params.push(`%${host}%`);
  }
  if (ip)       { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`);           params.push(`%${ip}%`); }
  // Threat drill-down — matches the EXACT by_threat COALESCE used by
  // GET /api/security/ips-events so a Threat Summary card drills into precisely
  // that threat's events. Same field order / NULLIF / CONCAT_WS, compared = $N.
  if (threat)   {
    conditions.push(`COALESCE(NULLIF(se.structured_data->>'certdesc',''), NULLIF(se.structured_data->>'catdesc',''), NULLIF(CONCAT_WS('/', NULLIF(se.structured_data->>'eventtype',''), NULLIF(se.structured_data->>'eventsubtype','')), ''), NULLIF(se.structured_data->>'attack',''), NULLIF(se.structured_data->>'msg',''), 'Unknown') = $${p++}`);
    params.push(threat);
  }

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
          match_pattern, threshold_count, threshold_window, notify_email, mitre_techniques } = req.body;

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
  // MITRE technique IDs — technique-level (Txxxx) or sub-technique (Txxxx.yyy).
  let techniques = null;
  if (mitre_techniques !== undefined && mitre_techniques !== null) {
    if (!Array.isArray(mitre_techniques) || mitre_techniques.some(t => typeof t !== 'string' || !/^T\d{4}(\.\d{3})?$/.test(t)))
      return res.status(400).json({ error: 'mitre_techniques must be an array of ATT&CK IDs (e.g. T1110)' });
    techniques = mitre_techniques;
  }

  const { rows } = await pool.query(`
    INSERT INTO alert_rules (name, description, match_severity, match_vendor, match_host,
      match_pattern, threshold_count, threshold_window, notify_email, mitre_techniques)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *
  `, [name, description, match_severity, match_vendor, match_host,
      match_pattern, threshold_count || 1, threshold_window || '5 minutes', notify_email, techniques]);
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
  // Optional `hours` window (backward compatible — omitted = no time filter).
  // The ATT&CK coverage matrix counts alerts FIRED within a window; when the user
  // drills into a technique we pass that same window here so the chip-filtered
  // view shows exactly the alerts the matrix counted, instead of relying on the
  // LIMIT 500 ordering (which could push an older technique's alerts off the page
  // in a long window and re-introduce the empty-drill-down). When `hours` is
  // present we also drop the LIMIT so a window-scoped query returns the full set.
  const hasHours = req.query.hours !== undefined && req.query.hours !== '';
  const hours = hasHours ? safeHours(req.query.hours) : null;
  const params = [];
  let p = 1;
  let timeClause = '';
  if (hasHours) {
    timeClause = `AND ae.fired_at > NOW() - make_interval(hours => $${p})`;
    params.push(hours);
    p += 1;
  }
  // RBAC: scope by the relay (ae.source_host → site), matching the mitre-coverage
  // alert branch so a technique the coverage matrix counted for this user is also
  // returned here. Keeps cross-site isolation intact.
  const sf = getAlertSiteFilter(req.rbac, p, 'ae');
  params.push(...sf.params);
  const { rows } = await pool.query(`
    SELECT ae.*, ar.name AS rule_name, ar.mitre_techniques
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE TRUE
    ${timeClause}
    ${sf.clause}
    ORDER BY ae.acknowledged ASC, ae.fired_at DESC
    ${hasHours ? '' : 'LIMIT 500'}
  `, params);
  res.json({ data: rows });
}));

app.patch('/api/alerts/events/:id/acknowledge', asyncHandler(async (req, res) => {
  const ackBy = (req.rbac && req.rbac.userId) ? String(req.rbac.userId) : null;
  await pool.query(
    'UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW(), acknowledged_by=$2 WHERE id=$1',
    [req.params.id, ackBy]
  );
  await writeAudit(pool, req, 'alert.acknowledge', { target: req.params.id });
  res.json({ ok: true });
}));

app.patch('/api/alerts/events/acknowledge-all', asyncHandler(async (req, res) => {
  const { ids } = req.body;
  const ackBy = (req.rbac && req.rbac.userId) ? String(req.rbac.userId) : null;
  let auditTarget;
  if (ids && Array.isArray(ids) && ids.length > 0) {
    await pool.query(
      'UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW(), acknowledged_by=$2 WHERE id = ANY($1::int[])',
      [ids, ackBy]
    );
    auditTarget = ids.join(',');
  } else {
    await pool.query(
      'UPDATE alert_events SET acknowledged=TRUE, acknowledged_at=NOW(), acknowledged_by=$1 WHERE acknowledged=FALSE',
      [ackBy]
    );
    auditTarget = 'all-open';
  }
  await writeAudit(pool, req, 'alert.acknowledge', { target: auditTarget });
  res.json({ ok: true });
}));

// Alert banner — most recent unacknowledged alerts
app.get('/api/alerts/events/recent-unacked', asyncHandler(async (req, res) => {
  const sf = getSiteFilter(req.rbac, 1, 'ae');
  const { rows } = await pool.query(`
    SELECT ae.id, ae.fired_at, ae.source_host, ae.source_ip, ae.sample_message AS message,
      ar.name AS rule_name, ar.mitre_techniques
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE ae.acknowledged = FALSE
    ${sf.clause}
    ORDER BY ae.fired_at DESC
    LIMIT 5
  `, sf.params);
  res.json({ data: rows });
}));

// Correlation-rule → look-back window (minutes) used to gather the underlying
// syslog entries behind a fired alert. Mirrors the windows in
// collector/correlationEngine.js. Anything not listed falls back to DEFAULT.
const ALERT_LOG_WINDOW_MINUTES = {
  'Brute Force Login Success':        10,
  'Port Scan Detected':                3,
  'Interface Flapping Detected':      10,
  'Network Loop Detected':             2,
  'After-Hours Configuration Change':  1,
  'STP Instability Detected':          5,
  'Repeated IPS Triggers':             5,
  'VPN Brute Force Attempt':           5,
};
const ALERT_LOG_WINDOW_DEFAULT = 30;

// Underlying syslog entries that triggered a given alert event — powers the
// "logs behind this alert" UI detail panel. RBAC: same getSiteFilter pattern as
// the other /api/alerts routes, applied to BOTH the alert lookup (ae) and the
// syslog query (se), so a user only ever sees alerts/logs for their sites.
app.get('/api/alerts/events/:id/logs', asyncHandler(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id < 1) return res.status(400).json({ error: 'Invalid alert id' });

  // 1) Look up the alert (RBAC site-filtered on ae.source_ip).
  const af = getSiteFilter(req.rbac, 2, 'ae');
  const alertResult = await pool.query(`
    SELECT ae.*, ar.name AS rule_name, ar.mitre_techniques
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE ae.id = $1
    ${af.clause}
  `, [id, ...af.params]);
  if (!alertResult.rows.length) return res.status(404).json({ error: 'Alert not found' });
  const alert = alertResult.rows[0];

  // 2) Determine the correlation look-back window (minutes) from the rule name.
  const windowMinutes = ALERT_LOG_WINDOW_MINUTES[alert.rule_name] || ALERT_LOG_WINDOW_DEFAULT;

  // 3) Fetch matching logs around fired_at from the SAME ACTOR. alert.source_ip
  //    holds the real actor (the attacker's structured_data.srcip for security
  //    rules, or the device IP for operational rules), so match on the parsed
  //    srcip first and the sender source_ip as a fallback. We deliberately do NOT
  //    match broadly on source_host — in a relay deployment every log shares the
  //    forwarding device's hostname, which would return every log in the window.
  const params = [windowMinutes, alert.fired_at];
  let p = 3;
  const srcMatch = [];
  if (alert.source_ip != null) {
    const ipIdx = p++; params.push(alert.source_ip);
    srcMatch.push(`se.structured_data->>'srcip' = host($${ipIdx}::inet)`);
    srcMatch.push(`se.source_ip = $${ipIdx}`);
  } else if (alert.source_host != null) {
    const hostIdx = p++; params.push(alert.source_host);
    srcMatch.push(`se.source_host = $${hostIdx}`);
  }
  if (!srcMatch.length) srcMatch.push('FALSE');

  const sf = getSiteFilter(req.rbac, p, 'se');

  const logsResult = await pool.query(`
    SELECT se.id, se.received_at, se.log_timestamp, se.severity_label, se.vendor,
           se.category, se.risk_score, se.source_ip::text, se.source_host,
           se.message, se.structured_data
    FROM syslog_entries se
    WHERE se.received_at BETWEEN ($2::timestamptz - make_interval(mins => $1))
                            AND ($2::timestamptz + interval '1 minute')
      AND (${srcMatch.join(' OR ')})
    ${sf.clause}
    ORDER BY se.received_at DESC
    LIMIT 200
  `, [...params, ...sf.params]);

  // 4) Respond.
  res.json({ alert, window_minutes: windowMinutes, logs: logsResult.rows });
}));

// CSV export
app.get('/api/logs/export', asyncHandler(async (req, res) => {
  const { q, vendor, severity, host, ip, category, threat } = req.query;
  const hours = safeHours(req.query.hours, 720);

  const conditions = [`se.received_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (q)        { const qp = p++; conditions.push(`(to_tsvector('english', se.message) @@ plainto_tsquery('english', $${qp}) OR se.message ILIKE '%'||$${qp}||'%' OR se.structured_data->>'user' ILIKE '%'||$${qp}||'%' OR se.structured_data->>'srccountry' ILIKE '%'||$${qp}||'%' OR se.structured_data->>'service' ILIKE '%'||$${qp}||'%')`); params.push(q); }
  if (vendor)   { conditions.push(`se.vendor = $${p++}`);                   params.push(vendor); }
  if (category) { conditions.push(`se.category = $${p++}`);                 params.push(category); }
  if (severity) {
    const sevs = String(severity).split(',').map(Number).filter(n => !isNaN(n) && n >= 0 && n <= 7);
    if (sevs.length) { conditions.push(`se.severity = ANY($${p++}::int[])`); params.push(sevs); }
  }
  if (host) {
    // Match the host/IP against the syslog sender AND the parsed source/dest IPs
    // (structured_data.srcip/dstip/remip), so drilling by a real client/attacker IP
    // — not just the reporting device — finds its events. One placeholder, reused.
    const hp = p++;
    conditions.push(`(se.source_host ILIKE $${hp} OR kh.hostname ILIKE $${hp} OR se.source_ip::TEXT ILIKE $${hp} OR se.structured_data->>'srcip' ILIKE $${hp} OR se.structured_data->>'dstip' ILIKE $${hp} OR se.structured_data->>'remip' ILIKE $${hp})`);
    params.push(`%${host}%`);
  }
  if (ip) { conditions.push(`se.source_ip::TEXT ILIKE $${p++}`); params.push(`%${ip}%`); }
  // Threat drill-down — mirrors /api/logs so a CSV export from a Threat Summary
  // drill matches the EXACT by_threat COALESCE (GET /api/security/ips-events).
  if (threat) {
    conditions.push(`COALESCE(NULLIF(se.structured_data->>'certdesc',''), NULLIF(se.structured_data->>'catdesc',''), NULLIF(CONCAT_WS('/', NULLIF(se.structured_data->>'eventtype',''), NULLIF(se.structured_data->>'eventsubtype','')), ''), NULLIF(se.structured_data->>'attack',''), NULLIF(se.structured_data->>'msg',''), 'Unknown') = $${p++}`);
    params.push(threat);
  }

  // RBAC site filter — restrict export to the user's allowed sites
  const sf = getSiteFilter(req.rbac, p, 'se');
  if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }

  const { rows } = await pool.query(`
    SELECT se.received_at, COALESCE(kh.hostname, se.source_host) AS source_host,
      se.source_ip::TEXT, se.severity_label, se.vendor, se.program,
      se.category, se.risk_score, se.message,
      -- Slide-in detail fields (from structured_data) for downstream analysis.
      COALESCE(se.structured_data->>'srcip', se.structured_data->>'remip') AS remote_ip,
      se.structured_data->>'user'       AS usr,
      se.structured_data->>'srccountry' AS country,
      se.structured_data->>'subcategory' AS subcategory,
      se.structured_data->>'action'     AS action,
      se.structured_data->>'subtype'    AS subtype,
      se.structured_data->>'dstip'      AS dstip,
      se.structured_data->>'reason'     AS reason
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE ${conditions.join(' AND ')}
    ORDER BY se.received_at DESC
    LIMIT 10000
  `, params);

  // Build CSV. esc() RFC-4180-quotes any field containing comma/quote/newline;
  // clean() blanks out the firewall's "N/A" placeholders so columns stay analysis-friendly.
  const esc = (v) => {
    if (v == null) return '';
    const s = String(v);
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const clean = (v) => (v == null || v === 'N/A' || v === '') ? '' : v;
  const header = 'Time,Reporting Device,Reporting Device IP,Remote Source IP,Country,User,Category,Subcategory,Action,Subtype,Dest IP,Severity,Risk Score,Vendor,Program,Reason,Message\n';
  const csvRows = rows.map(r => [
    esc(r.received_at), esc(r.source_host), esc(r.source_ip),
    esc(clean(r.remote_ip)), esc(clean(r.country)), esc(clean(r.usr)),
    esc(r.category), esc(clean(r.subcategory)), esc(clean(r.action)), esc(clean(r.subtype)), esc(clean(r.dstip)),
    esc(r.severity_label), r.risk_score != null ? r.risk_score : '',
    esc(r.vendor), esc(r.program), esc(clean(r.reason)), esc(r.message),
  ].join(','));

  const csv = header + csvRows.join('\n');
  const filename = `logvault-export-${new Date().toISOString().slice(0, 10)}.csv`;

  // Data-exfiltration audit — record the filters used and how many rows left.
  await writeAudit(pool, req, 'logs.export', {
    detail: {
      filters: { q, vendor, severity, host, ip, category, threat, hours },
      row_count: rows.length,
    },
  });

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
      site_name, site_id, brand, model, device_status, lifecycle_status,
      synced_from_nv, last_synced, last_seen,
      country_code, country_name, city, asn, asn_org, is_external,
      abuse_score, is_known_bad, threat_tags, last_enriched
    FROM known_hosts
    ${where}
    ORDER BY is_known_bad DESC NULLS LAST, abuse_score DESC NULLS LAST,
      synced_from_nv DESC, last_seen DESC
  `, params);
  res.json({ data: rows });
}));

app.put('/api/hosts', requireAdmin, asyncHandler(async (req, res) => {
  const { ip_address, hostname, vendor, description } = req.body;
  if (!ip_address) return res.status(400).json({ error: 'ip_address required' });

  // Optional manual site assignment. site_id must be a real netvault.sites.id
  // (integer) — that's what RBAC site filtering keys on. We also denormalize
  // site_name for the table display, matching the sync's "name · city" form.
  let siteId = req.body.site_id;
  let siteName = null;
  if (siteId === '' || siteId === undefined || siteId === null) {
    siteId = null;
  } else {
    siteId = parseInt(siteId, 10);
    if (isNaN(siteId)) return res.status(400).json({ error: 'invalid site_id' });
    try {
      const sites = await getNetvaultSites();
      const match = sites.find(s => s.id === siteId);
      if (!match) return res.status(400).json({ error: 'unknown site_id' });
      siteName = match.label;
    } catch (_) {
      // NetVault DB unreachable — still persist the integer site_id (RBAC needs
      // it); site_name display will fill in on the next NetVault sync/lookup.
    }
  }

  const { rows } = await pool.query(`
    INSERT INTO known_hosts (ip_address, hostname, vendor, description, site_id, site_name, last_seen)
    VALUES ($1,$2,$3,$4,$5,$6,NOW())
    ON CONFLICT (ip_address) DO UPDATE
      SET hostname=EXCLUDED.hostname, vendor=EXCLUDED.vendor,
          description=EXCLUDED.description, site_id=EXCLUDED.site_id,
          site_name=EXCLUDED.site_name, last_seen=NOW()
    RETURNING *
  `, [ip_address, hostname, vendor, description, siteId, siteName]);
  res.json({ data: rows[0] });
}));

// Manual trigger for NetVault sync + sites list for the Known Hosts dropdown
const { syncFromNetVault, getNetvaultSites } = require('./netvaultSync');

// Sites come from NetVault (the CMDB). Used to populate the manual site-assignment
// dropdown for hosts that aren't NetVault-managed (external IPs, syslog relays).
app.get('/api/sites', requireAdmin, asyncHandler(async (req, res) => {
  try {
    const data = await getNetvaultSites();
    res.json({ data });
  } catch (err) {
    console.error('[Sites] Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
}));

app.post('/api/hosts/sync-netvault', requireSuperAdmin, asyncHandler(async (req, res) => {
  try {
    const result = await syncFromNetVault(pool);
    await writeAudit(pool, req, 'hosts.sync_netvault', { detail: { synced: result?.synced || 0 } });
    res.json({ ok: true, synced: result?.synced || 0 });
  } catch (err) {
    console.error('[SyncNV] Error:', err.message);
    await writeAudit(pool, req, 'hosts.sync_netvault', { result: 'error', detail: { message: err.message } });
    res.status(500).json({ error: 'Internal server error' });
  }
}));

// ── THREAT INTELLIGENCE ──────────────────────────────────────
// Known-bad hosts = known_hosts flagged is_known_bad = TRUE OR abuse_score >= 50.
// RBAC: known_hosts carries site_id directly (NetVault site link), so we filter
// on it the same way /api/hosts does — getSiteFilter builds a source_ip subquery
// for syslog_entries, which does not apply to this known_hosts-keyed table. The
// per-source-IP getSiteFilter clause IS still used for the total_hits subquery
// (which reads syslog_entries.source_ip) so a user only counts hits from their
// own sites, matching the other per-source endpoints.
app.get('/api/threats/known-bad', asyncHandler(async (req, res) => {
  const limit = safeInt(req.query.limit, 100, 500);
  const rbac = req.rbac;

  // Site filter on known_hosts.site_id (admins: none; no-sites user: 1=0).
  let khWhere = '';
  const params = [];
  let p = 1;
  if (rbac && rbac.allowedSiteIds !== null && rbac.allowedSiteIds !== undefined) {
    if (rbac.allowedSiteIds.length === 0) {
      khWhere = 'AND 1=0';
    } else {
      khWhere = `AND kh.site_id = ANY($${p}::int[])`;
      params.push(rbac.allowedSiteIds);
      p += 1;
    }
  }

  // Site filter for the correlated 24h hit count (per-source on syslog_entries).
  const sf = getSiteFilter(rbac, p, 'se');
  params.push(...sf.params);
  p = sf.nextParamIndex;

  const limitIdx = p;
  params.push(limit);

  const { rows } = await pool.query(`
    SELECT
      kh.ip_address::TEXT AS ip_address,
      kh.hostname,
      kh.country_name,
      kh.country_code,
      kh.asn_org,
      kh.abuse_score,
      kh.threat_tags,
      kh.last_enriched,
      kh.last_seen,
      COALESCE((
        SELECT COUNT(*)
        FROM syslog_entries se
        WHERE (
              se.structured_data->>'srcip' = host(kh.ip_address)
           OR se.structured_data->>'dstip' = host(kh.ip_address)
           OR se.source_ip = kh.ip_address
        )
          AND se.received_at > NOW() - INTERVAL '24 hours'
          ${sf.clause}
      ), 0) AS total_hits
    FROM known_hosts kh
    WHERE (kh.is_known_bad = TRUE OR kh.abuse_score >= 50)
    ${khWhere}
    ORDER BY kh.abuse_score DESC NULLS LAST
    LIMIT $${limitIdx}
  `, params);

  // Whether an AbuseIPDB key is configured — lets the widget show a "paste a key"
  // empty state vs. a clean "no threats" state. Boolean only; the key is never sent.
  let keyConfigured = false;
  try {
    const k = await pool.query(
      `SELECT value FROM app_settings WHERE key = 'abuseipdb_api_key'`
    );
    keyConfigured = !!(k.rows[0] && String(k.rows[0].value || '').trim());
  } catch (_) { /* best-effort; default false */ }

  res.json({ data: rows, keyConfigured });
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
  // The window is driven by the ?hours param (defaults to 24h for backward
  // compatibility) so it tracks the Network Health time-range picker like the
  // sibling /api/health/* endpoints. The logs_1h / logs_24h / critical_24h /
  // error_24h columns stay on their fixed (1h / 24h) windows because the UI
  // labels them as such.
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'se');
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
      WHERE se.received_at > NOW() - make_interval(hours => $1)
      ${sf.clause}
      GROUP BY se.source_host, se.source_ip, kh.hostname, kh.vendor, kh.description, se.vendor
      ORDER BY last_seen DESC
    `, [hours, ...sf.params]);
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
  const sfA = getSiteFilter(req.rbac, 2, 'a');               // alias 'a' subquery (brute-force success)
  const sfSe = getSiteFilter(req.rbac, 2, 'se');             // alias 'se' subquery (known-bad join)
  const [authFail, denies, vpn, ips, afterHours, bruteSuccess, vpnLoginFail, knownBadFail] = await Promise.all([
    // Real auth failure = normalized subcategory (vendor-agnostic), with a tight
    // message-regex fallback. The old broad %fail%/%error% match counted SSL teardown
    // noise (ssl-exit-error/ssl-alert/negotiate) as login failures — dropped.
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (structured_data->>'subcategory' IN ('login_failed','auth_failed') OR message ILIKE '%login failed%' OR message ILIKE '%authentication fail%') ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action' = 'deny' ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND (structured_data->>'subtype' = 'vpn' OR message ILIKE '%vpn%') ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type' = 'utm' ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') OR message ILIKE '%login failed%' OR message ILIKE '%configured from%') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19 ${sf.clause}`, [hours, ...sf.params]),
    // Brute-force success: vendor-agnostic. A real attacker source (real srcip, not the
    // firewall) that had a login_failed AND a later login_success within the window.
    pool.query(`SELECT COUNT(DISTINCT COALESCE(a.structured_data->>'srcip', a.source_ip::text)) AS count
      FROM syslog_entries a
      INNER JOIN syslog_entries b
        ON COALESCE(b.structured_data->>'srcip', b.source_ip::text) = COALESCE(a.structured_data->>'srcip', a.source_ip::text)
        AND b.structured_data->>'subcategory' = 'login_failed'
        AND b.received_at > NOW() - make_interval(hours => $1)
        AND b.received_at < a.received_at
      WHERE a.received_at > NOW() - make_interval(hours => $1)
        AND a.structured_data->>'subcategory' = 'login_success'
      ${sfA.clause}`, [hours, ...sfA.params]),
    // VPN login failures: vpn category/subtype AND a normalized auth failure.
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND (category='vpn' OR structured_data->>'subtype'='vpn') AND structured_data->>'subcategory' IN ('login_failed','auth_failed') ${sf.clause}`, [hours, ...sf.params]),
    // Known-bad failures: login-failure events whose real source matches a known_hosts
    // row flagged is_known_bad OR abuse_score >= 50. Join uses host(ip_address) because
    // known_hosts.ip_address is INET stored with a /32 mask; shape-guard the join key.
    pool.query(`SELECT COUNT(*) AS count
      FROM syslog_entries se
      LEFT JOIN known_hosts kh
        ON COALESCE(se.structured_data->>'srcip', se.source_ip::text) ~ '^[0-9.]+$'
       AND host(kh.ip_address) = COALESCE(se.structured_data->>'srcip', se.source_ip::text)
      WHERE se.received_at > NOW() - make_interval(hours => $1)
        AND (se.structured_data->>'subcategory' IN ('login_failed','auth_failed') OR se.message ILIKE '%login failed%' OR se.message ILIKE '%authentication fail%')
        AND (kh.is_known_bad = TRUE OR kh.abuse_score >= 50)
      ${sfSe.clause}`, [hours, ...sfSe.params]),
  ]);
  res.json({
    hours,
    auth_failures:       parseInt(authFail.rows[0].count),
    firewall_denies:     parseInt(denies.rows[0].count),
    vpn_events:          parseInt(vpn.rows[0].count),
    ips_events:          parseInt(ips.rows[0].count),
    after_hours_events:  parseInt(afterHours.rows[0].count),
    brute_force_success: parseInt(bruteSuccess.rows[0].count),
    vpn_login_failures:  parseInt(vpnLoginFail.rows[0].count),
    known_bad_failures:  parseInt(knownBadFail.rows[0].count),
  });
}));

app.get('/api/security/auth-failures', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'se');
  // Group by the REAL attacker source (normalized srcip, falling back to the syslog
  // sender), vendor-agnostically. Detection uses the normalized subcategory with a tight
  // message-regex fallback — the old per-vendor broad %failed%+%login% / %fail% matching
  // wrongly counted SSL teardown noise. known_hosts join uses host(ip_address) (INET /32)
  // with a shape-guarded text key, mirroring the top-blocked/top-failures joins.
  const { rows } = await pool.query(`
    SELECT
      COALESCE(se.structured_data->>'srcip', se.source_ip::text) AS source_ip,
      COALESCE(kh.hostname, se.structured_data->>'srcip', se.source_host) AS source_host,
      COUNT(*) AS failure_count,
      COUNT(DISTINCT se.structured_data->>'user') AS distinct_users,
      (ARRAY_AGG(DISTINCT se.structured_data->>'user')
        FILTER (WHERE se.structured_data->>'user' IS NOT NULL
          AND se.structured_data->>'user' NOT IN ('','N/A')))[1:5] AS sample_users,
      MIN(se.received_at) AS first_attempt, MAX(se.received_at) AS last_attempt, se.vendor,
      COALESCE(se.structured_data->>'srccountry', kh.country_name) AS country,
      kh.country_code,
      BOOL_OR(kh.is_known_bad) AS is_known_bad,
      MAX(kh.abuse_score) AS abuse_score
    FROM syslog_entries se
    LEFT JOIN known_hosts kh
      ON COALESCE(se.structured_data->>'srcip', se.source_ip::text) ~ '^[0-9.]+$'
     AND host(kh.ip_address) = COALESCE(se.structured_data->>'srcip', se.source_ip::text)
    WHERE se.received_at > NOW() - make_interval(hours => $1)
      AND (se.structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force')
        OR se.message ILIKE '%login failed%' OR se.message ILIKE '%authentication fail%')
    ${sf.clause}
    GROUP BY COALESCE(se.structured_data->>'srcip', se.source_ip::text),
      COALESCE(kh.hostname, se.structured_data->>'srcip', se.source_host), se.vendor,
      COALESCE(se.structured_data->>'srccountry', kh.country_name), kh.country_code
    ORDER BY failure_count DESC LIMIT 50
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

app.get('/api/security/brute-force', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 3, 'syslog_entries');
  // Both CTEs group by the REAL attacker source (normalized srcip → syslog sender),
  // vendor-agnostically, via the normalized subcategory (with a tight message fallback).
  // known_hosts join uses host(ip_address) on the shape-guarded real-source key.
  const { rows } = await pool.query(`
    WITH failures AS (
      SELECT COALESCE(structured_data->>'srcip', source_ip::text) AS source_ip,
        MIN(received_at) AS first_fail, MAX(received_at) AS last_fail, COUNT(*) AS fail_count,
        COUNT(DISTINCT structured_data->>'user') AS distinct_users
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1)
        AND (structured_data->>'subcategory' IN ('login_failed','auth_failed')
          OR message ILIKE '%login failed%' OR message ILIKE '%authentication fail%')
      ${sf.clause}
      GROUP BY COALESCE(structured_data->>'srcip', source_ip::text)
    ),
    successes AS (
      SELECT COALESCE(structured_data->>'srcip', source_ip::text) AS source_ip,
        MIN(received_at) AS success_time, message AS success_msg
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $2)
        AND (structured_data->>'subcategory' = 'login_success'
          OR message ILIKE '%login success%' OR message ILIKE '%authenticated%')
      ${sf.clause}
      GROUP BY COALESCE(structured_data->>'srcip', source_ip::text), message
    )
    SELECT f.source_ip,
      COALESCE(kh.hostname, f.source_ip) AS host,
      f.fail_count, f.distinct_users, f.first_fail, f.last_fail, s.success_time, s.success_msg,
      CASE WHEN s.success_time IS NOT NULL THEN TRUE ELSE FALSE END AS success_after_failure
    FROM failures f
    LEFT JOIN successes s ON s.source_ip = f.source_ip AND s.success_time > f.first_fail
    LEFT JOIN known_hosts kh
      ON f.source_ip ~ '^[0-9.]+$' AND host(kh.ip_address) = f.source_ip
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
  // event_type is driven by the normalized subcategory — NOT the broad %fail%/%error%
  // match, which mislabelled SSL teardown noise (ssl-exit-error/ssl-alert) as failures.
  // vpn_src_ip is the REAL remote client (structured_data.srcip), not the firewall.
  const { rows } = await pool.query(`
    SELECT received_at, source_host, source_ip::TEXT, severity_label, message,
      structured_data->>'srcip' AS vpn_src_ip,
      structured_data->>'user' AS username,
      structured_data->>'srccountry' AS country,
      structured_data->>'msg' AS detail,
      CASE WHEN structured_data->>'subcategory' IN ('login_failed','auth_failed') THEN 'failure'
           WHEN structured_data->>'subcategory' = 'login_success' THEN 'success'
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
    pool.query(`SELECT received_at, source_host, source_ip::TEXT, severity_label, message, structured_data->>'srcip' AS src_ip, structured_data->>'dstip' AS dst_ip, COALESCE(NULLIF(structured_data->>'certdesc',''), NULLIF(structured_data->>'catdesc',''), NULLIF(CONCAT_WS('/', NULLIF(structured_data->>'eventtype',''), NULLIF(structured_data->>'eventsubtype','')), ''), NULLIF(structured_data->>'attack',''), NULLIF(structured_data->>'msg',''), 'Unknown') AS threat_name, structured_data->>'hostname' AS hostname, structured_data->>'url' AS url, structured_data->>'catdesc' AS web_category, structured_data->>'crlevel' AS crlevel, structured_data->>'eventtype' AS eventtype, structured_data->>'action' AS action, structured_data->>'subtype' AS subtype FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type'='utm' ${sf.clause} ORDER BY received_at DESC LIMIT 100`, [hours, ...sf.params]),
    pool.query(`SELECT COALESCE(NULLIF(structured_data->>'certdesc',''), NULLIF(structured_data->>'catdesc',''), NULLIF(CONCAT_WS('/', NULLIF(structured_data->>'eventtype',''), NULLIF(structured_data->>'eventsubtype','')), ''), NULLIF(structured_data->>'attack',''), NULLIF(structured_data->>'msg',''), 'Unknown') AS threat, structured_data->>'subtype' AS subtype, COUNT(*) AS hit_count, COUNT(DISTINCT structured_data->>'srcip') AS unique_sources FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'type'='utm' ${sf.clause} GROUP BY COALESCE(NULLIF(structured_data->>'certdesc',''), NULLIF(structured_data->>'catdesc',''), NULLIF(CONCAT_WS('/', NULLIF(structured_data->>'eventtype',''), NULLIF(structured_data->>'eventsubtype','')), ''), NULLIF(structured_data->>'attack',''), NULLIF(structured_data->>'msg',''), 'Unknown'), structured_data->>'subtype' ORDER BY hit_count DESC LIMIT 20`, [hours, ...sf.params]),
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

app.get('/api/security/top-targeted-users', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'se');
  // Usernames most hit by real auth failures, vendor-agnostically. distinct_sources counts
  // the REAL attacker source (normalized srcip → syslog sender), not the firewall.
  const { rows } = await pool.query(`
    SELECT se.structured_data->>'user' AS username,
      COUNT(*) AS failure_count,
      COUNT(DISTINCT COALESCE(se.structured_data->>'srcip', se.source_ip::text)) AS distinct_sources,
      MAX(se.received_at) AS last_attempt
    FROM syslog_entries se
    WHERE se.received_at > NOW() - make_interval(hours => $1)
      AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
      AND se.structured_data->>'user' IS NOT NULL
      AND se.structured_data->>'user' NOT IN ('','N/A')
    ${sf.clause}
    GROUP BY se.structured_data->>'user'
    ORDER BY failure_count DESC LIMIT 20
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

app.get('/api/security/failed-logins-by-country', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'se');
  // Auth failures grouped by country — preferring the event's own srccountry (Fortinet),
  // falling back to the known_hosts geo of the REAL source. known_hosts join uses
  // host(ip_address) on the shape-guarded real-source key. distinct_sources = real sources.
  const { rows } = await pool.query(`
    SELECT COALESCE(se.structured_data->>'srccountry', kh.country_name) AS country,
      kh.country_code,
      COUNT(*) AS failure_count,
      COUNT(DISTINCT COALESCE(se.structured_data->>'srcip', se.source_ip::text)) AS distinct_sources
    FROM syslog_entries se
    LEFT JOIN known_hosts kh
      ON COALESCE(se.structured_data->>'srcip', se.source_ip::text) ~ '^[0-9.]+$'
     AND host(kh.ip_address) = COALESCE(se.structured_data->>'srcip', se.source_ip::text)
    WHERE se.received_at > NOW() - make_interval(hours => $1)
      AND (se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
        OR se.message ILIKE '%login failed%' OR se.message ILIKE '%authentication fail%')
      AND COALESCE(se.structured_data->>'srccountry', kh.country_name) IS NOT NULL
      AND COALESCE(se.structured_data->>'srccountry', kh.country_name) <> ''
    ${sf.clause}
    GROUP BY COALESCE(se.structured_data->>'srccountry', kh.country_name), kh.country_code
    ORDER BY failure_count DESC LIMIT 20
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

// ── ANOMALY DETECTION & UEBA (Phase 2 — anomaly_events / entity_risk) ──
// These read the Phase 2 tables created in scripts/schema.sql. RBAC site filter
// is applied on the entity's source_ip, BUT rows with a NULL source_ip (user /
// global entities, which have no IP) are ALSO kept so they aren't hidden from
// site-scoped users. anomalySiteFilter() wraps getSiteFilter to add that
// null-allowance: it strips the leading "AND " from the strict clause, ORs in
// "<alias>.source_ip IS NULL", and re-prefixes "AND ". For super_admin the
// strict clause is empty → no restriction at all (and no null OR-term needed).
function anomalySiteFilter(rbac, startParamIndex, tableAlias) {
  const sf = getSiteFilter(rbac, startParamIndex, tableAlias);
  if (!sf.clause) return sf; // admin / super_admin — no restriction
  const inner = sf.clause.replace(/^AND\s+/i, '');
  return {
    clause: `AND (${inner} OR ${tableAlias}.source_ip IS NULL)`,
    params: sf.params,
    nextParamIndex: sf.nextParamIndex,
  };
}

// 1) Anomaly events list — filters: hours (window), anomaly_type, severity,
//    acknowledged ('true'/'false'). RBAC-with-null-allowance on ae.source_ip.
app.get('/api/anomalies', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours || '168', 720);
  const { type, severity } = req.query;
  const conditions = [`ae.detected_at > NOW() - make_interval(hours => $1)`];
  const params = [hours];
  let p = 2;

  if (type)     { conditions.push(`ae.anomaly_type = $${p++}`); params.push(type); }
  if (severity) { conditions.push(`ae.severity = $${p++}`);     params.push(severity); }
  if (req.query.acknowledged === 'true' || req.query.acknowledged === 'false') {
    conditions.push(`ae.acknowledged = $${p++}`);
    params.push(req.query.acknowledged === 'true');
  }

  const sf = anomalySiteFilter(req.rbac, p, 'ae');
  if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }

  const { rows } = await pool.query(`
    SELECT ae.id, ae.detected_at, ae.entity_type, ae.entity_value,
      ae.source_ip::TEXT, ae.anomaly_type, ae.severity, ae.score, ae.title,
      ae.detail, ae.acknowledged, ae.acknowledged_at, ae.acknowledged_by
    FROM anomaly_events ae
    WHERE ${conditions.join(' AND ')}
    ORDER BY ae.detected_at DESC
    LIMIT 200
  `, params);
  res.json({ data: rows });
}));

// 2) Anomaly summary — 24h totals, unacknowledged count, by-type and
//    by-severity breakdowns. Same RBAC-with-null-allowance on ae.source_ip.
app.get('/api/anomalies/summary', asyncHandler(async (req, res) => {
  // One shared site filter at $1 (no other params), reused across the queries.
  const sf = anomalySiteFilter(req.rbac, 1, 'ae');
  const window = `ae.detected_at > NOW() - make_interval(hours => 24)`;
  const [totals, byType, bySeverity] = await Promise.all([
    pool.query(`
      SELECT COUNT(*) AS total_24h,
             COUNT(*) FILTER (WHERE ae.acknowledged = FALSE) AS unacknowledged
      FROM anomaly_events ae
      WHERE ${window}
      ${sf.clause}
    `, sf.params),
    pool.query(`
      SELECT ae.anomaly_type, COUNT(*) AS count
      FROM anomaly_events ae
      WHERE ${window}
      ${sf.clause}
      GROUP BY ae.anomaly_type
      ORDER BY count DESC
    `, sf.params),
    pool.query(`
      SELECT ae.severity, COUNT(*) AS count
      FROM anomaly_events ae
      WHERE ${window}
      ${sf.clause}
      GROUP BY ae.severity
      ORDER BY count DESC
    `, sf.params),
  ]);
  res.json({
    total_24h:      parseInt(totals.rows[0].total_24h),
    unacknowledged: parseInt(totals.rows[0].unacknowledged),
    by_type:        byType.rows,
    by_severity:    bySeverity.rows,
  });
}));

// 3) Acknowledge a single anomaly. Mirrors /api/alerts/events/:id/acknowledge.
app.patch('/api/anomalies/:id/acknowledge', asyncHandler(async (req, res) => {
  const ackBy = (req.rbac && req.rbac.userId) ? String(req.rbac.userId) : null;
  await pool.query(
    'UPDATE anomaly_events SET acknowledged=TRUE, acknowledged_at=NOW(), acknowledged_by=$2 WHERE id=$1',
    [req.params.id, ackBy]
  );
  await writeAudit(pool, req, 'anomaly.acknowledge', { target: req.params.id });
  res.json({ ok: true });
}));

// 4) Bulk-acknowledge anomalies. Mirrors /api/alerts/events/acknowledge-all.
app.patch('/api/anomalies/acknowledge-all', asyncHandler(async (req, res) => {
  const { ids } = req.body;
  const ackBy = (req.rbac && req.rbac.userId) ? String(req.rbac.userId) : null;
  let auditTarget;
  if (ids && Array.isArray(ids) && ids.length > 0) {
    await pool.query(
      'UPDATE anomaly_events SET acknowledged=TRUE, acknowledged_at=NOW(), acknowledged_by=$2 WHERE id = ANY($1::int[])',
      [ids, ackBy]
    );
    auditTarget = ids.join(',');
  } else {
    await pool.query(
      'UPDATE anomaly_events SET acknowledged=TRUE, acknowledged_at=NOW(), acknowledged_by=$1 WHERE acknowledged=FALSE',
      [ackBy]
    );
    auditTarget = 'all-open';
  }
  await writeAudit(pool, req, 'anomaly.acknowledge', { target: auditTarget });
  res.json({ ok: true });
}));

// 5) UEBA top entities by risk score. Optional entity_type filter. RBAC-with-
//    null-allowance on er.source_ip (user entities have NULL source_ip).
app.get('/api/ueba/top', asyncHandler(async (req, res) => {
  const limit = safeInt(req.query.limit, 20, 100);
  const { type } = req.query;
  const conditions = [`TRUE`];
  const params = [];
  let p = 1;

  if (type) { conditions.push(`er.entity_type = $${p++}`); params.push(type); }

  const sf = anomalySiteFilter(req.rbac, p, 'er');
  if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }

  params.push(limit);
  const { rows } = await pool.query(`
    SELECT er.entity_type, er.entity_value, er.source_ip::TEXT, er.risk_score,
      er.factors, er.event_count, er.anomaly_count, er.last_activity, er.updated_at
    FROM entity_risk er
    WHERE ${conditions.join(' AND ')}
    ORDER BY er.risk_score DESC
    LIMIT $${p++}
  `, params);
  res.json({ data: rows });
}));

// 6) UEBA entity drill-down — risk row, recent anomalies, and a 7-day
//    syslog_entries activity summary for the entity. :type ∈ {device,user,srcip}.
//    The syslog aggregation is RBAC site-filtered (strict getSiteFilter on se).
app.get('/api/ueba/entity/:type/:value', asyncHandler(async (req, res) => {
  const { type, value } = req.params;
  if (!['device', 'user', 'srcip'].includes(type)) {
    return res.status(400).json({ error: 'Invalid entity type' });
  }

  // risk + recent anomalies keyed by (entity_type, entity_value).
  const [risk, anomalies] = await Promise.all([
    pool.query(`
      SELECT entity_type, entity_value, source_ip::TEXT, risk_score, factors,
        event_count, anomaly_count, last_activity, updated_at
      FROM entity_risk
      WHERE entity_type = $1 AND entity_value = $2
    `, [type, value]),
    pool.query(`
      SELECT id, detected_at, entity_type, entity_value, source_ip::TEXT,
        anomaly_type, severity, score, title, detail,
        acknowledged, acknowledged_at, acknowledged_by
      FROM anomaly_events
      WHERE entity_type = $1 AND entity_value = $2
      ORDER BY detected_at DESC
      LIMIT 20
    `, [type, value]),
  ]);

  // 7-day syslog activity summary for this entity. The per-type entity match is
  // a single reused placeholder ($2 = value); $1 is the entity value used by the
  // device/srcip IP comparison too — keep value as a single param reused across
  // the OR terms. RBAC site filter (strict) on se appended after.
  let entityMatch;
  const params = [value];
  let p = 2;
  if (type === 'device') {
    entityMatch = `(se.source_host = $1 OR se.source_ip::text = $1)`;
  } else if (type === 'srcip') {
    entityMatch = `(se.structured_data->>'srcip' = $1 OR se.source_ip::text = $1)`;
  } else { // user
    entityMatch = `se.structured_data->>'user' = $1`;
  }

  const sf = getSiteFilter(req.rbac, p, 'se');

  const summaryRes = await pool.query(`
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE se.structured_data->>'subcategory' IN ('login_failed','auth_failed')) AS failed_logins,
      MAX(se.received_at) AS last_seen
    FROM syslog_entries se
    WHERE se.received_at > NOW() - make_interval(days => 7)
      AND ${entityMatch}
    ${sf.clause}
  `, [...params, ...sf.params]);

  const byCategoryRes = await pool.query(`
    SELECT COALESCE(se.category, 'uncategorized') AS category, COUNT(*) AS count
    FROM syslog_entries se
    WHERE se.received_at > NOW() - make_interval(days => 7)
      AND ${entityMatch}
    ${sf.clause}
    GROUP BY se.category
    ORDER BY count DESC
  `, [...params, ...sf.params]);

  const s = summaryRes.rows[0];
  res.json({
    entity: { type, value },
    risk: risk.rows[0] || null,
    recent_anomalies: anomalies.rows,
    events_summary: {
      total:         parseInt(s.total),
      by_category:   byCategoryRes.rows,
      failed_logins: parseInt(s.failed_logins),
      last_seen:     s.last_seen,
    },
  });
}));

// 7) UEBA baseline warm-up status — how "ready" anomaly detection is. Reads
//    entity_baselines (how many entities/slots are learned + last rebuild) plus
//    the earliest syslog_entries timestamp to express coverage as "X of N days".
//    Baselines are collector-wide (not per-site), so this is an unfiltered
//    readiness indicator for any authenticated user. Read-only; never 500s.
const BASELINE_TARGET_DAYS = 7;
app.get('/api/ueba/baseline-status', asyncHandler(async (req, res) => {
  const data = await getCached(`baseline-status`, 60000, async () => {
    // Baseline coverage: distinct entities + total hour×dow slots, by type, and
    // the most recent rebuild time. One pass over the small entity_baselines table.
    const cov = await pool.query(`
      SELECT
        COUNT(DISTINCT entity_value)                                              AS entities,
        COUNT(*)                                                                  AS slots,
        COUNT(DISTINCT entity_value) FILTER (WHERE entity_type = 'device')        AS device_entities,
        COUNT(DISTINCT entity_value) FILTER (WHERE entity_type = 'user')          AS user_entities,
        MAX(updated_at)                                                           AS last_update
      FROM entity_baselines
    `);

    // Earliest log we have — drives days-of-data accumulated. Cheap MIN over the
    // partition key (planner uses the per-partition received_at index).
    const span = await pool.query(`SELECT MIN(received_at) AS earliest FROM syslog_entries`);

    const c = cov.rows[0] || {};
    const earliest = span.rows[0] && span.rows[0].earliest ? new Date(span.rows[0].earliest) : null;
    let daysAccumulated = 0;
    if (earliest && !isNaN(earliest.getTime())) {
      daysAccumulated = Math.max(0, (Date.now() - earliest.getTime()) / 86400000);
    }
    // Round down to whole days for display, capped at the target.
    const daysWhole = Math.min(BASELINE_TARGET_DAYS, Math.floor(daysAccumulated));
    const entities = parseInt(c.entities || 0, 10);

    return {
      target_days:      BASELINE_TARGET_DAYS,
      days_accumulated: daysWhole,
      // raw (uncapped) days, 1dp, so the UI can show partial-day progress finely
      days_raw:         Math.round(daysAccumulated * 10) / 10,
      entities,
      device_entities:  parseInt(c.device_entities || 0, 10),
      user_entities:    parseInt(c.user_entities || 0, 10),
      slots:            parseInt(c.slots || 0, 10),
      last_update:      c.last_update || null,
      earliest_log:     earliest ? earliest.toISOString() : null,
      // "ready" once we have at least the target days of data AND some baselines built.
      ready:            daysAccumulated >= BASELINE_TARGET_DAYS && entities > 0,
    };
  });
  res.json(data);
}));

// ── ADVANCED ANALYTICS (computed on the fly — no new tables) ──
// All four endpoints below are READ-ONLY and RBAC site-filtered on syslog_entries
// via getSiteFilter, matching every other /api/stats and /api/security route.

// 1) Activity heatmap — log volume by day-of-week × hour-of-day.
//    metric=all (default) counts every entry; metric=auth_failed restricts to
//    auth-failure events. Default window 168h (7 days).
app.get('/api/stats/heatmap', asyncHandler(async (req, res) => {
  const hours  = safeHours(req.query.hours || '168', 720);
  const metric = req.query.metric === 'auth_failed' ? 'auth_failed' : 'all';
  const sf = getSiteFilter(req.rbac, 2, 'se');
  const metricClause = metric === 'auth_failed'
    ? `AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')`
    : '';
  const cacheKey = `heatmap:${metric}:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    const { rows } = await pool.query(`
      SELECT
        EXTRACT(DOW  FROM se.received_at)::int AS dow,
        EXTRACT(HOUR FROM se.received_at)::int AS hour,
        COUNT(*)::bigint AS count
      FROM syslog_entries se
      WHERE se.received_at > NOW() - make_interval(hours => $1)
      ${metricClause}
      ${sf.clause}
      GROUP BY dow, hour
      ORDER BY dow, hour
    `, [hours, ...sf.params]);
    return { metric, hours, data: rows };
  });
  res.json(data);
}));

// 2) Failed logins by country WITH a prior-period count for trend arrows.
//    count = failures in the last `hours`; prev_count = failures in the equal
//    window immediately before that (computed in one query via FILTER).
app.get('/api/stats/geo', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'se');
  // Same country resolution + known_hosts join as /api/security/failed-logins-by-country
  // (prefer the event's srccountry, fall back to known_hosts geo of the REAL source).
  // The outer time bound covers BOTH windows (now-2*hours … now); the FILTER clauses
  // split current vs prior so count + prev_count come from a single scan.
  const cacheKey = `geo:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(se.structured_data->>'srccountry', kh.country_name) AS country,
        kh.country_code,
        COUNT(*) FILTER (
          WHERE se.received_at > NOW() - make_interval(hours => $1)
        )::bigint AS count,
        COUNT(*) FILTER (
          WHERE se.received_at BETWEEN NOW() - make_interval(hours => $1 * 2)
                                   AND NOW() - make_interval(hours => $1)
        )::bigint AS prev_count,
        COUNT(DISTINCT COALESCE(se.structured_data->>'srcip', se.source_ip::text)) FILTER (
          WHERE se.received_at > NOW() - make_interval(hours => $1)
        )::bigint AS distinct_sources
      FROM syslog_entries se
      LEFT JOIN known_hosts kh
        ON COALESCE(se.structured_data->>'srcip', se.source_ip::text) ~ '^[0-9.]+$'
       AND host(kh.ip_address) = COALESCE(se.structured_data->>'srcip', se.source_ip::text)
      WHERE se.received_at > NOW() - make_interval(hours => $1 * 2)
        AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
        AND COALESCE(se.structured_data->>'srccountry', kh.country_name) IS NOT NULL
        AND COALESCE(se.structured_data->>'srccountry', kh.country_name) <> ''
      ${sf.clause}
      GROUP BY COALESCE(se.structured_data->>'srccountry', kh.country_name), kh.country_code
      HAVING COUNT(*) FILTER (WHERE se.received_at > NOW() - make_interval(hours => $1)) > 0
      ORDER BY count DESC
      LIMIT 20
    `, [hours, ...sf.params]);
    return { hours, data: rows };
  });
  res.json(data);
}));

// 3) Capacity / ingestion forecast — computed in JS from on-the-fly aggregates.
//    No stored table: daily volume → least-squares linear regression → 30-day
//    projection + status/confidence; ingestion spike (today vs avg); silent
//    devices (active before, quiet now).
app.get('/api/stats/forecast', asyncHandler(async (req, res) => {
  const days = safeInt(req.query.days, 30, 365);
  const sf = getSiteFilter(req.rbac, 2, 'se');
  const cacheKey = `forecast:${days}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    // a) Daily volume series over the requested window.
    const dailyRes = await pool.query(`
      SELECT date_trunc('day', se.received_at) AS d, COUNT(*)::bigint AS c
      FROM syslog_entries se
      WHERE se.received_at > NOW() - make_interval(days => $1)
      ${sf.clause}
      GROUP BY 1
      ORDER BY 1
    `, [days, ...sf.params]);

    const daily = dailyRes.rows.map(r => ({
      date: r.d, count: parseInt(r.c, 10) || 0,
    }));

    // b) Least-squares linear regression (x = day index, y = count).
    let slope = 0;
    const n = daily.length;
    if (n >= 2) {
      const xs = daily.map((_, i) => i);
      const ys = daily.map(d => d.count);
      const meanX = xs.reduce((a, b) => a + b, 0) / n;
      const meanY = ys.reduce((a, b) => a + b, 0) / n;
      let num = 0, den = 0;
      for (let i = 0; i < n; i++) {
        num += (xs[i] - meanX) * (ys[i] - meanY);
        den += (xs[i] - meanX) ** 2;
      }
      slope = den === 0 ? 0 : num / den;
    }

    // Project the next 30 days from the regression line: y = meanY + slope*(x-meanX).
    const meanY = n ? daily.reduce((a, d) => a + d.count, 0) / n : 0;
    const meanX = n ? (n - 1) / 2 : 0;
    let projectedTotal = 0;
    for (let k = 0; k < 30; k++) {
      const x = (n - 1) + 1 + k; // days after the last observed day
      projectedTotal += Math.max(0, Math.round(meanY + slope * (x - meanX)));
    }

    // Status by slope relative to the average daily volume (guard divide-by-zero).
    const relSlope = meanY > 0 ? slope / meanY : 0;
    let status = 'steady';
    if (relSlope > 0.02) status = 'growing';
    else if (relSlope < -0.02) status = 'declining';

    // Confidence by sample size.
    let confidence = 'low';
    if (n >= 14) confidence = 'high';
    else if (n >= 7) confidence = 'medium';

    // c) Ingestion spike — today's count so far vs avg daily count.
    const todayRes = await pool.query(`
      SELECT COUNT(*)::bigint AS c
      FROM syslog_entries se
      WHERE se.received_at >= date_trunc('day', NOW())
      ${sf.clause}
    `, sf.params);
    const today = parseInt(todayRes.rows[0]?.c, 10) || 0;
    const avgDaily = n ? Math.round(meanY) : 0;
    const spike = avgDaily > 0 ? today > avgDaily * 1.5 : false;

    // d) Silent devices — source_hosts active in the prior week but silent in the
    //    last 24h. Over an 8-day window, FILTER recent vs prior per source_host.
    const silentRes = await pool.query(`
      SELECT
        se.source_host,
        host(MAX(se.source_ip)) AS source_ip,
        COUNT(*) FILTER (
          WHERE se.received_at BETWEEN NOW() - interval '8 days' AND NOW() - interval '1 day'
        )::bigint AS prior_count,
        COUNT(*) FILTER (WHERE se.received_at > NOW() - interval '24 hours')::bigint AS recent_count,
        MAX(se.received_at) AS last_seen
      FROM syslog_entries se
      WHERE se.received_at > NOW() - interval '8 days'
        AND se.source_host IS NOT NULL AND se.source_host <> ''
      ${sf.clause}
      GROUP BY se.source_host
      HAVING COUNT(*) FILTER (
               WHERE se.received_at BETWEEN NOW() - interval '8 days' AND NOW() - interval '1 day'
             ) >= 50
         AND COUNT(*) FILTER (WHERE se.received_at > NOW() - interval '24 hours') = 0
      ORDER BY prior_count DESC
      LIMIT 20
    `, sf.params);
    const silent = silentRes.rows.map(r => ({
      source_host: r.source_host,
      source_ip:   r.source_ip,
      prior_count: parseInt(r.prior_count, 10) || 0,
      last_seen:   r.last_seen,
    }));

    return {
      volume: {
        daily,
        slope: Math.round(slope * 100) / 100,
        projected_next_30d_total: projectedTotal,
        status,
        confidence,
      },
      ingestion: { today, avg_daily: avgDaily, spike },
      silent,
    };
  });
  res.json(data);
}));

// 4) What changed vs baseline — values seen in the recent `days` window that did
//    NOT appear in the prior 30 days, via a NOT EXISTS anti-join, per dimension.
app.get('/api/stats/whats-changed', asyncHandler(async (req, res) => {
  const days = safeInt(req.query.days, 1, 30);
  const cacheKey = `whats-changed:${days}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    // Each dimension: aggregate recent-window distinct values + counts, anti-joined
    // against the set of values seen in the 30 days BEFORE the recent window. The
    // RBAC site filter is applied to BOTH the recent (r) and baseline (b) scans so a
    // restricted user only ever compares within their own sites. Param order:
    // $1 = days (recent window), $2..$2+k = site params for r, then again for b.
    function buildAntiJoin(expr, extraRecent) {
      const sfR = getSiteFilter(req.rbac, 2, 'r');
      const sfB = getSiteFilter(req.rbac, 2 + sfR.params.length, 'b');
      // COUNT(*) OVER() = total distinct NEW values after the anti-join but before
      // LIMIT, so the UI can show an honest "+N more" / tile total beyond the top 15.
      const sql = `
        SELECT v AS value, cnt AS count, COUNT(*) OVER()::bigint AS total FROM (
          SELECT ${expr.replace(/\bse\./g, 'r.')} AS v, COUNT(*)::bigint AS cnt
          FROM syslog_entries r
          WHERE r.received_at > NOW() - make_interval(days => $1)
            AND ${expr.replace(/\bse\./g, 'r.')} IS NOT NULL
            AND ${expr.replace(/\bse\./g, 'r.')} NOT IN ('', 'N/A')
            ${extraRecent ? extraRecent.replace(/\bse\./g, 'r.') : ''}
          ${sfR.clause}
          GROUP BY 1
        ) recent
        WHERE NOT EXISTS (
          SELECT 1 FROM syslog_entries b
          WHERE b.received_at BETWEEN NOW() - make_interval(days => $1) - interval '30 days'
                                  AND NOW() - make_interval(days => $1)
            AND ${expr.replace(/\bse\./g, 'b.')} = recent.v
            ${sfB.clause}
        )
        ORDER BY count DESC, value
        LIMIT 15
      `;
      const params = [days, ...sfR.params, ...sfB.params];
      return { sql, params };
    }

    const dims = {
      new_countries: buildAntiJoin(`se.structured_data->>'srccountry'`),
      new_users:     buildAntiJoin(`se.structured_data->>'user'`),
      new_sources:   buildAntiJoin(`COALESCE(se.structured_data->>'srcip', se.source_ip::text)`),
      new_services:  buildAntiJoin(`se.structured_data->>'service'`),
    };

    const [countries, users, sources, services] = await Promise.all([
      pool.query(dims.new_countries.sql, dims.new_countries.params),
      pool.query(dims.new_users.sql,     dims.new_users.params),
      pool.query(dims.new_sources.sql,   dims.new_sources.params),
      pool.query(dims.new_services.sql,  dims.new_services.params),
    ]);

    const shape = (r) => r.rows.map(x => ({ value: x.value, count: parseInt(x.count, 10) || 0 }));
    const total = (r) => (r.rows.length ? (parseInt(r.rows[0].total, 10) || r.rows.length) : 0);
    return {
      window_days:   days,
      new_countries: shape(countries),
      new_users:     shape(users),
      new_sources:   shape(sources),
      new_services:  shape(services),
      totals: {
        new_countries: total(countries),
        new_users:     total(users),
        new_sources:   total(sources),
        new_services:  total(services),
      },
    };
  });
  res.json(data);
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
  '2.18.3': [
    'Fix: the in-app "Update" (Settings) now works on fresh installs. The update API previously refused to start with a 400 when SERVER_IP was unset; it now derives the IP from LV_APP_URL and proceeds. The updater script also prepends Git/Node to the SYSTEM PATH so the pull/build/restart actually runs',
    'The update screen now shows the server error instead of spinning indefinitely when an update cannot start',
  ],
  '2.18.2': [
    'Security: upgraded the frontend Next.js 16.2.6 → 16.2.9 (patched release), clearing the bundled postcss stringify XSS advisory.',
    'Security: upgraded the backend ws 8.20.0 → 8.21.0 (WebSocket memory-exhaustion DoS) and qs to the patched 6.15.x. No functional or UI changes.',
  ],
  '2.18.1': [
    'License changes now take effect within ~5 minutes: the hub-license cache was shortened from 24 hours to 5 minutes (matching the suite\'s dynamic-settings cadence), so a reduced or revoked license enforces promptly instead of staying open for up to a day.',
    'Unlicensed/expired apps now show a full-screen lock on every entry path: the disabled-license lock screen replaces the entire app (main page and the SSO landing alike) rather than just showing a banner with the app still usable behind it.',
    'The frontend also re-checks its license every 5 minutes (down from 6 hours) so the lock appears promptly without waiting for a reload.',
  ],
  '2.18.0': [
    'Per-app license entitlement: LogVault now honours the module list on your NocVault license. If your active license key explicitly lists the products it covers and LogVault is not among them, the app locks to a "not included in this license" screen.',
    'Fail-open by design: trials, grace periods, an unreachable hub, and legacy/empty-module license keys are never blocked — only an ACTIVE key that explicitly enumerates modules and omits LogVault triggers the lock, so existing customers are never bricked.',
    'Enforcement is access-control only — no database, schema, or log-data changes. The lock is applied by the existing license middleware (402) and the disabled-screen, so no new infrastructure is required.',
    'The disabled screen now shows a clearer message for the unlicensed-module case, pointing operators to their NocVault representative rather than the generic "License Expired" copy.',
  ],
  '2.17.0': [
    'Known Hosts: you can now assign a Site to a host directly in LogVault. The Add/Edit form has a new Site dropdown populated from NetVault (the CMDB is the source of truth for sites), so manually-registered hosts that aren\'t NetVault-managed — external IPs, syslog relays like the firewall — can be put into a site.',
    'Why it matters: site-based access control (RBAC) and all per-site dashboards/alerts key on a host\'s site. Hosts with no site were invisible to site-scoped users; assigning a site fixes that.',
    'New GET /api/sites endpoint returns the active NetVault sites for the dropdown; PUT /api/hosts now accepts site_id (validated against real NetVault sites) and denormalizes the site name for the table.',
    'NetVault-synced devices are unchanged — their site still flows automatically from the CMDB every 15 minutes; the manual dropdown is for the non-managed hosts only.',
  ],
  '2.16.5': [
    'Fixed ATT&CK Coverage for site-scoped (non-admin) users: alert-derived techniques (T1190 Repeated IPS Triggers, T1110/T1133 VPN Brute Force, T1046 Port Scan) were collapsing to zero because the alert branch was filtered by the internal triggering-host IP, which is almost never registered to a site. Alerts are now scoped by the same relay/site attribution as events, so a technique an admin sees is also visible to the site-scoped user whose site produced it.',
    'Hardened cross-site isolation on the coverage matrix: alert attribution keys on the firewall relay (source_host → known_hosts.site_id) so a user never sees another site\'s techniques.',
    'Fixed the Alerts drill-down landing on an empty list: clicking an alert-only technique now passes the active time window to /api/alerts/events so the filtered view shows exactly the alerts the coverage matrix counted, instead of relying on a LIMIT 500 ordering that could push older alerts off the page.',
    '/api/alerts/events now accepts an optional `hours` query param (backward compatible) that filters by fired_at and lifts the row cap for window-scoped queries.',
  ],
  '2.16.4': [
    'ATT&CK Coverage drill-down now lands on the right evidence: clicking an alert-derived technique (e.g. T1046 Port Scan, T1190) opens the Alerts view filtered to that technique instead of an empty log search; purely event-tagged techniques still open the Log Explorer',
    'Coverage tiles now show the events/alerts split in the tooltip (N logs · M alerts), and the Alerts view can be filtered by ATT&CK technique',
  ],
  '2.16.3': [
    'ATT&CK Coverage now reflects alert-level classifications, not just per-event tags — techniques that only surface from correlation alerts (e.g. T1190 from "Repeated IPS Triggers") now light up the matrix instead of staying invisible',
    'Tightened the "Repeated IPS Triggers" correlation rule to fire only on real IPS detections (structured type/subtype=ips), so blocked outbound web/SSL traffic is no longer mislabeled as an IPS exploit (T1190)',
    'Stopped the event-level MITRE mapper from tagging T1190 on benign "FortiGuard IPS update license expiring" notices (a bare "ips" word match) that had put a phantom technique in the coverage matrix',
  ],
  '2.16.2': [
    'Made the "Logs by Vendor" widget\'s severity badges self-explaining: the compact "c"/"e" badges now have hover tooltips ("N critical" / "N error(s)") and the total shows "N total logs", plus a tiny one-line legend (c = critical · e = error) under the sub-header so the meaning is clear at a glance.',
  ],
  '2.16.1': [
    'Compacted the dashboard "Top Destinations" card — the country · ASN now sits inline on the same row as the destination IP (matching Top Connection Failures / Top Blocked) instead of wrapping to a second line.',
    'Rebalanced the dashboard into two even rows of three: Top Blocked · Top Connection Failures · Top Destinations, then Log Volume · Top Talkers · Logs by Vendor.',
  ],
  '2.16.0': [
    'New dashboard "Top Destinations" widget: outbound-callout analysis ranking the external destination IPs your network reaches out to (the destination side of firewall logs), with country/ASN enrichment and known-bad flagging — surfaces possible C2/exfil channels alongside the existing source-side Top Talkers.',
    'New UEBA "Baseline Status" panel on the Intelligence console: shows anomaly-detection readiness — days of data accumulated toward the 7-day learning window ("X of 7 days"), how many devices/users have learned baselines, and when baselines were last rebuilt.',
    'AbuseIPDB threat scoring is now fully wired end-to-end: paste a free AbuseIPDB API key in Settings (masked, super-admin only) and the collector scores external IPs into known_hosts (abuse score / known-bad / threat tags) feeding the Known-Bad Sources widget and badges. With no key configured, the widget shows a clear "not configured" prompt instead of a misleading all-clear.',
  ],
  '2.15.3': [
    'Made the Security tab more compact: the Overview KPI cards are now a tighter 4-across layout (8 cards in 2 rows instead of 3) with reduced padding, and the "Activity by Hour of Week" heatmap uses shorter cells so it takes far less vertical space. No data or behavior changes.',
  ],
  '2.15.2': [
    'Cleanup: removed the historical false-positive "Auth Failures" alerts that were created while the rule was unfiltered (they were ordinary traffic — e.g. "Connection Failed" / DNS connections and IPsec tunnel negotiation — wrongly labelled as authentication failures). Genuine auth-failure alerts are preserved. Combined with the v2.15.1 rule fix, the Alerts list is now accurate.',
  ],
  '2.15.1': [
    'Fix: default alert rules were being duplicated on every deploy (the seed had no unique constraint to conflict on), accumulating dozens of copies that each fired their own alert. De-duplicated to one of each rule, preserved all existing fired-alert history, and added a UNIQUE(name) constraint so it can never recur.',
    'Fix: the built-in "Auth Failures" alert rule had no match filter, so it fired on unrelated traffic (e.g. IPsec tunnel-negotiation noise) — which is why an "Auth Failures" alert could appear while the Security > Auth Failures tab was correctly empty. It is now scoped to genuine authentication-failure messages.',
    'Note: the Security tab panels (auth failures, brute force, firewall denies, IPS/threats) only populate when the firewall forwards those log types. If a device is sending mostly allowed-traffic and VPN session logs, those panels are correctly empty.',
  ],
  '2.15.0': [
    'Fix (attacker attribution sweep): several places were attributing activity to the syslog relay/forwarding firewall instead of the real actor (the parsed source IP). The dashboard "Top Talkers" widget now ranks by the actual source/attacker IP with per-actor geo and known-bad enrichment — previously, with a relay, it collapsed to a single row (the firewall) for all traffic.',
    'Fix: threshold-based alerts (e.g. Auth Failures, Critical Threshold) now record, suppress, and de-duplicate per real attacker IP, and the alert email shows the attacker — not the forwarding firewall. (Correlation alerts already did this.)',
    'Fix: the alert detail "triggering logs" drill now returns the specific actor\'s events instead of every log from the relay device in the time window; the alert detail panel shows the attacker as "Source" with the relay listed separately as "Reporting device".',
    'Fix: the Known-Bad Sources hit counter now matches the flagged IP against the parsed source/destination IPs, so genuine external threats are counted instead of always reading zero.',
    'Attacker source IPs are now GeoIP/threat-enriched (in addition to destination IPs), so country/ASN/known-bad data is available for the real actor across Top Talkers, Known-Bad Sources, and UEBA risk scoring.',
  ],
  '2.14.0': [
    'Fix: the UEBA "Riskiest Entities" ranking no longer lists the log-source/relay device itself (e.g. the forwarding firewall). Because every log arrives through the relay, it always won on raw volume — which is meaningless. UEBA now scores only real actors (users, external source IPs, monitored assets); relay hosts are excluded from device baselines, anomaly detection, and entity-risk, and any previously-recorded relay entity is cleaned up automatically. Configurable via the UEBA_RELAY_HOSTS environment variable.',
    'Improved the dashboard "What\'s New / Changed" widget: instead of one long scrolling list, it now shows four at-a-glance count tiles (New Sources / Accounts / Services / Countries) that double as a selector, with a compact top-5 list and a "+N more" expander for the chosen dimension. Each item still drills into the Log Explorer.',
    'The /api/stats/whats-changed endpoint now also returns the true total count per dimension, so the tile numbers and "+N more" reflect everything new, not just the displayed rows.',
  ],
  '2.13.0': [
    'Phase 2 intelligence engine (fully on-prem, no external calls): behavioral baselining of normal activity per device and user (hour-of-week), statistical anomaly detection (volume spike/drop, silent device, new source country / new service), and UEBA rolling entity-risk scoring.',
    'New "Intelligence" tab: an anomalies console (filter, acknowledge, drill to the Log Explorer) and a "Riskiest Entities" (UEBA) ranking with a per-entity slide-in showing the risk-factor breakdown, recent anomalies, and an events summary.',
    'New dashboard "Riskiest Entities" widget.',
    'Correlation thresholds are now adaptive — they auto-relax for chronically noisy entities (fewer false positives) and never become more sensitive; they fall back to the existing static thresholds until baselines are learned.',
    'Note: anomalies and baselines populate as history accumulates (roughly 1-2 weeks); entity-risk scores populate within minutes of deploy.',
  ],
  '2.12.3': [
    'Fix: Log Explorer search (and the dashboard "What\'s New / Changed" account/country/service drills) now also match the parsed username, source country, and service fields — not just the message text — so drilling by an account or country returns its events instead of an empty result.',
  ],
  '2.12.2': [
    'Fix: clicking a "Threat Summary" card in the Security tab now opens the Log Explorer filtered to that specific threat and shows its events (new `threat` filter matching the parsed threat identity), instead of landing on an empty result.',
  ],
  '2.12.1': [
    'Fix: drilling from a Security-tab row (IPS/Threats, blocked destinations, threat summary, etc.) into the Log Explorer by IP now returns results — the host filter now also matches the parsed source/destination IPs (structured_data.srcip/dstip/remip), not just the reporting device. Previously, drilling by an internal/client IP showed "No logs found".',
  ],
  '2.12.0': [
    'Risk scores are now explainable — each event records its contributing factors, and the log detail panel shows a "Why this score?" breakdown.',
    'MITRE ATT&CK badges now carry plain-language explanations (what the technique means and why it matters) in a hover popover.',
    'New on-prem analytics (no external calls): capacity & ingestion forecasting with spike and silent-device detection, and a "what\'s new vs the last 30 days" view (new countries, accounts, sources, services).',
    'New visualizations: activity-by-hour-of-week heatmaps (overall + failed logins) and per-country failed-login trend arrows in the Security tab.',
    'New dashboard widgets: Capacity & Ingestion Health and What\'s New / Changed.',
    'Added shared severity-color and trend-arrow UI primitives for consistent representation.',
  ],
  '2.11.1': [
    'Fix: the Log Explorer (and CSV export) returned HTTP 500 when filtering by host — a SQL parameter-index offset in the host filter shifted every later placeholder (RBAC filter, LIMIT/OFFSET) out of alignment.',
    'Drilling from a Security-tab row (e.g. IPS/Threats) into the Log Explorer by host now loads results correctly instead of erroring.',
  ],
  '2.11.0': [
    'Security-tab tables are now clickable: each row drills into the Log Explorer pre-filtered to its context — source/attacker IP, targeted user, denied service, blocked destination, threat, or ATT&CK technique.',
    'Reuses the existing Log Explorer and its detail view (no new slide-ins or panels), so the Security analytics are now directly actionable for investigation.',
    'Subtle hover + pointer affordance on every drillable row; rows with no useful filter value stay non-clickable.',
  ],
  '2.10.0': [
    'Alerts are now clickable: a detail slide-in shows the alert\'s rule, severity, MITRE techniques, source, match count, detection window, and acknowledgement status.',
    'The panel lists the actual underlying logs that triggered the alert (by source within the rule\'s time window), each drillable into the full log detail view.',
    'New API: GET /api/alerts/events/:id/logs returns an alert plus its triggering log entries (RBAC-filtered).',
  ],
  '2.9.0': [
    'Applied the deep field-capture & correctness pass (previously done for Fortinet) to ALL vendor parsers: Cisco, Palo Alto, Check Point, SonicWall, Juniper, Windows, Aruba, Sangfor, Forcepoint, and the generic fallback',
    'Every parser now emits the normalized contract (real remote source IP, dest IP, ports, username, login outcome) and the correct category, so cross-vendor brute-force/scan/IPS correlation and the Security tab work for all brands',
    'Captures full security context: IPS/threat signature names + severity, web-filter URLs + categories, VPN/auth identity, and traffic service/proto/bytes/geo',
    'Timezone-correct timestamps where the vendor log carries an offset (Check Point, SonicWall, Juniper, Windows, PAN-OS) instead of relying on the collector\'s OS locale',
    'Expanded Windows Security event coverage (logon, account management, Kerberos/NTLM, process creation, audit) and Cisco multi-product coverage (ASA/FTD/ISE/AnyConnect auth, traffic, denies, intrusion)',
    'Cross-vendor risk scoring now boosts events carrying a threat/signature name; firewall classification recognizes more action verbs. (Vendor mappings validated against synthetic samples — spot-check against real logs, especially PAN-OS CSV indices, when each device is onboarded.)',
  ],
  '2.8.0': [
    'Fortinet parser now captures ~40 more log fields (service, geo, interfaces, session/bytes; VPN gateway/port/IPsec status/XAuth user; UTM threat type/cert/hostname; webfilter URL/category/risk-level; admin UI/user) — fixes the empty "Top Services" widget and blank IPS threat names',
    'Timestamps now use each log\'s own timezone offset instead of the collector\'s OS locale (prevents hour-shifted times)',
    'Malicious-category / high-risk webfilter blocks are now classified as Security instead of Web',
    'Risk scoring is now discriminating (auth failures, denied traffic, and FortiGate\'s own crlevel/crscore) instead of a flat severity+category lookup',
    'Successful SSL-VPN logins are now classified, fixing brute-force-success correlation',
    'Security tab IPS/Threats view shows the real threat name, target URL/host, web category, and threat level; backfill script extended to recover these fields for historical logs',
  ],
  '2.7.1': [
    'Added scripts/backfill-fortinet-srcip.js to recover the real remote source IP, username, and country for pre-fix historical Fortinet events (re-parses raw_message through the current parser; dry-run by default)',
    'Backfill is purely additive and idempotent — it only fills missing fields and preserves existing structured_data (mitre, category, etc.), so historical slide-in detail + CSV export match new rows',
  ],
  '2.7.0': [
    'CSV export now includes the detail-panel fields for analysis: real remote source IP, country, username, login outcome (subcategory), action, subtype, destination IP, and reason — previously only top-level columns (which showed the reporting firewall, not the attacker)',
    'Export CSV is now RFC-4180 quoted and blanks the firewall\'s "N/A" placeholders for clean analysis',
    'Detail slide-in now labels pre-authentication probes ("no credentials submitted") when a VPN/auth event has a remote source but no username',
  ],
  '2.6.0': [
    'Security tab now shows the real attacker IP, targeted username, and source country for auth/VPN failures (previously showed the reporting firewall)',
    'New widgets: Top Targeted Usernames and Failed Logins by Country',
    'New KPIs: VPN Login Failures and failures From Known-Bad IPs (threat-intel via known_hosts)',
    'Auth-failure / brute-force / VPN-event detection now uses normalized login_failed/login_success classification instead of loose message matching — eliminates false "VPN brute force" alerts from benign SSL teardown/negotiation events',
    'Fortinet parser now classifies VPN/login auth outcome (subcategory) so failures are detected and correlated',
  ],
  '2.5.0': [
    'All vendor parsers (Cisco, Palo Alto, Windows, Juniper, SonicWall, Aruba, Check Point, Sangfor, Forcepoint, generic) now extract the real remote client IP, username, and login outcome for auth/VPN/failed-login events — previously only Fortinet did',
    'Brute-force, VPN-brute-force, port-scan, and repeated-IPS correlation rules are now vendor-agnostic (previously Fortinet-only) and attribute alerts to the real attacker IP, not the relaying device',
    'Windows failed logons (Event ID 4625/4771/4768/4776) are now classified and correlated for brute-force detection',
    'Source IP, user, and login outcome are surfaced consistently as structured_data.srcip / user / subcategory across all vendors',
    'Note: Palo Alto CSV column positions are best-effort pending live PAN-OS samples and may need tuning',
  ],
  '2.4.0': [
    'Fortinet parser now captures the remote client IP (remip), username, source country, and failure reason for SSL-VPN / auth events (previously dropped)',
    'Log Explorer now shows the real remote source (and user/country) for VPN/auth events instead of the reporting firewall',
    'A single failed login is no longer mislabeled "Brute Force" (MITRE T1110) — brute force is now determined by correlation (repeated failures) or explicit lockout/spray, matching the T1133 approach',
    'VPN brute-force correlation can now group by the real attacker IP (srcip = remip), so genuine attacks are detected and attributed correctly',
    'Added a backfill script to clear the incorrect T1110 tag from previously-ingested single-failure events',
  ],
  '2.3.1': [
    "Launcher 'Log Sources' KPI now counts distinct source_host instead of source_ip (correct when devices send via syslog relays)",
    'In production, devices forward syslog through relays, so source_ip collapses to the relay IP and undercounts the real number of log-emitting devices',
    'source_host preserves each device’s true identity, so the metric now reflects how many distinct devices are actually sending logs',
    'No schema or ingestion change — this only corrects the public /api/stats summary counter surfaced on the launcher',
  ],
  '2.3.0': [
    'The Security tab now has its own time-range picker (and auto-refresh control), matching the Dashboard and Network Health — you can change the window without leaving the page',
  ],
  '2.2.2': [
    'MITRE precision: routine VPN traffic (IPsec negotiate, SSL alerts) is no longer tagged T1133 at the event level — it was drowning the ATT&CK Coverage view in benign VPN volume. T1133 now maps only on the VPN brute-force correlation alert, where it is security-relevant',
    'Added scripts/fix-mitre-vpn-t1133.js to strip the over-broad T1133 tag from already-tagged events (run once as postgres)',
  ],
  '2.2.1': [
    'MITRE mapping coverage: event tagging now reads the structured subtype/type fields (e.g. Fortinet IPS/VPN events) and a broader set of auth-failure phrasings, so more events map to techniques like T1190/T1133/T1110',
    'Hardened the ATT&CK coverage query so an unexpected non-array value under structured_data.mitre can never error the endpoint',
    'Log Explorer: applying a preset now clears an active ATT&CK technique deep-link filter',
  ],
  '2.2.0': [
    'MITRE ATT&CK mapping: alerts now carry ATT&CK technique tags — the 8 correlation rules map to techniques (Brute Force T1110, External Remote Services T1133, Network Service Discovery T1046, Exploit Public-Facing App T1190, Impair Defenses T1562), and user threshold rules can declare their own',
    'Log events are tagged with ATT&CK techniques at ingest (shown in the log detail panel); filter the Log Explorer by technique',
    'New ATT&CK Coverage view in the Security tab — a tactic-by-technique matrix of how much observed activity maps to each technique over the selected window',
    'Technique badges link out to the technique definition on attack.mitre.org',
  ],
  '2.1.8': [
    'Top Blocked Destinations & Top Connection Failures: the country flag · country · ASN now sits inline on the same row as the destination IP (was a separate line) — more compact and readable',
    'Top Connection Failures now shows GeoIP context too (flag/country/ASN for external destinations like 8.8.8.8), matching Top Blocked Destinations',
    'Fixed the last row touching the bottom edge of the Top Connection Failures card — it now scrolls inside the card like the other widgets',
  ],
  '2.1.7': [
    'Dashboard layout: Top Blocked Destinations and Top Connection Failures now share a wider 2-column row so the destination IP, country flag, ASN and known-bad badge have room to read clearly',
    'The remaining dashboard widgets reflow into clean 3-per-row rows (Top Security Events / VPN Status / Firewall Actions, and Timeline / Top Talkers / Vendor Breakdown)',
  ],
  '2.1.6': [
    'Fixed country flag / GeoIP context never appearing on Top Blocked Destinations and Top Connection Failures — the destination-IP join compared known_hosts.ip_address::text (which keeps the /32 mask, e.g. "17.248.154.174/32") against the unmasked dstip and never matched. It now joins on host(ip_address), so country/ASN/flag show for enriched destinations',
    'Top Talkers now displays source IPs without the trailing /32 mask',
  ],
  '2.1.5': [
    'Fixed Top Blocked Destinations, Top Connection Failures, Top Talkers, Top Security Events, Severity Summary and the activity Timeline rendering empty for regular (non-admin) users — the site filter on these aggregate dashboard widgets was too strict',
    'Dashboard stat widgets now treat unregistered/unassigned devices (e.g. a firewall not yet assigned a site in known_hosts) as visible to all users; only devices explicitly assigned to a site are restricted. Detailed log access (Log Explorer, export, alerts) keeps the strict per-site filter',
  ],
  '2.1.4': [
    'Fixed Top Blocked Destinations and Top Connection Failures widgets returning empty — the destination-IP geo join now casts the address to text (works whether the column is inet or text and never errors on a non-IP destination)',
    'Top Blocked Destinations now detects blocks vendor-agnostically (matches the actual action values in the data, e.g. Fortinet "blocked", Palo Alto "deny"/"drop") instead of narrow per-vendor rules that silently matched nothing',
  ],
  '2.1.3': [
    'Fixed the Storage & Capacity widget showing "LOG TABLE: 0 bytes" (and "AVG GROWTH/DAY: N/A") after the Phase 3 partitioning migration — the size now sums all daily partitions instead of measuring the empty partitioned parent table',
  ],
  '2.1.2': [
    'GeoIP/threat enrichment now also covers destination IPs — in firewall logs (e.g. Fortinet) the external IP is the destination (dstip), while source_ip is the internal device',
    'The collector now enriches and stores external destination IPs in known_hosts at ingest, alongside source IPs (private IPs still never leave the box)',
    'Top Blocked Destinations and Top Connection Failures widgets now show country/ASN and known-bad badges for the destination IP they display (previously they showed geo for the source device)',
  ],
  '2.1.1': [
    'Top Talkers widget now shows country flag, country/ASN and an AbuseIPDB known-bad badge per source, with a red highlight on flagged rows — matching the other dashboard widgets',
  ],
  '2.1.0': [
    'GeoIP enrichment: external source IPs are now tagged with country, city and ASN/owner (free ip-api.com, no key required)',
    'Threat intelligence: optional AbuseIPDB scoring flags known-bad IPs (set a free API key in Settings → Threat Intelligence)',
    'New "Known-Bad Sources" dashboard widget and country/ASN context on top-talker / blocked / failure widgets',
    'New GET /api/threats/known-bad endpoint (RBAC-filtered) listing flagged external IPs with 24h hit counts',
    'Enrichment runs at ingest in the collector (private IPs never leave the box, never blocks ingestion) and is stored in known_hosts',
  ],
  '2.0.0': [
    'Log storage is now time-partitioned (daily) — retention drops whole partitions instead of slow bulk DELETEs, keeping the database fast as it grows',
    'Tamper-evident log integrity: every entry is hash-chained (HMAC-SHA256) and logs are now append-only, so any modification is detectable (run scripts/verify-integrity.js to check)',
    'Durable ingest spool: syslog is written to a disk write-ahead spool and replayed on restart, so a crash or database outage no longer loses logs',
    'New immutable audit trail of privileged actions (settings changes, exports, acknowledgements, syncs, updates) — viewable by super-admins at /api/audit',
    'DB migration required for existing servers: run scripts/migration-phase3-partitioning.sql manually (maintenance window + backup) — fresh installs get it automatically',
  ],
  '1.5.0': [
    'Security hardening: removed all hardcoded credential fallbacks from code and scrubbed secrets from the repo — passwords and NEXTAUTH_SECRET now come only from NSSM/.env',
    'Session cookies now auto-enable the Secure flag when served over HTTPS (no change on HTTP deployments)',
    'Collector can now restrict ingestion by source IP/CIDR allow-list and rate-limit per source (both opt-in, default off — no impact on existing ingestion)',
    'Alert acknowledgements now record who acknowledged them (acknowledged_by)',
    'Fixed an alerting bug where threshold rules could silently never fire when the event count jumped past the threshold in one burst',
  ],
  '1.4.0': [
    'Network Health now has a time-range picker in its header, matching the other pages',
    'Switch between 15m / 1h / 6h / 24h / 48h / 7d / 30d (and custom ranges) without leaving the page — defaults to 24h',
    'Changing the range refetches all counts, events and the device-status window',
  ],
  '1.3.12': [
    'Fixed the Log Explorer results table header bleeding through and looking garbled when scrolling in dark mode',
    'Sticky table header now uses an opaque background so rows no longer show through it',
  ],
  '1.3.11': [
    'Fixed an undefined CSS token on time-range selects so they use the correct adaptive input background',
  ],
  '1.3.10': [
    'Dropdown and select menus are now readable in dark mode',
    'Native select option popups, scrollbars and date/number controls follow the theme via color-scheme',
    'Custom dropdown panels use adaptive surface tokens instead of light backgrounds',
  ],
  '1.3.9': [
    'Settings nav icon is now a gear (was a sun)',
    'Fixed the Security shield icon being clipped at the bottom',
  ],
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
  '1.3.5': [
    'Made the dashboard Log Volume / Top Blocked / Top Talkers / Vendor row four equal-width columns',
    'Fixed the Top Blocked Destinations scrollbar overlapping the count — added clearance so numbers stay readable',
  ],
  '1.3.6': [
    'Fixed Network Health panel text being unreadable in dark mode',
    'Improved contrast of the Active Alerts "fired" tile in dark mode',
  ],
  '1.3.7': [
    'Dark-mode polish: introduced adaptive surface/tint design tokens (--surface-subtle, --tint-info/success/warn/danger + matching -fg)',
    'Swept hardcoded light surface hexes (tiles, rows, table headers, badges, banners, dropdowns) onto the new tokens so they adapt to dark mode',
    'Fixed unreadable amber/red alert banners, VPN/security stat tiles, and tinted table rows in dark mode',
    'Added a dark override for --primary-light to match the rest of the suite',
  ],
  '1.3.8': [
    'Completed the dark-mode polish: added an adaptive --tint-purple / --tint-purple-fg token to the suite-standard set',
    'Tinted the remaining purple surfaces (brute-force-success tile/banner, OSPF/BGP/EIGRP/storm-shutdown chips) so they stay readable in dark mode',
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

  // SERVER_IP is only persisted to .env.local for future use by the updater — the
  // update itself does not require it. Don't block the update if it's unset (the
  // suite installer doesn't always provision it for LogVault). Fall back to the
  // host derived from LV_APP_URL, and only warn if it's still empty.
  const serverIp = process.env.SERVER_IP || (process.env.LV_APP_URL || '').replace(/^https?:\/\//, '').split(':')[0] || '';
  if (!serverIp) {
    console.warn('[Update] SERVER_IP not configured and LV_APP_URL unset — proceeding without a server IP.');
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
    await writeAudit(pool, req, 'system.update', { detail: { version } });
    res.json({ started: true });
  } catch (err) {
    console.error('[Update] schtasks error:', err.message);
    await writeAudit(pool, req, 'system.update', { result: 'error', detail: { message: err.message } });
    res.status(500).json({ error: 'Failed to schedule update: ' + err.message });
  }
}));

// ── APP SETTINGS ─────────────────────────────────────────────

app.get('/api/settings', asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM app_settings');
  const data = Object.fromEntries(rows.map(r => [r.key, r.value]));
  // Never expose secrets (SMTP password, AbuseIPDB API key) to anyone but a
  // super_admin (the only role that can edit them). Settings writes are already
  // super_admin-gated.
  if (!req.rbac || !req.rbac.isSuperAdmin) {
    delete data.smtp_pass;
    delete data.abuseipdb_api_key;
  }
  res.json({ data });
}));

app.post('/api/settings', requireSuperAdmin, asyncHandler(async (req, res) => {
  const allowed = ['app_name', 'app_subtitle', 'primary_color', 'sidebar_color', 'logo_url',
    'dns_server', 'dns_lookup_enabled',
    'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_from', 'smtp_enabled',
    'email_notify_enabled', 'email_notify_severities', 'email_notify_categories',
    'email_notify_vendors', 'email_notify_min_risk', 'email_notify_digest_mode',
    'email_notify_digest_hour', 'email_notify_recipients', 'email_notify_cooldown_mins',
    'abuseipdb_api_key'];
  const changedKeys = [];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      await pool.query(
        `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, req.body[key]]
      );
      changedKeys.push(key);
    }
  }
  // Audit changed KEYS only — never the values (e.g. smtp_pass).
  await writeAudit(pool, req, 'settings.update', { detail: { keys: changedKeys } });
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
  // Audit the recipient + outcome only — never the SMTP credentials.
  await writeAudit(pool, req, 'settings.test_email', {
    target: to,
    result: result.ok ? 'success' : 'error',
  });
  if (result.ok) {
    res.json({ ok: true });
  } else {
    res.status(400).json({ error: result.error || 'Failed to send test email' });
  }
}));

// ── AUDIT TRAIL ──────────────────────────────────────────────
// Super-admin-only view of the append-only audit_log. Optional filters:
//   ?hours=  lookback window (default 720 / 30 days, max 8760)
//   ?action= exact action match (e.g. 'logs.export')
//   ?actor=  exact actor_user_id match
//   ?limit=  max rows (default 200, max 1000)
app.get('/api/audit', requireSuperAdmin, asyncHandler(async (req, res) => {
  // Default to a 30-day window when ?hours= is omitted (safeHours' own default
  // is 24h, too short for an audit view).
  const hours = req.query.hours != null ? safeHours(req.query.hours, 8760) : 720;
  const limit = safeInt(req.query.limit, 200, 1000);

  const conditions = ['occurred_at > NOW() - make_interval(hours => $1)'];
  const params = [hours];
  let p = 2;

  if (req.query.action) { conditions.push(`action = $${p++}`);        params.push(String(req.query.action)); }
  if (req.query.actor)  { conditions.push(`actor_user_id = $${p++}`); params.push(String(req.query.actor)); }

  params.push(limit);
  const { rows } = await pool.query(`
    SELECT id, occurred_at, actor_user_id, actor_role, action, target, detail, source_ip, result
    FROM audit_log
    WHERE ${conditions.join(' AND ')}
    ORDER BY occurred_at DESC
    LIMIT $${p}
  `, params);
  res.json({ data: rows });
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
      pool.query(`SELECT COUNT(DISTINCT source_host) AS c FROM syslog_entries WHERE received_at > NOW() - INTERVAL '24 hours'`),
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
