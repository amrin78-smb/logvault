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
const { rbacMiddleware, requireSuperAdmin, requireAdmin, getSiteFilter, getStatsSiteFilter, getAlertSiteFilter, getRollupSiteFilter } = require('./rbac');
const { getLicense, getLicenseState } = require('./licenseCheck');
const { writeAudit } = require('./auditLog');
const { createReportsRouter } = require('./reports');
const { createSocRouter } = require('./soc');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

// App version — single source of truth is the root package.json.
const { version } = require('../package.json');

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

// ── No intermediary caching, EVER (perf-incident fix, 2026-07) ─────────
// Every API response here was missing any Cache-Control header at all --
// only a weak ETag. A response with no explicit caching directive but WITH
// a validator like an ETag is exactly the shape RFC 7234 permits a
// compliant proxy/cache to store heuristically. On a corporate network with
// a transparent caching proxy/security appliance in the path, this can
// (and, in a live incident, did) cause different requests for the SAME
// dynamic endpoint to intermittently return a stale cached response instead
// of hitting this server -- invisible from server-side testing (a direct
// curl bypassing that proxy sees the origin every time and looks perfectly
// consistent) and NOT fixable by a browser hard-refresh or an Incognito/
// InPrivate window (neither has any effect on a cache that lives on
// network infrastructure between the browser and this server, not in the
// browser itself). Every response from this API must explicitly forbid
// caching so no RFC-compliant intermediary can legally store it.
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

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

  const exemptPaths = ['/api/health', '/api/stats', '/api/license-status', '/api/system/update-available', '/api/system/last-update-status'];
  if (state.disabled && !exemptPaths.some(p => req.path.startsWith(p))) {
    return res.status(402).json({
      error: 'License has expired. Please renew your NocVault license.',
      license_status: license?.status,
    });
  }
  next();
}

app.use(enforceLicense);

// ── REPORTING (Phase 1) ──────────────────────────────────────
// Mounted after rbacMiddleware (req.rbac exists) and enforceLicense (gated
// identically to the /api/stats/* routes below — same license-exempt path
// prefix list does NOT include /api/reports, so it follows the normal
// license gate, matching every other business route in this file).
app.use('/api/reports', createReportsRouter(pool));
app.use('/api/soc', createSocRouter(pool));

// ── DASHBOARD STATS ──────────────────────────────────────────

app.get('/api/stats/summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  // Reads the pre-aggregated hourly rollup (scripts/schema.sql "HOURLY ROLLUP
  // TABLES") instead of scanning raw syslog_entries — site_id is already
  // resolved on the rollup row, so getRollupSiteFilter is a plain column
  // filter (no known_hosts join needed at read time).
  const sf = getRollupSiteFilter(req.rbac, 2);
  const cacheKey = `summary:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT severity, severity_label, SUM(log_count)::bigint AS log_count
      FROM syslog_stats_rollup
      WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
      ${sf.clause}
      GROUP BY severity, severity_label
      ORDER BY severity
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
  const cacheKey = `timeline:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    if (hours <= 6) {
      // 5-minute bucket granularity — the hourly rollup can't serve this, so
      // this branch is unchanged: raw syslog_entries scan + getStatsSiteFilter.
      const sf = getStatsSiteFilter(req.rbac, 3, 'syslog_entries');
      const { rows } = await pool.query(`
        SELECT
          date_trunc('minute', received_at)
            - (EXTRACT(MINUTE FROM received_at)::int % $2) * INTERVAL '1 minute' AS bucket,
          severity_label,
          COUNT(*) AS log_count
        FROM syslog_entries
        WHERE received_at > NOW() - make_interval(hours => $1)
        ${sf.clause}
        GROUP BY bucket, severity_label
        ORDER BY bucket
      `, [hours, mod, ...sf.params]);
      return { hours, bucket, data: rows };
    }
    // 1-hour / 6-hour bucket granularity — served from the pre-aggregated
    // hourly rollup (scripts/schema.sql "HOURLY ROLLUP TABLES"). hour_bucket
    // is already hour-truncated at write time, so no need to re-truncate it.
    const sf = getRollupSiteFilter(req.rbac, 3);
    const { rows } = await pool.query(`
      SELECT
        hour_bucket - (EXTRACT(HOUR FROM hour_bucket)::int % $2) * INTERVAL '1 hour' AS bucket,
        severity_label,
        SUM(log_count)::bigint AS log_count
      FROM syslog_stats_rollup
      WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
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
  // RBAC site-scoping (on the relay device) reads from the pre-aggregated
  // syslog_talker_rollup (scripts/schema.sql "HOURLY ROLLUP TABLES"), keyed by
  // the ACTOR ip (srcip) — the collector already resolves site_id per-actor at
  // rollup-build time, so getRollupSiteFilter is a plain column filter here.
  // Display enrichment (hostname/vendor fallback/geo/threat) stays a LIVE join
  // to known_hosts, independent of site-scoping, so it always reflects current
  // enrichment rather than a stale rollup snapshot.
  const sf = getRollupSiteFilter(req.rbac, 3);
  const cacheKey = `top-talkers:${hours}:${limit}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(kh.hostname, agg.actor) AS host,
        agg.actor AS source_ip,
        COALESCE(kh.vendor, agg.vendor) AS vendor,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        agg.log_count,
        -- NOTE (intentional trade-off): last_seen is now MAX(hour_bucket) — the
        -- HOUR this actor was last active in, not an exact timestamp like the
        -- old MAX(received_at). Acceptable for a live-refreshing dashboard
        -- widget; do not "fix" this by joining back to raw syslog_entries —
        -- that would defeat the entire purpose of reading from the rollup.
        agg.last_hour AS last_seen
      FROM (
        SELECT srcip AS actor, MAX(vendor) AS vendor, SUM(log_count) AS log_count, MAX(hour_bucket) AS last_hour
        FROM syslog_talker_rollup
        WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
        ${sf.clause}
        GROUP BY srcip
      ) agg
      LEFT JOIN known_hosts kh ON agg.actor ~ '^[0-9.]+$' AND host(kh.ip_address) = agg.actor
      ORDER BY agg.log_count DESC
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
// Reads syslog_dest_rollup (scripts/schema.sql "PHASE 3 HOURLY ROLLUP
// TABLES") instead of scanning raw syslog_entries. This endpoint was measured
// at 3.6s (24h) up to 76s (168h) live — identical disk-spilled-sort shape to
// the pre-fix syslog_talker_rollup problem, just on the destination side
// (see CLAUDE.md's Phase 3 write-up). Geo/threat enrichment stays a LIVE join
// to known_hosts, same as top-talkers. One disclosed precision trade-off,
// same as top-talkers: last_seen is now MAX(hour_bucket) (hour-granularity),
// not an exact timestamp — don't "fix" this by joining back to raw
// syslog_entries, that defeats the point of the rollup.
app.get('/api/stats/top-destinations', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const limit = safeInt(req.query.limit, 10, 50);
  const sf = getRollupSiteFilter(req.rbac, 3);
  const cacheKey = `top-destinations:${hours}:${limit}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(kh.hostname, agg.dstip) AS host,
        agg.dstip AS dst_ip,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        agg.log_count,
        agg.last_hour AS last_seen
      FROM (
        SELECT dstip, SUM(log_count) AS log_count, MAX(hour_bucket) AS last_hour
        FROM syslog_dest_rollup
        WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
        ${sf.clause}
        GROUP BY dstip
      ) agg
      -- host() strips the /32 that known_hosts.ip_address (INET) renders.
      -- LEFT JOIN keeps rows with no enrichment (geo cols NULL).
      LEFT JOIN known_hosts kh ON host(kh.ip_address) = agg.dstip
      ORDER BY agg.log_count DESC
      LIMIT $2
    `, [hours, limit, ...sf.params]);
    return { hours, data: rows };
  });
  res.json(data);
}));

app.get('/api/stats/by-vendor', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  // Reads the pre-aggregated hourly rollup (scripts/schema.sql "HOURLY ROLLUP
  // TABLES") instead of scanning raw syslog_entries. No getCached wrapper here
  // — matches the pre-existing (uncached) behavior of this endpoint.
  const sf = getRollupSiteFilter(req.rbac, 2);
  const { rows } = await pool.query(`
    SELECT
      vendor,
      SUM(log_count)::bigint AS log_count,
      SUM(log_count) FILTER (WHERE severity <= 2) AS critical_count,
      SUM(log_count) FILTER (WHERE severity = 3)  AS error_count,
      SUM(log_count) FILTER (WHERE severity = 4)  AS warning_count
    FROM syslog_stats_rollup
    WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sf.clause}
    GROUP BY vendor
    ORDER BY log_count DESC
  `, [hours, ...sf.params]);
  res.json({ hours, data: rows });
}));

// Reads syslog_security_event_rollup (scripts/schema.sql "PHASE 2 HOURLY
// ROLLUP TABLES") instead of scanning raw syslog_entries. This endpoint used
// to take 17-29s live: `severity <= 4` matches ~100% of a typical day's rows
// here, so the filter has no selectivity and no index can help it — it
// needed pre-aggregation, not a better index. See CLAUDE.md's Phase 2
// rollup write-up for the full incident.
app.get('/api/stats/top-security-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const cacheKey = `top-security-events:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT event_type, SUM(log_count)::bigint AS count
      FROM syslog_security_event_rollup
      WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
      ${sf.clause}
      GROUP BY event_type
      ORDER BY count DESC
      LIMIT 7
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

// Reads syslog_dest_event_rollup WHERE event_class = 'failure' (scripts/schema.sql
// "PHASE 2 HOURLY ROLLUP TABLES") instead of scanning raw syslog_entries. Geo/
// threat enrichment stays a LIVE join to known_hosts on dstip — same reasoning
// as top-talkers/top-destinations, so enrichment always reflects current
// threat-intel data rather than a stale rollup-time snapshot.
app.get('/api/stats/top-failures', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const cacheKey = `top-failures:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        agg.dstip AS dst_ip, agg.service,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        agg.fail_count
      FROM (
        SELECT dstip, service, SUM(log_count) AS fail_count
        FROM syslog_dest_event_rollup
        WHERE event_class = 'failure'
          AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
        ${sf.clause}
        GROUP BY dstip, service
      ) agg
      -- host(ip_address): known_hosts.ip_address is INET stored WITH a /32 mask
      -- (e.g. 17.248.154.174/32); host() strips it so it matches the unmasked
      -- dstip string. LEFT JOIN keeps rows with no known_hosts match (geo NULL).
      LEFT JOIN known_hosts kh
        ON agg.dstip ~ '^[0-9.]+$' AND host(kh.ip_address) = agg.dstip
      ORDER BY agg.fail_count DESC
      LIMIT 5
    `, [hours, ...sf.params]);
    return { data: rows };
  });
  res.json(data);
}));

// Reads syslog_dest_event_rollup WHERE event_class = 'blocked' — see the
// top-failures comment above for the rollup table and live-enrichment
// rationale (identical here, just the other event_class).
app.get('/api/stats/top-blocked', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const cacheKey = `top-blocked:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 30000, async () => {
    const { rows } = await pool.query(`
      SELECT
        agg.dstip AS dst_ip, agg.service, agg.vendor,
        kh.country_code, kh.country_name, kh.asn_org,
        kh.abuse_score, kh.is_known_bad, kh.is_external,
        agg.deny_count
      FROM (
        SELECT dstip, service, vendor, SUM(log_count) AS deny_count
        FROM syslog_dest_event_rollup
        WHERE event_class = 'blocked'
          AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
        ${sf.clause}
        GROUP BY dstip, service, vendor
      ) agg
      LEFT JOIN known_hosts kh
        ON agg.dstip ~ '^[0-9.]+$' AND host(kh.ip_address) = agg.dstip
      ORDER BY agg.deny_count DESC
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
        -- se.structured_data ? 'mitre' (perf pass, 2026-07) is a GIN
        -- existence check against idx_syslog_structured, letting the planner
        -- use a Bitmap Index Scan instead of a full sequential scan just to
        -- discover most rows have no 'mitre' key at all — measured 8s -> 250ms
        -- (~30x) on a live 24h window where zero rows currently carry MITRE
        -- tags. The LATERAL unnest below still does the real per-technique
        -- work; this predicate only prunes rows that could never contribute
        -- to it. Do not remove this "redundant-looking" filter — without it
        -- the planner has no way to push the mitre-key check down to the
        -- index and falls back to evaluating the LATERAL on every row.
        SELECT t.technique AS technique, COUNT(*)::bigint AS events
        FROM syslog_entries se,
             LATERAL jsonb_array_elements_text(
               CASE WHEN jsonb_typeof(se.structured_data->'mitre') = 'array'
                    THEN se.structured_data->'mitre' ELSE '[]'::jsonb END
             ) AS t(technique)
        WHERE se.received_at > NOW() - make_interval(hours => $1)
          AND se.structured_data ? 'mitre'
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

// Reads syslog_vpn_rollup (scripts/schema.sql "PHASE 2 HOURLY ROLLUP TABLES")
// instead of scanning raw syslog_entries. The 4 metrics are independent,
// overlapping FILTER counts (a message can count in more than one), so this
// SUMs each pre-computed column across the window rather than re-deriving
// them — matches the rollup's own build query exactly.
app.get('/api/stats/vpn-summary', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const { rows } = await pool.query(`
    SELECT
      COALESCE(SUM(total), 0)::bigint      AS total,
      COALESCE(SUM(failures), 0)::bigint   AS failures,
      COALESCE(SUM(successes), 0)::bigint  AS successes,
      COALESCE(SUM(ssl_alerts), 0)::bigint AS ssl_alerts
    FROM syslog_vpn_rollup
    WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sf.clause}
  `, [hours, ...sf.params]);
  res.json(rows[0]);
}));

app.get('/api/stats/alerts-summary', asyncHandler(async (req, res) => {
  // RBAC: scope by the relay (ae.source_host → site), same as every other
  // alert_events read (see the mitre-coverage / recent-unacked routes above).
  const sf = getAlertSiteFilter(req.rbac, 1, 'ae');
  const [unacked, total24h, recent] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM alert_events ae WHERE ae.acknowledged = FALSE ${sf.clause}`, sf.params),
    pool.query(`SELECT COUNT(*) AS count FROM alert_events ae WHERE ae.fired_at > NOW() - make_interval(hours => 24) ${sf.clause}`, sf.params),
    pool.query(`SELECT ae.fired_at, ar.name AS rule_name FROM alert_events ae LEFT JOIN alert_rules ar ON ar.id = ae.rule_id WHERE ae.acknowledged = FALSE ${sf.clause} ORDER BY ae.fired_at DESC LIMIT 3`, sf.params),
  ]);
  res.json({ unacknowledged: parseInt(unacked.rows[0].count), total_24h: parseInt(total24h.rows[0].count), recent: recent.rows });
}));

// Lightweight count for the header notifications bell badge
app.get('/api/alerts/unacked-count', asyncHandler(async (req, res) => {
  const sf = getAlertSiteFilter(req.rbac, 1, 'ae');
  const { rows } = await pool.query(`SELECT COUNT(*) AS count FROM alert_events ae WHERE ae.acknowledged = FALSE ${sf.clause}`, sf.params);
  res.json({ count: parseInt(rows[0].count) });
}));

// Reads syslog_fortinet_field_rollup WHERE dimension='service' (scripts/
// schema.sql "PHASE 4 HOURLY ROLLUP TABLES") instead of scanning raw
// syslog_entries — this dashboard widget was structurally identical to
// several already-rollup-backed ones (vendor='fortinet' matches ~100% of
// rows in this deployment) but was missed by the earlier rollup passes.
// getRollupSiteFilter (permissive), not getStatsSiteFilter — same
// intentional widening every rollup migration makes; the two are already
// equivalent in shape/params, this just points at the rollup's own
// snapshotted site_id column instead of a live known_hosts join.
app.get('/api/stats/top-services', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const { rows } = await pool.query(`
    SELECT value AS service, SUM(log_count)::bigint AS count
    FROM syslog_fortinet_field_rollup
    WHERE dimension = 'service'
      AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sf.clause}
    GROUP BY value
    ORDER BY count DESC LIMIT 8
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

// Reads syslog_fortinet_field_rollup WHERE dimension='action' — see
// top-services above for the rollup table and rationale. The rollup stores
// 'unknown' for a null action (matching the OLD live query's SELECT-side
// COALESCE), but the old query's WHERE excluded nulls entirely before that
// COALESCE could ever apply — so 'unknown' never actually appeared in past
// output. Excluding it here preserves that same behavior exactly.
app.get('/api/stats/firewall-actions', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const { rows } = await pool.query(`
    SELECT value AS action, SUM(log_count)::bigint AS count
    FROM syslog_fortinet_field_rollup
    WHERE dimension = 'action' AND value != 'unknown'
      AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sf.clause}
    GROUP BY value
    ORDER BY count DESC LIMIT 10
  `, [hours, ...sf.params]);
  res.json({ data: rows });
}));

// ── STORAGE STATS ────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 ** 3)   return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

// Global DB/table size + retention stats. Not site-scopable (a single physical
// database, not a per-site metric), so there is no getStatsSiteFilter call
// here by design. Relies on the proxy-level fix (frontend/src/proxy.ts) to
// require SOME authenticated session before this handler is ever reached —
// matches the rest of the /api/stats/* dashboard tiles, which are readable by
// any logged-in role, not admin-restricted (this powers StorageWidget.tsx on
// the general dashboard, not an admin-only page).
app.get('/api/stats/storage', asyncHandler(async (req, res) => {
  // Perf pass (2026-07, Phase 3): this endpoint had no caching at all, unlike
  // every other stat endpoint in this file — added the same getCached wrapper,
  // 60s TTL (matches /api/stats/forecast's TTL; these are slow-changing,
  // whole-database-scale numbers, not per-request-sensitive). Not RBAC-scoped
  // (see comment above this handler), so a single global cache key is correct.
  const data = await getCached('storage-stats', 60000, async () => {
  const [sizes, growth, oldest, retention] = await Promise.all([
    // table_size must SUM the partition tree: syslog_entries is a PARTITIONED parent
    // (Phase 3), so pg_total_relation_size() on the parent alone returns 0 bytes — the
    // rows live in the daily child partitions (+ syslog_entries_legacy). pg_partition_tree
    // includes the parent and every partition; GREATEST falls back to the plain size if
    // the table is somehow not partitioned (returns no tree rows -> NULL -> 0).
    // total_rows uses pg_class.reltuples (planner statistics, refreshed by
    // autovacuum/ANALYZE) summed across the partition tree, NOT an exact
    // COUNT(*) — an exact count over the full multi-GB partitioned table took
    // ~5s live for a number that's purely informational display on a widget
    // (never used for filtering/pagination), so an approximate count (same
    // trade-off Postgres's own \dt+ and pg_stat_user_tables use) is the right
    // call here. rows_24h/rows_7d stay exact — those are bounded, cheap scans
    // via the received_at index on only the last 1-7 days of partitions.
    //
    // Perf pass (2026-07, Phase 3): GREATEST(pg_total_relation_size(...)) used to
    // be written out TWICE in this query (once for the pretty table_size, again
    // for the raw table_size_bytes) — Postgres does NOT common-subexpression-
    // eliminate STABLE functions across separate call sites in the same SQL
    // text, so each pg_total_relation_size() call (real filesystem stat() calls
    // per relation, ×37 partitions) was paid twice, live-measured at 2.4-4.0s.
    // `WITH sz AS MATERIALIZED` forces single evaluation regardless of how many
    // times `sz.bytes` is referenced below.
    pool.query(`
      WITH sz AS MATERIALIZED (
        SELECT GREATEST(
          pg_total_relation_size('syslog_entries'),
          COALESCE((SELECT SUM(pg_total_relation_size(relid)) FROM pg_partition_tree('syslog_entries')), 0)
        ) AS bytes
      )
      SELECT
        pg_size_pretty(pg_database_size('logvault')) AS db_size,
        pg_database_size('logvault') AS db_size_bytes,
        pg_size_pretty(sz.bytes) AS table_size,
        sz.bytes AS table_size_bytes,
        (SELECT COALESCE(SUM(c.reltuples), 0)::bigint FROM pg_partition_tree('syslog_entries') pt JOIN pg_class c ON c.oid = pt.relid) AS total_rows,
        (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => 24)) AS rows_24h,
        (SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - make_interval(days => 7)) AS rows_7d
      FROM sz
    `),
    // Reads syslog_stats_rollup (Phase 1) instead of raw syslog_entries — legitimate
    // work either way (not a bug, ~920-1057ms live scanning ~2M rows via index-only
    // scans across 7 partitions), but the rollup already answers this exactly and
    // trivially. No RBAC filter here (matches this endpoint's existing not-site-
    // scopable design — see the comment above this handler).
    pool.query(`SELECT DATE_TRUNC('day', hour_bucket) AS day, SUM(log_count) AS log_count FROM syslog_stats_rollup WHERE hour_bucket > NOW() - make_interval(days => 7) GROUP BY day ORDER BY day`),
    pool.query(`SELECT MIN(received_at) AS oldest_log FROM syslog_entries`),
    pool.query(`SELECT EXTRACT(DAY FROM (NOW() - MIN(received_at))) AS days_stored FROM syslog_entries`),
  ]);
  const s = sizes.rows[0];
  const avgPerDay = s.rows_7d > 0 ? Math.round(parseInt(s.table_size_bytes) / Math.max(parseFloat(retention.rows[0]?.days_stored || 1), 1)) : 0;
  return { db_size: s.db_size, db_size_bytes: parseInt(s.db_size_bytes), table_size: s.table_size, table_size_bytes: parseInt(s.table_size_bytes), total_rows: parseInt(s.total_rows), rows_24h: parseInt(s.rows_24h), rows_7d: parseInt(s.rows_7d), oldest_log: oldest.rows[0]?.oldest_log, days_stored: parseFloat(retention.rows[0]?.days_stored || 0).toFixed(1), avg_bytes_per_day: avgPerDay, avg_size_per_day: avgPerDay > 0 ? formatBytes(avgPerDay) : 'N/A', daily_breakdown: growth.rows };
  });
  res.json(data);
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

  // Free-text search. All 5 branches are now indexed, so the planner can
  // build a genuine BitmapOr across the whole OR instead of abandoning every
  // index and sequential-scanning (measured up to 94.5s for a common term at
  // 30d before the 3 new trigram indexes below existed). CORRECTION (perf
  // pass, 2026-07, Phase 4 hotfix): an EARLIER version of this same pass
  // dropped the to_tsvector @@ plainto_tsquery branch entirely, reasoning
  // that ILIKE '%term%' was a strict superset since it catches every literal
  // substring match tsvector does. That reasoning missed English STEMMING —
  // to_tsvector folds 'connecting'/'connection'/'connected'/'connect' to the
  // same lexeme, so a search for "connecting" matches all four via tsvector
  // but ONLY the literal substring "connecting" via ILIKE. Verified live: over
  // 1 MILLION rows in a single 7-day window (mostly "Connection Failed"
  // traffic logs) would have silently stopped matching that one search term.
  // Restored. idx_syslog_message (the existing tsvector GIN index) plus the
  // 3 new structured_data trigram indexes below (idx_syslog_user_trgm/
  // srccountry_trgm/service_trgm) mean all 5 branches are indexed now, so
  // restoring tsvector does NOT reintroduce the original all-branches-must-
  // be-indexed-or-none-are seq-scan problem. Do not drop this branch again
  // without a live stemming-equivalence check across several real search
  // terms, not just one or two — "failed"/"blocked" happened to have zero
  // stemming variants in this data, "connecting" did not.
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

  const dataParams = [...params, limit, offset];
  const countParams = params;
  const conditionsSql = conditions.join(' AND ');

  // Count query (perf pass, 2026-07). A free-text `q` search can't use any
  // index for an exact COUNT(*) the same way an indexed-only filter can —
  // measured up to 94.5s for a common term at 30d, run on EVERY search. For
  // `q` searches, cap the count at 5,000 via a LIMIT-bounded subquery:
  // Postgres stops scanning the moment it finds 5,000 matches, so a common
  // term now returns in well under a second instead of scanning the whole
  // table to find an exact total nobody reads past "Showing 100 of Y" for.
  // `total_is_capped` tells the frontend to render "5,000+" instead of an
  // exact number when the cap is hit. Filter-only searches (no `q`, all
  // branches indexed) keep an exact COUNT(*) — already fast (~121ms even
  // unfiltered) and worth keeping precise. Both queries run in parallel with
  // the data query (previously sequential — free ~2x wall-time cut on
  // whatever count cost remains).
  const COUNT_CAP = 5000;
  const countSql = q
    ? `SELECT COUNT(*) AS total FROM (SELECT 1 FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip WHERE ${conditionsSql} LIMIT ${COUNT_CAP}) capped`
    : `SELECT COUNT(*) AS total FROM syslog_entries se LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip WHERE ${conditionsSql}`;

  const [{ rows }, countRes] = await Promise.all([
    pool.query(`
      SELECT se.id, se.received_at, se.log_timestamp, se.source_ip::TEXT,
        COALESCE(kh.hostname, se.source_host) AS source_host,
        se.facility_label, se.severity, se.severity_label, se.vendor,
        se.program, se.message, se.structured_data, se.is_parsed,
        se.category, se.risk_score
      FROM syslog_entries se
      LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
      WHERE ${conditionsSql}
      ORDER BY se.received_at DESC
      LIMIT $${p} OFFSET $${p + 1}
    `, dataParams),
    pool.query(countSql, countParams),
  ]);

  const total = parseInt(countRes.rows[0].total);
  res.json({ total, total_is_capped: !!q && total >= COUNT_CAP, page, limit, data: rows });
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

app.get('/api/alerts/rules', requireAdmin, asyncHandler(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM alert_rules ORDER BY id');
  res.json({ data: rows });
}));

// Lightweight alert-rule list for per-rule email configuration in Settings.
app.get('/api/alert-rules', requireAdmin, asyncHandler(async (req, res) => {
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

  // Free-text search. All 5 branches are now indexed, so the planner can
  // build a genuine BitmapOr across the whole OR instead of abandoning every
  // index and sequential-scanning (measured up to 94.5s for a common term at
  // 30d before the 3 new trigram indexes below existed). CORRECTION (perf
  // pass, 2026-07, Phase 4 hotfix): an EARLIER version of this same pass
  // dropped the to_tsvector @@ plainto_tsquery branch entirely, reasoning
  // that ILIKE '%term%' was a strict superset since it catches every literal
  // substring match tsvector does. That reasoning missed English STEMMING —
  // to_tsvector folds 'connecting'/'connection'/'connected'/'connect' to the
  // same lexeme, so a search for "connecting" matches all four via tsvector
  // but ONLY the literal substring "connecting" via ILIKE. Verified live: over
  // 1 MILLION rows in a single 7-day window (mostly "Connection Failed"
  // traffic logs) would have silently stopped matching that one search term.
  // Restored. idx_syslog_message (the existing tsvector GIN index) plus the
  // 3 new structured_data trigram indexes below (idx_syslog_user_trgm/
  // srccountry_trgm/service_trgm) mean all 5 branches are indexed now, so
  // restoring tsvector does NOT reintroduce the original all-branches-must-
  // be-indexed-or-none-are seq-scan problem. Do not drop this branch again
  // without a live stemming-equivalence check across several real search
  // terms, not just one or two — "failed"/"blocked" happened to have zero
  // stemming variants in this data, "connecting" did not.
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

// ── GLOBAL SEARCH ────────────────────────────────────────────
// Backs the header search box, which until now was a decorative input wired to
// nothing at all. Returns a small grouped preview across hosts, alerts and logs;
// the UI links out to Log Explorer for the full, filterable result set.
//
// ⛔ PERFORMANCE — this runs on every (debounced) keystroke against a 10.5M-row,
// 43GB partitioned syslog_entries, so the log branch is deliberately bounded on
// BOTH axes: a 24h window and LIMIT 5. Measured live (EXPLAIN ANALYZE):
//   term '10.248' 2.1ms · common term 0.6ms · NO-MATCH term 19.9ms (worst case,
//   since a miss must scan the window to prove it). Removing either bound puts
//   this back in the territory of the 94.5s/30d scan documented on /api/logs.
// Keep the same 5-branch predicate /api/logs uses so a preview hit and the
// Explorer's full search agree — including the tsvector branch, which catches
// English stemming that ILIKE alone misses (see the long note on /api/logs).
app.get('/api/search', asyncHandler(async (req, res) => {
  const term = String(req.query.q || '').trim();
  // 1 character matches almost everything; make the client's debounce cheap to
  // get wrong by refusing to scan at all below 2.
  if (term.length < 2) return res.json({ hosts: [], alerts: [], logs: [], truncated: false });

  const rbac = req.rbac;
  const LOG_HOURS = 24;

  // known_hosts carries site_id directly — same shape as GET /api/hosts.
  let hostWhere = '';
  const hostParams = [term];
  if (rbac && rbac.allowedSiteIds !== null && rbac.allowedSiteIds !== undefined) {
    if (rbac.allowedSiteIds.length === 0) hostWhere = 'AND 1=0';
    else { hostParams.push(rbac.allowedSiteIds); hostWhere = `AND site_id = ANY($${hostParams.length}::int[])`; }
  }

  const alertSf = getAlertSiteFilter(rbac, 2, 'ae');
  const logSf   = getSiteFilter(rbac, 3, 'se');

  const [hosts, alerts, logs] = await Promise.all([
    pool.query(`
      SELECT ip_address::TEXT AS ip_address, hostname, vendor, site_name,
             country_name, is_known_bad
        FROM known_hosts
       WHERE (hostname ILIKE '%'||$1||'%' OR host(ip_address) ILIKE '%'||$1||'%'
              OR description ILIKE '%'||$1||'%')
         ${hostWhere}
       ORDER BY is_known_bad DESC NULLS LAST, last_seen DESC NULLS LAST
       LIMIT 8`, hostParams),

    pool.query(`
      SELECT ae.id, ae.fired_at, ae.source_host, ae.sample_message,
             ae.acknowledged, r.name AS rule_name
        FROM alert_events ae
        LEFT JOIN alert_rules r ON r.id = ae.rule_id
       WHERE (ae.sample_message ILIKE '%'||$1||'%' OR ae.source_host ILIKE '%'||$1||'%'
              OR r.name ILIKE '%'||$1||'%')
         ${alertSf.clause}
       ORDER BY ae.fired_at DESC
       LIMIT 8`, [term, ...alertSf.params]),

    pool.query(`
      SELECT se.id, se.received_at, se.source_host, se.vendor, se.severity,
             left(se.message, 160) AS message
        FROM syslog_entries se
       WHERE se.received_at > NOW() - make_interval(hours => $2)
         AND (to_tsvector('english', se.message) @@ plainto_tsquery('english', $1)
              OR se.message ILIKE '%'||$1||'%'
              OR se.structured_data->>'user' ILIKE '%'||$1||'%'
              OR se.structured_data->>'srccountry' ILIKE '%'||$1||'%'
              OR se.structured_data->>'service' ILIKE '%'||$1||'%')
         ${logSf.clause}
       ORDER BY se.received_at DESC
       LIMIT 5`, [term, LOG_HOURS, ...logSf.params]),
  ]);

  res.json({
    hosts: hosts.rows,
    alerts: alerts.rows,
    logs: logs.rows,
    log_window_hours: LOG_HOURS,
    // The log preview is capped at 5 of a 24h window; the UI uses this to offer
    // "see all in Log Explorer" rather than implying these are all the matches.
    truncated: logs.rows.length === 5,
  });
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
// Reads syslog_known_bad_hit_rollup (scripts/schema.sql "PHASE 3 HOURLY
// ROLLUP TABLES") instead of a correlated per-known_hosts-row subquery — the
// old shape re-scanned syslog_entries ONCE PER matching host (O(known_bad_
// hosts × matching rows)), measured at ~130 SECONDS live, and was ALSO
// starving the API's 10-connection pool long enough to make unrelated
// widgets (e.g. Riskiest Entities) look slow purely from queueing behind it.
// See CLAUDE.md's Phase 3 write-up.
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

  // Rollup site filter for the hit-count join (site_id already resolved at
  // rollup-build time — see getRollupSiteFilter's doc comment in api/rbac.js).
  const sf = getRollupSiteFilter(rbac, p);
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
      COALESCE(hits.total_hits, 0) AS total_hits
    FROM known_hosts kh
    LEFT JOIN (
      SELECT ip_address, SUM(hit_count) AS total_hits
      FROM syslog_known_bad_hit_rollup
      WHERE hour_bucket >= date_trunc('hour', NOW() - INTERVAL '24 hours')
      ${sf.clause}
      GROUP BY ip_address
    ) hits ON hits.ip_address = host(kh.ip_address)
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
  // Reads syslog_device_status_rollup (scripts/schema.sql "PHASE 4 HOURLY
  // ROLLUP TABLES") instead of scanning raw syslog_entries. This was a
  // documented-but-unbuilt gap since the Phase 3 rollup pass: the 6-column
  // GROUP BY + 4 overlapping COUNT(*) FILTER clauses had to touch every row
  // in the window regardless of indexing (cost scales with rows read, not
  // anything an index can prune) — measured live at 2.3s (24h) up to 23.4s
  // (7d), and it dominated the whole Network Health tab (one shared spinner
  // over all 8 calls on that page, 7 of which are already sub-400ms).
  // getRollupSiteFilter (permissive), not the strict getSiteFilter this used
  // before — same intentional widening every other rollup migration makes.
  // kh.hostname/vendor/description enrichment stays a LIVE join at read
  // time, same as every other rollup here.
  //
  // Trade-off (same shape as top-talkers'/top-destinations' MAX(hour_bucket)
  // last_seen note): logs_24h/critical_24h/error_24h are summed over HOUR
  // BUCKETS, not an exact rolling 24h window (±59 min edge effect, ~4% —
  // acceptable for a live-refreshing status table over a 24h span).
  //
  // CORRECTION (Phase 4 hotfix): logs_1h originally used the SAME hour-bucket
  // approach ("current hour bucket" instead of "last 60 minutes"), but on a
  // 1-HOUR window that ±59-minute edge effect is not a small percentage, it's
  // the WHOLE window — right after every hour rolls over, logs_1h read near-
  // zero and climbed back up over the next 60 minutes (verified live: as low
  // as a 91% undercount 5 minutes past the hour). On a device health/liveness
  // page that reads as devices going silent every hour on the hour. Fixed by
  // keeping logs_1h on a genuine live rolling-window subquery instead — a
  // bare 1-hour scan is cheap even on raw syslog_entries (idx_syslog_received_
  // source's received_at-DESC-leading shape serves it directly), unlike the
  // original 6-column/4-FILTER aggregation this whole rollup was built to
  // eliminate. Do not fold logs_1h back into the hour-bucket SUM approach.
  const hours = safeHours(req.query.hours);
  const sf = getRollupSiteFilter(req.rbac, 2);
  const cacheKey = `device-status:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    const { rows } = await pool.query(`
      WITH live_1h AS (
        SELECT host(se.source_ip) AS source_ip, COUNT(*) AS logs_1h
        FROM syslog_entries se
        WHERE se.received_at > NOW() - INTERVAL '1 hour'
        GROUP BY host(se.source_ip)
      )
      SELECT
        COALESCE(kh.hostname, agg.source_host, agg.source_ip) AS host,
        agg.source_ip AS source_ip,
        kh.vendor AS known_vendor, agg.vendor, kh.description,
        agg.last_seen,
        COALESCE(live_1h.logs_1h, 0)   AS logs_1h,
        COALESCE(agg.logs_24h, 0)      AS logs_24h,
        COALESCE(agg.critical_24h, 0)  AS critical_24h,
        COALESCE(agg.error_24h, 0)     AS error_24h,
        EXTRACT(EPOCH FROM (NOW() - agg.last_seen))/60 AS minutes_since_last_log
      FROM (
        SELECT source_ip,
          MAX(source_host) AS source_host, MAX(vendor) AS vendor, MAX(last_seen) AS last_seen,
          SUM(log_count)      FILTER (WHERE hour_bucket >= date_trunc('hour', NOW() - interval '24 hours')) AS logs_24h,
          SUM(critical_count) FILTER (WHERE hour_bucket >= date_trunc('hour', NOW() - interval '24 hours')) AS critical_24h,
          SUM(error_count)    FILTER (WHERE hour_bucket >= date_trunc('hour', NOW() - interval '24 hours')) AS error_24h
        FROM syslog_device_status_rollup
        WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
        ${sf.clause}
        GROUP BY source_ip
      ) agg
      LEFT JOIN known_hosts kh ON host(kh.ip_address) = agg.source_ip
      LEFT JOIN live_1h ON live_1h.source_ip = agg.source_ip
      ORDER BY agg.last_seen DESC
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
      // message ILIKE fallback removed (perf pass, 2026-07 Phase 3): a live
      // 30-day recall check confirmed it catches zero rows beyond what
      // subcategory='config_change' already covers, while forcing an
      // expensive BitmapOr across the message-trigram index on every
      // partition — same verified-zero-extra-recall pattern already applied
      // to /api/security/summary. Do not re-add without fresh evidence.
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory'='config_change' ${sf.clause}`, [hours, ...sf.params]),
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
  // firewall_denies/vpn_events/ips_events read syslog_fortinet_field_rollup
  // (scripts/schema.sql "PHASE 4 HOURLY ROLLUP TABLES") instead of scanning
  // raw syslog_entries — vendor='fortinet' matches ~100% of rows in this
  // single-vendor deployment, the same no-selectivity shape Phase 2's
  // top-security-events already hit (7-92s live, worse at wider ranges).
  // getRollupSiteFilter, not getSiteFilter, since site_id is already resolved
  // on the rollup row (no known_hosts join needed at read time) — same
  // pattern as every other rollup-backed endpoint.
  //
  // Correctness fix riding along with this: firewall_denies used to filter
  // structured_data->>'action' = 'deny', a value this deployment's Fortinet
  // parser never actually emits (confirmed live: the real value is 'blocked'
  // — 546 rows/24h — 'deny' matches 0 rows, always). This card has silently
  // shown "0" since it shipped. Now correctly reads dimension='action',
  // value='blocked'.
  //
  // vpn_events also drops the redundant `OR message ILIKE '%vpn%'` — a live
  // check (same technique as the already-fixed auth-failure/brute-force
  // ILIKE removals) confirmed structured_data->>'subtype'='vpn' alone
  // catches every row the ILIKE branch did, at a fraction of the cost.
  const sfRollupDenies = getRollupSiteFilter(req.rbac, 2);
  const sfRollupVpn    = getRollupSiteFilter(req.rbac, 2);
  const sfRollupIps     = getRollupSiteFilter(req.rbac, 2);
  const [authFail, denies, vpn, ips, afterHours, bruteSuccess, vpnLoginFail, knownBadFail] = await Promise.all([
    // Real auth failure = normalized subcategory (vendor-agnostic). The old broad
    // %fail%/%error% match counted SSL teardown noise (ssl-exit-error/ssl-alert/
    // negotiate) as login failures — dropped. The message ILIKE fallback that used
    // to sit alongside the subcategory check was ALSO dropped (perf pass, 2026-07):
    // a live 30-day production check confirmed it caught zero rows beyond what
    // subcategory already covers (every vendor parser has reliably populated
    // structured_data.subcategory since 2.9.0), while costing ~60x more query time
    // (forces a 3-way BitmapOr across the subcategory + message-trigram indexes on
    // every one of the 35 partitions — ~350ms of planning alone). Do not re-add it
    // without fresh evidence it's catching something real.
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory' IN ('login_failed','auth_failed') ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'action' AND value = 'blocked' AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1)) ${sfRollupDenies.clause}`, [hours, ...sfRollupDenies.params]),
    pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'subtype' AND value = 'vpn' AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1)) ${sfRollupVpn.clause}`, [hours, ...sfRollupVpn.params]),
    pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'type' AND value = 'utm' AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1)) ${sfRollupIps.clause}`, [hours, ...sfRollupIps.params]),
    // Same message-ILIKE-fallback removal as authFail above (zero extra recall,
    // verified over 30 days) applies here too.
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19 ${sf.clause}`, [hours, ...sf.params]),
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
        AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
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
  // sender), vendor-agnostically. Detection uses ONLY the normalized subcategory — the
  // old per-vendor broad %failed%+%login% / %fail% matching wrongly counted SSL
  // teardown noise, and a later "tight" message ILIKE fallback (removed perf pass,
  // 2026-07) was proven over a live 30-day check to catch zero rows beyond what
  // subcategory alone already covers, while costing ~60x more query time. known_hosts
  // join uses host(ip_address) (INET /32) with a shape-guarded text key, mirroring the
  // top-blocked/top-failures joins.
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
      AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed','brute_force')
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
  // vendor-agnostically, via the normalized subcategory alone — the message ILIKE
  // fallbacks that used to sit alongside both CTEs' subcategory checks were removed
  // (perf pass, 2026-07): a live 30-day production check confirmed both patterns
  // (login_failed/auth_failed and login_success) caught zero rows beyond what
  // subcategory already covers, while forcing an expensive 3-way BitmapOr plan on
  // every partition. known_hosts join uses host(ip_address) on the shape-guarded
  // real-source key.
  const { rows } = await pool.query(`
    WITH failures AS (
      SELECT COALESCE(structured_data->>'srcip', source_ip::text) AS source_ip,
        MIN(received_at) AS first_fail, MAX(received_at) AS last_fail, COUNT(*) AS fail_count,
        COUNT(DISTINCT structured_data->>'user') AS distinct_users
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1)
        AND structured_data->>'subcategory' IN ('login_failed','auth_failed')
      ${sf.clause}
      GROUP BY COALESCE(structured_data->>'srcip', source_ip::text)
    ),
    successes AS (
      SELECT COALESCE(structured_data->>'srcip', source_ip::text) AS source_ip,
        MIN(received_at) AS success_time, message AS success_msg
      FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $2)
        AND structured_data->>'subcategory' = 'login_success'
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
  // Correctness fix (perf pass, 2026-07): the filter was action='deny', a
  // value this deployment's Fortinet parser never actually emits — confirmed
  // live, the real value is 'blocked' (546 rows/24h vs 0 for 'deny', always).
  // This page has silently shown nothing since it shipped, not because there
  // was nothing to show. idx_syslog_action (scripts/schema.sql) now backs
  // this equality filter, same pattern as idx_syslog_subcategory.
  const [bySrc, byDst, bySvc] = await Promise.all([
    pool.query(`SELECT structured_data->>'srcip' AS src_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'dstip') FILTER (WHERE structured_data->>'dstip' IS NOT NULL) AS destinations FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='blocked' AND structured_data->>'srcip' IS NOT NULL ${sf.clause} GROUP BY structured_data->>'srcip' ORDER BY deny_count DESC LIMIT 15`, [hours, ...sf.params]),
    pool.query(`SELECT structured_data->>'dstip' AS dst_ip, COUNT(*) AS deny_count, ARRAY_AGG(DISTINCT structured_data->>'srcip') FILTER (WHERE structured_data->>'srcip' IS NOT NULL) AS sources FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='blocked' AND structured_data->>'dstip' IS NOT NULL ${sf.clause} GROUP BY structured_data->>'dstip' ORDER BY deny_count DESC LIMIT 15`, [hours, ...sf.params]),
    pool.query(`SELECT COALESCE(structured_data->>'service','unknown') AS service, COUNT(*) AS deny_count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND vendor='fortinet' AND structured_data->>'action'='blocked' ${sf.clause} GROUP BY structured_data->>'service' ORDER BY deny_count DESC LIMIT 10`, [hours, ...sf.params]),
  ]);
  res.json({ by_source: bySrc.rows, by_destination: byDst.rows, by_service: bySvc.rows });
}));

app.get('/api/security/vpn-events', asyncHandler(async (req, res) => {
  const hours = safeHours(req.query.hours);
  const sf = getSiteFilter(req.rbac, 2, 'syslog_entries');
  // event_type is driven by the normalized subcategory — NOT the broad %fail%/%error%
  // match, which mislabelled SSL teardown noise (ssl-exit-error/ssl-alert) as failures.
  // vpn_src_ip is the REAL remote client (structured_data.srcip), not the firewall.
  // The `OR message ILIKE '%ssl vpn%'/'%ipsec%'/'%vpn%'` fallback that used to sit
  // alongside subtype='vpn' was removed (perf pass, 2026-07): a live check confirmed
  // it caught zero rows beyond what subtype='vpn' already covers, while forcing a
  // sequential scan (no index can serve a leading-wildcard ILIKE) — 6.7-27x slower
  // depending on window. Same verified-zero-extra-recall pattern already applied to
  // /api/security/summary and /api/security/auth-failures. Do not re-add without
  // fresh evidence it's catching something real.
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
      AND structured_data->>'subtype'='vpn'
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
  // Detection uses ONLY the normalized subcategory — the message ILIKE fallback that used
  // to sit alongside it was removed (perf pass, 2026-07); a live 30-day check confirmed it
  // caught zero rows beyond what subcategory already covers, at ~60x the query cost.
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
      AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
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

  // 7-day syslog activity summary for this entity. Reads
  // syslog_entity_activity_rollup (scripts/schema.sql "PHASE 4 HOURLY ROLLUP
  // TABLES") instead of scanning raw syslog_entries — this was the single
  // slowest thing on the Intelligence tab: an unindexed structured_data->>
  // 'user'/'srcip' equality filter over a 7-day raw window, measured 20-23s
  // PER QUERY (this endpoint runs two of them, sequentially — ~40-50s per
  // entity-panel click). entity_value normalization matches the rollup's own
  // build query exactly (see the schema.sql comment on that table) — `value`
  // here is already in that form, since it's whatever entity_risk/
  // anomaly_events stored via the SAME normalization in
  // collector/analytics/uebaRollup.js. getRollupSiteFilter (permissive), not
  // the strict getSiteFilter this used before — same intentional widening
  // every other rollup migration makes.
  const sf = getRollupSiteFilter(req.rbac, 3);

  const summaryRes = await pool.query(`
    SELECT
      COALESCE(SUM(log_count), 0)::bigint AS total,
      COALESCE(SUM(failed_login_count), 0)::bigint AS failed_logins,
      MAX(last_seen) AS last_seen
    FROM syslog_entity_activity_rollup
    WHERE entity_type = $1 AND entity_value = $2
      AND hour_bucket >= date_trunc('hour', NOW() - interval '7 days')
    ${sf.clause}
  `, [type, value, ...sf.params]);

  const byCategoryRes = await pool.query(`
    SELECT COALESCE(category, 'uncategorized') AS category, SUM(log_count)::bigint AS count
    FROM syslog_entity_activity_rollup
    WHERE entity_type = $1 AND entity_value = $2
      AND hour_bucket >= date_trunc('hour', NOW() - interval '7 days')
    ${sf.clause}
    GROUP BY COALESCE(category, 'uncategorized')
    ORDER BY count DESC
  `, [type, value, ...sf.params]);

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
  const cacheKey = `heatmap:${metric}:${hours}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    if (metric === 'all') {
      // Reads syslog_stats_rollup (scripts/schema.sql "HOURLY ROLLUP TABLES")
      // instead of scanning raw syslog_entries — there's no filter beyond the
      // time window, so every row in range had to be touched just to bucket-
      // count it. Measured 341ms (24h) -> 8.45s (30d) live; the rollup is
      // already hour-bucketed at exactly the granularity this needs, so it's
      // a direct SUM(log_count) instead of a fresh COUNT(*) over raw rows.
      // getRollupSiteFilter (permissive: NULL site_id visible to everyone),
      // not the strict getSiteFilter this branch used before — same
      // intentional widening every other rollup migration makes (see
      // getStatsSiteFilter's doc comment for why the strict filter is wrong
      // for aggregate widgets like this one).
      const sf = getRollupSiteFilter(req.rbac, 2);
      const { rows } = await pool.query(`
        SELECT
          EXTRACT(DOW  FROM hour_bucket)::int AS dow,
          EXTRACT(HOUR FROM hour_bucket)::int AS hour,
          SUM(log_count)::bigint AS count
        FROM syslog_stats_rollup
        WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
        ${sf.clause}
        GROUP BY dow, hour
        ORDER BY dow, hour
      `, [hours, ...sf.params]);
      return { metric, hours, data: rows };
    }
    // metric='auth_failed' stays on raw syslog_entries — already fast
    // (pre-filtered on the indexed subcategory expression, confirmed live at
    // 213ms/168h) and no rollup dimension carries subcategory.
    const sf = getSiteFilter(req.rbac, 2, 'se');
    const { rows } = await pool.query(`
      SELECT
        EXTRACT(DOW  FROM se.received_at)::int AS dow,
        EXTRACT(HOUR FROM se.received_at)::int AS hour,
        COUNT(*)::bigint AS count
      FROM syslog_entries se
      WHERE se.received_at > NOW() - make_interval(hours => $1)
        AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
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
  // a/c read syslog_stats_rollup (Phase 1) — accurate for "today so far" too,
  // since every past hour of today was already finalized as it went from
  // "current" to "previous" hour in two consecutive 5-min recompute cycles.
  // d reads syslog_source_host_rollup (Phase 3, scripts/schema.sql "PHASE 3
  // HOURLY ROLLUP TABLES") — no existing rollup carried source_host (the
  // relay hostname), only srcip (the actor), so silent-device detection
  // needed a new table. All 3 sub-queries used to run SEQUENTIALLY on raw
  // syslog_entries (14-20s live, see CLAUDE.md's Phase 3 write-up); now
  // parallel reads of small pre-aggregated tables.
  const sfDaily  = getRollupSiteFilter(req.rbac, 2);
  const sfToday  = getRollupSiteFilter(req.rbac, 2);
  const sfSilent = getRollupSiteFilter(req.rbac, 2);
  const cacheKey = `forecast:${days}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    const [dailyRes, todayRes, silentRes] = await Promise.all([
      // a) Daily volume series over the requested window.
      pool.query(`
        SELECT date_trunc('day', hour_bucket) AS d, SUM(log_count)::bigint AS c
        FROM syslog_stats_rollup
        WHERE hour_bucket >= date_trunc('day', NOW() - make_interval(days => $1))
        ${sfDaily.clause}
        GROUP BY 1
        ORDER BY 1
      `, [days, ...sfDaily.params]),

      // c) Ingestion spike — today's count so far vs avg daily count.
      pool.query(`
        SELECT COALESCE(SUM(log_count), 0)::bigint AS c
        FROM syslog_stats_rollup
        WHERE hour_bucket >= date_trunc('day', NOW())
        ${sfToday.clause}
      `, sfToday.params),

      // d) Silent devices — source_hosts active in the prior week but silent in
      //    the last 24h. Same 8-day-window / >=50-prior / 0-recent thresholds as
      //    before, just at hour granularity (rollup's native precision) instead
      //    of exact timestamps — a boundary difference of at most ~1h either
      //    side, acceptable for this "silent" heuristic.
      pool.query(`
        SELECT
          source_host,
          MAX(source_ip) AS source_ip,
          COALESCE(SUM(log_count) FILTER (
            WHERE hour_bucket BETWEEN date_trunc('hour', NOW() - interval '8 days')
                                  AND date_trunc('hour', NOW() - interval '1 day')
          ), 0)::bigint AS prior_count,
          COALESCE(SUM(log_count) FILTER (
            WHERE hour_bucket >= date_trunc('hour', NOW() - interval '24 hours')
          ), 0)::bigint AS recent_count,
          MAX(hour_bucket) AS last_seen
        FROM syslog_source_host_rollup
        WHERE hour_bucket >= date_trunc('hour', NOW() - interval '8 days')
        ${sfSilent.clause}
        GROUP BY source_host
        HAVING COALESCE(SUM(log_count) FILTER (
                 WHERE hour_bucket BETWEEN date_trunc('hour', NOW() - interval '8 days')
                                       AND date_trunc('hour', NOW() - interval '1 day')
               ), 0) >= 50
           AND COALESCE(SUM(log_count) FILTER (
                 WHERE hour_bucket >= date_trunc('hour', NOW() - interval '24 hours')
               ), 0) = 0
        ORDER BY prior_count DESC
        LIMIT 20
      `, sfSilent.params),
    ]);

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
    const today = parseInt(todayRes.rows[0]?.c, 10) || 0;
    const avgDaily = n ? Math.round(meanY) : 0;
    const spike = avgDaily > 0 ? today > avgDaily * 1.5 : false;

    // d) Silent devices — source_hosts active in the prior week but silent in
    //    the last 24h (query itself now runs above, in the Promise.all).
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
// Reads syslog_distinct_value_rollup (scripts/schema.sql "PHASE 3 HOURLY
// ROLLUP TABLES") instead of raw syslog_entries. This was the worst offender
// found in the Phase 3 audit: one dimension alone measured 216+ SECONDS live
// — the 30-day baseline filter matches ~100% of every daily partition it
// touches (same "filter has no selectivity, no index can help" shape as
// Phase 2's top-security-events), and there's no expression index at all on
// the JSONB fields involved, so each of the 4 dimensions independently
// scanned ~20GB from disk. The anti-join now runs against a few thousand
// pre-aggregated (hour, value) rows per dimension instead. See CLAUDE.md's
// Phase 3 write-up.
app.get('/api/stats/whats-changed', asyncHandler(async (req, res) => {
  const days = safeInt(req.query.days, 1, 30);
  const cacheKey = `whats-changed:${days}:${rbacCacheKey(req.rbac)}`;
  const data = await getCached(cacheKey, 60000, async () => {
    // Each dimension: aggregate recent-window distinct values + counts, anti-joined
    // against the set of values seen in the 30 days BEFORE the recent window. The
    // RBAC site filter is applied to BOTH the recent (r) and baseline (b) scans so a
    // restricted user only ever compares within their own sites. Param order:
    // $1 = days (recent window), $2 = dimension, $3..$3+k = site params for r, then
    // again for b.
    function buildAntiJoin(dimension) {
      const sfR = getRollupSiteFilter(req.rbac, 3);
      const sfB = getRollupSiteFilter(req.rbac, 3 + sfR.params.length);
      // COUNT(*) OVER() = total distinct NEW values after the anti-join but before
      // LIMIT, so the UI can show an honest "+N more" / tile total beyond the top 15.
      const sql = `
        SELECT v AS value, cnt AS count, COUNT(*) OVER()::bigint AS total FROM (
          SELECT value AS v, SUM(log_count)::bigint AS cnt
          FROM syslog_distinct_value_rollup r
          WHERE r.dimension = $2
            AND r.hour_bucket >= date_trunc('hour', NOW() - make_interval(days => $1))
          ${sfR.clause}
          GROUP BY value
        ) recent
        WHERE NOT EXISTS (
          SELECT 1 FROM syslog_distinct_value_rollup b
          WHERE b.dimension = $2
            AND b.hour_bucket >= date_trunc('hour', NOW() - make_interval(days => $1) - interval '30 days')
            AND b.hour_bucket <  date_trunc('hour', NOW() - make_interval(days => $1))
            AND b.value = recent.v
          ${sfB.clause}
        )
        ORDER BY count DESC, value
        LIMIT 15
      `;
      const params = [days, dimension, ...sfR.params, ...sfB.params];
      return { sql, params };
    }

    const dims = {
      new_countries: buildAntiJoin('country'),
      new_users:     buildAntiJoin('user'),
      new_sources:   buildAntiJoin('source'),
      new_services:  buildAntiJoin('service'),
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
const { execSync, execFile } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);
const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
const path = require('path');

app.get('/api/stats/disk', asyncHandler(async (req, res) => {
  try {
    // Use PowerShell to get real disk info for C: drive.
    // execFileP, NOT execSync: this runs inside the API process, and execSync blocks the
    // WHOLE event loop until powershell.exe exits — every other in-flight request, plus
    // pg's connection callbacks and its connectionTimeoutMillis timer, stall for that
    // long. That is not theoretical: the identical pattern in DDIVault's collector
    // surfaced as bogus "Connection terminated due to connection timeout" errors from a
    // perfectly healthy database (fixed in ddivault 1.28.0). Never put sync I/O in a
    // request path. execFile also takes the script as ONE argument with no shell in
    // between, so the old cmd.exe -Command "..." quoting is no longer needed.
    const psScript =
      `$d = Get-PSDrive C; ` +
      `$used = $d.Used; $free = $d.Free; $total = $used + $free; ` +
      `Write-Output ($used.ToString() + ',' + $free.ToString() + ',' + $total.ToString())`;
    const { stdout } = await execFileP(
      'powershell.exe',
      ['-NonInteractive', '-Command', psScript],
      { encoding: 'utf8', timeout: 10000 }
    );
    const output = stdout.trim();
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
const fs = require('fs');
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

// Short git commit hash for origin/main, read over GIT TRANSPORT (git ls-remote)
// instead of GitHub's public web API. Git transport is not per-IP rate-limited,
// so this works from Thai Union's shared egress where api.github.com times out
// and raw.githubusercontent returns 429. Returns null on any failure.
async function remoteCommitHash() {
  try {
    const { stdout } = await execFileP('git', ['ls-remote', 'origin', 'main'], {
      cwd: appRoot, encoding: 'utf8', timeout: 10000, env: GIT_ENV,
    });
    const sha = stdout.trim().split(/\s+/)[0];
    return sha ? sha.slice(0, 7) : null;
  } catch {
    return null;
  }
}

// package.json version on origin/main, read over git transport. Does a network
// fetch, so only call this once the remote hash is known to differ from local.
// Falls back to the local version on any failure (display-only field).
async function remoteVersion(localVersion) {
  try {
    await execFileP('git', ['fetch', '--quiet', 'origin', 'main'], { cwd: appRoot, timeout: 20000, env: GIT_ENV });
    const { stdout } = await execFileP('git', ['show', 'FETCH_HEAD:package.json'], {
      cwd: appRoot, encoding: 'utf8', timeout: 10000, env: GIT_ENV,
    });
    return JSON.parse(stdout).version || localVersion;
  } catch {
    return localVersion;
  }
}

// Structured release notes keyed by version. The update-status endpoint surfaces
// these as a bullet list in the Settings UI — there is no CHANGELOG.md. When
// bumping the version, add a matching entry here with 3-5 bullets.
const releaseNotes = {
  '2.27.0': [
    'The search box at the top of the screen now works. It was previously connected to nothing at all — typing into it filled the box and did nothing else, with no results and no error, which is exactly how it appeared to anyone who tried it.',
    'Typing at least two characters now shows matching hosts, alerts and recent log entries grouped together, and clicking any result opens it in the right place: a host opens its traffic in Log Explorer, an alert opens the Alerts page, a log entry opens the full search. Pressing Enter goes straight to Log Explorer with your term applied.',
    'The log results shown in the box are a preview of the last 24 hours only, and are labelled as such. This is deliberate: the log store holds over ten million entries, and searching all of it on every keystroke would be slow for everyone. The "Search all logs" link at the bottom of the results runs the full, unrestricted search in Log Explorer where you can widen the time range and refine filters.',
    'Results respect your site access — you only see hosts, alerts and logs from sites assigned to you.',
  ],
  '2.26.6': [
    'The disk-space panel no longer stalls the rest of the application while it refreshes. Reading the drive figures runs a short Windows command, and LogVault was waiting for it in a way that stopped the server from doing anything else at the same time — roughly 0.85 seconds, measured, on every refresh. During that pause every other request from every other user simply waited, and background database work could be reported as timing out even though the database was healthy. The reading is now taken without holding everything else up; the figures shown are unchanged.',
  ],
  '2.26.5': [
    'Silenced a build-time warning that was written to the error log 399 times. LogVault has two dependency lockfiles — one for the API and collector, one for the web frontend — and the web framework could not tell which folder was the project root, so it guessed and warned every time. It is now told explicitly. No behaviour change; the log is just readable again.',
  ],
  '2.26.4': [
    'The collector now stops all of its scheduled work before closing its database connection when shutting down. Previously only one of its fourteen background jobs was stopped, so the rest could fire into a connection that had just been closed and log an error on the way out (172 of them). Nothing was lost — the work is repeated on the next run and the service was exiting anyway — but it filled the error log with noise that hid genuine shutdown problems.',
  ],
  '2.26.3': [
    'When an update check cannot reach the remote (offline, air-gapped, or a transient git failure), the Updates panel now still shows the version and commit this server is actually running. It previously dropped those fields on that path, so a check that failed for network reasons also blanked out information the server already knew locally. Matches what NetVault has always returned.',
  ],
  '2.26.2': [
    'Fixed drill-through from the Threat Map (and any view with its own time range) into Log Explorer: clicking a country now correctly carries the country name into the search box AND the time range you were viewing. Two bugs: Log Explorer ignored the incoming free-text "q" filter (it applied every other field but not the search term), and the "open in Explorer" handler always overrode the caller\'s time range with the global one — so clicking Germany at 30d landed on an empty 24h search. Both fixed; the drill now lands pre-filtered with results.',
  ],
  '2.26.1': [
    'Threat Map now draws the actual world continents behind the attack bubbles instead of just a coordinate grid — it was hard to read as a map with only two dots on a graticule. The landmass is a bundled, pre-generated world outline (Natural Earth 110m) rendered with the same projection as the bubbles, so coastlines and country bubbles line up exactly. Fully dependency-free (a static ~55 KB JSON, no runtime map library) and dark-mode safe.',
  ],
  '2.26.0': [
    'SIEM Phase 3+4: three new analyst surfaces added to the sidebar. Security Overview (SOC single-pane) composes the whole security picture — a deterministic, plain-language narrative digest (incidents, anomalies, riskiest entities, external threats, volume-vs-baseline — no AI/LLM, no email), severity breakdown, KPI totals, top source countries, riskiest entities, security signals, and an active-incidents list.',
    'Kill-chain timeline: clicking an active incident opens a modal that pulls the underlying log entries behind the fired alert and groups them into MITRE ATT&CK tactic phases (ordered along the kill chain) with the techniques involved.',
    'Entities page: a dedicated UEBA entity-profile explorer (device / user / source-IP) with a searchable list, per-entity risk score and explainable risk-factor breakdown, a 14-day activity trend, recent anomalies, and an events-by-category summary — the flagship version of what was previously only a dashboard widget + slide-in panel.',
    'Threat Map: a dependency-free world attack map plotting failed-auth/attack activity by source country (equirectangular SVG with bubbles sized by volume) alongside a ranked country list with period-over-period trend.',
    'All of the above is compute-on-read over existing tables/rollups via a new /api/soc/* module (overview, digest, killchain, entity-timeline) — no new database tables, schema, or installer changes; every query reuses the same site-scoping (RBAC) as the endpoints it composes.',
  ],
  '2.25.14': [
    'CRITICAL: the "kill any remaining node process" safety net (main flow AND rollback) only ever checked ports 3004/3005 (App/API) -- LogVault-Collector (514/1514, TCP+UDP) was never checked, even though sc.exe stop is asynchronous and this is the exact mechanism of the original production incident (the Collector kept running against a node_modules directory being renamed/restored underneath it). Both port lists now include 514/1514.',
    'Invoke-Rollback no longer proceeds to restore node_modules/.next and restart services when the source revert itself fails (missing pre-update commit, or a failed git reset) -- it now short-circuits and reports "MANUAL INTERVENTION REQUIRED" instead of risking the new broken code combined with the OLD dependencies.',
    'Fixed the rollback\'s own service-stop step, which only stopped a service sampled as exactly "RUNNING" (unlike the main flow, which already stops unconditionally) -- a crash-looping service could be skipped and left eligible for NSSM auto-restart while files were being restored underneath it.',
    'The pre-update snapshot step used to rename node_modules/.next with silent error suppression and an unconditional "Snapshotted" success message -- a failed rename (locked file, permissions) was invisible and poisoned any later rollback attempt. Now verified with Test-Path and routed through the same failure-handling as every other stage.',
    'Added a concurrency guard (a PID-stamped lock file, checked by both the script and the in-app update-trigger API) so a manual on-server run can no longer race an in-app-triggered update against the same files; the "Update Now" overlay now surfaces a clear error instead of silently colliding.',
    'The "Update Now" overlay used to declare success purely from a health-poll transition, which looks identical whether the update actually succeeded or silently rolled back to the old version. It now checks the real outcome and shows distinct states for a successful update, a failed-and-rolled-back update, and the more urgent "rollback also failed" case (no auto-reload).',
    'Aligned the rollback health-check timeout with the main flow\'s (60s, was 30s) -- rollback doesn\'t skip the slow part (service cold-start), so the shorter budget could misreport a genuinely healthy-but-slow rollback as failed.',
    'Smaller reliability fixes: the status file is now written atomically (temp file + rename) so a crash mid-write can\'t leave a corrupt JSON behind, and rollback now removes a .env.local that didn\'t exist before the update but was created during a failed attempt.',
  ],
  '2.25.13': [
    'Fixed a real production regression from the 2.25.12 fix (the one that made rollback snapshots actually survive git clean): TypeScript\'s build-time type-check only excludes the exact name "node_modules" by default, not the "node_modules.lastgood"/".next.lastgood" snapshot directories now sitting right next to it -- so once those snapshots could survive, the very next build tried to type-check next-auth\'s source code inside the OLD snapshot copy and failed on an import that only resolves from within its own original dependency tree. The two fixes were masking each other: before 2.25.12, the snapshot was always deleted before the build ran, so this was never hit. Snapshot directories are now explicitly excluded from the TypeScript check.',
  ],
  '2.25.12': [
    'Found via a full adversarial bug sweep of the resilience work (4 real issues, all fixed): the CRITICAL one -- git clean was deleting the rollback\'s own node_modules/.next backup snapshots on every single run, moments after creating them (verified by actually reproducing it against this repo\'s .gitignore), which meant the safety net added in 2.25.10/2.25.11 had never actually been able to restore anything. Fixed by excluding the backup naming pattern from the clean step.',
    'Two rollback status branches (a missing pre-update commit, and a missing root node_modules backup -- the exact directory that corrupted in the original incident) could let a rollback report full success even though it hadn\'t actually restored what it claimed to. Both now correctly mark the rollback as failed.',
    'The rollback\'s own service-stop step was weaker than the main update flow\'s: a flat sleep with no fallback for a slow-to-exit process, unlike the main flow\'s port-based force-kill safety net for the identical hazard. Now matches it.',
  ],
  '2.25.11': [
    'Fixed two real bugs in the resilience mechanism added in 2.25.10, found from a live production incident: (1) the post-start service-status check ran immediately after starting services and treated the normal, brief "STARTPENDING" state as a failure -- even when the health check passed right after, causing a working update to be wrongly rolled back (and the rollback\'s own identical check then made it report "rollback also failed" even though it had actually succeeded). Service status is now polled for up to 30s and is informational only; the health check alone decides success. (2) The rollback restored node_modules/.next BEFORE stopping the just-started services, mutating a live directory tree while the app was still running against it -- this is what actually corrupted node_modules down to a handful of packages in production (LogVault-Collector then crash-looped on a missing module) even though the restore itself reported success. The rollback now stops services first, matching the order the main update flow already used.',
  ],
  '2.25.10': [
    'Made the updater (Update-LogVault.ps1) resilient to a failed update instead of just reporting one -- it now snapshots the current commit, root node_modules, and the frontend build (.next + node_modules) before touching anything, and if any stage fails (git pull, either npm install, the frontend build, service start, a database schema migration, or a new mandatory post-start health check) it automatically reverts to the last known-good version, restarts all 3 services (Collector, API, App), and re-verifies health -- instead of leaving the app stopped with no recovery attempt, which is what every one of those failures did before.',
    'A failed schema migration now also triggers the same rollback (restores the previous working code + restarts services) instead of just leaving the app stopped -- the new code still isn\'t deployed against a database it failed to migrate, but the service comes back up on the last known-good version instead of staying down.',
    'Every update run (success or failure) now writes a structured result to logs/last-update-status.json -- what stage it reached, an error code, the error message, and whether it rolled back -- surfaced as a new in-app failure banner for admins (GET /api/system/last-update-status) so a failed update can\'t go unnoticed.',
    'The post-start health check, which used to be a best-effort probe that never blocked anything, is now a hard gate -- an update is no longer reported as successful unless the running version is actually confirmed serving traffic.',
  ],
  '2.25.9': [
    'Fixed a recurring version-drift bug: frontend/package.json (and its lockfile) had fallen 3 releases behind the root package.json again -- confirmed harmless (the app reads its displayed version only from the root package.json, per the 2.22.3 root-cause fix), and re-synced both files to the current version.',
    'Corrected 3 stale claims in the .ai-codex/ documentation index: the component-file count (was quoting 35, actually 36), DashboardWidgets.tsx\'s export count (was quoting "5 exports" while listing all 10 by name), and where the /sso route\'s handler actually lives (its own frontend/src/app/sso/page.tsx route file, not inline in another page.tsx).',
    'Reliability: the update script and the fresh-install suite installer now pass -v ON_ERROR_STOP=1 to psql when applying scripts/schema.sql, so a genuine SQL error in the schema is reported as a failure instead of being silently logged as success (schema.sql\'s existing idempotent IF NOT EXISTS-style statements are unaffected).',
  ],
  '2.25.8': [
    'Settings page redesign: every panel on the General and Email Alerts tabs was stretching to the full page width with mostly empty space around a handful of fields -- same fix already shipped in SpanVault. All panels now cap to a consistent form width, and the "How delivery works" info card correctly sticks below the header while the page scrolls.',
  ],
  '2.25.7': [
    'Settings > Email Alerts now has a short "How delivery works" panel next to the filters/delivery-mode section, explaining behavior that wasn\'t visible from the form alone -- including that Daily Digest mode isn\'t implemented yet (every alert still sends instantly) and that the cooldown timer resets on collector restart. Verified against the actual emailer code before writing it, not guessed.',
  ],
  '2.25.6': [
    'Consolidated severity/vendor/risk-score colors that had drifted into several independent per-file copies (some literally the same red as the critical-severity color) into two shared modules, so a badge, chip, or dot means the same color everywhere in the app. Purely cosmetic — a few colors that had quietly drifted apart now render as designed (e.g. Live Tail\'s error/warning distinction, and vendor colors on Top Talkers/Vendor Breakdown now match the rest of the app instead of a stale rainbow palette).',
  ],
  '2.25.5': [
    'Security: closed a gap where the cross-app diagnostic/dashboard read role could see the plaintext SMTP password and threat-intel API key stored in this app\'s settings. Those two values now live behind a filtered view that only exposes cosmetic settings (app name, colors, logo) -- any new setting added in the future is hidden from that role by default until someone deliberately decides it\'s safe to share.',
  ],
  '2.25.4': [
    'Fixed from an end-of-day bug sweep of the 2.25.2/2.25.3 Settings fixes: dropping the old width:100% left 3 standalone fields (DNS Server IP, alert cooldown, digest-send-hour) with no explicit width at all -- for the two dropdowns, the browser sizes a <select> to its currently-selected option\'s text, so the box could visibly change width as a different option was picked. Those three fields now keep a fixed width alongside their cap; the two fields inside the SMTP Host/Port and Username/Password rows (which rely on flex sizing, not a plain width) are unaffected and unchanged.',
  ],
  '2.25.3': [
    'Follow-up to 2.25.2\'s Settings page fix: capping the short fields\' own width (SMTP port, password, etc.) left a dead gap of empty space where the field used to stretch, because the surrounding layout was still forcing an equal-width column around it. The SMTP Host/Port and Username/Password rows now flow their fields at natural width instead, so the short field sits snugly next to the next one with no gap. Purely cosmetic, no behavior change.',
  ],
  '2.25.2': [
    'Settings page polish: short-value fields (SMTP port, DNS server IP, digest-send-hour, alert cooldown, SMTP password) no longer stretch to fill their entire grid cell -- they now size to fit the kind of value they hold, matching the fix already shipped in a sibling NocVault app. Purely cosmetic, no behavior change.',
  ],
  '2.25.1': [
    'Hotfix for 3 bugs found in a verification pass on yesterday\'s performance release, before they had any real-world impact: a Log Explorer search regression that could silently miss results for common word variants (e.g. searching "connecting" would miss "Connection Failed" entries), the Network Health page\'s "logs in the last hour" column occasionally under-reporting right after the clock struck the hour, and an Intelligence-tab entity table that could include the firewall itself instead of only real users/attackers.',
  ],
  '2.25.0': [
    'Performance: the Security page, Network Health page, and the Intelligence tab\'s entity drill-down panel are all substantially faster now. The worst offenders — a security summary card that could take over a minute and a half on a 30-day view, the device status table (up to 23 seconds), and clicking into an entity\'s activity history (40-50 seconds) — now load in a fraction of a second, using the same background pre-aggregation technique already applied to the main Dashboard.',
    'Fixed a real bug found along the way: the "Firewall Denies" card and page had been silently showing zero results since they shipped. They were checking for a value your firewall never actually sends — now checking the correct one, so blocked-traffic data actually shows up.',
    'Log Explorer search is now much faster, especially for common search terms across a wide time range (previously up to ~95 seconds in the worst case) — added missing search indexes and capped the "showing X of Y" count for text searches instead of always computing an exact total.',
    'Also fixed: MITRE ATT&CK coverage now loads about 30x faster, and a few smaller dashboard stat cards (Top Services, Firewall Actions, the public status widget) now use the same fast pre-aggregated data as the rest of the dashboard instead of scanning raw logs.',
  ],
  '2.24.1': [
    'Fixed a gap in the dashboard performance-summary tables added over the last few releases: they only ever refreshed the current and previous hour, so any logs that arrived late — after a database hiccup, a brief network blip, or simply because the collector service was restarting for an update — quietly never made it into any dashboard widget, permanently, with no error shown anywhere. The refresh window is now a full rolling day, so a delay or restart shorter than that self-corrects automatically within a few minutes instead of requiring a manual fix.',
  ],
  '2.24.0': [
    'Performance: a full pass over every remaining dashboard widget found and fixed several more slow spots — the worst were Known-Bad Sources (measured taking up to 130 seconds) and What\'s New/Changed (over 200 seconds for one part of it). Both were re-scanning the full log history live on every page load; they now read from small pre-aggregated summary tables kept up to date in the background, the same technique already used for the other dashboard widgets. Top Destinations (previously up to 76 seconds on a 7-day view) and Capacity & Ingestion Health got the same fix. The Known-Bad Sources fix also indirectly speeds up Riskiest Entities, which was being slowed down by the other widget tying up shared database connections behind the scenes.',
    'The Storage panel now caches its results briefly instead of recalculating on every single check, and a duplicated calculation inside it was removed — shaves roughly another second or two off that widget.',
  ],
  '2.23.0': [
    'Performance: 4 dashboard widgets — Top Security Events, Top Blocked Destinations, Top Connection Failures, and VPN Status — were classifying every matching log line live on each page load. Top Security Events alone was measured taking 17-29 seconds because its filter matches nearly every log line in a typical day, so there was no way to speed it up with a better index — it needed pre-computed data instead. All 4 now read from small, pre-aggregated summary tables kept up to date in the background, the same technique already used for the main dashboard KPIs. Typical load time for these 4 widgets drops from several seconds (up to ~29s for the worst case) to well under a second.',
    'The "Total logs stored" figure on the Storage panel now uses the database\'s own fast built-in estimate instead of recounting every row on every check — shaves a further ~5 seconds off that widget with no meaningful loss of accuracy for a number that\'s purely informational.',
  ],
  '2.22.3': [
    'ROOT CAUSE FIX: found the real reason the version number in the sidebar kept showing an old release (v2.18.12) on every fresh page load, which had been misdiagnosed as a network caching problem in 2.22.1/2.22.2 — it was neither. A separate, forgotten copy of the version number, in a file the release process never actually updates, was silently stuck at v2.18.12 this whole time. Every page load showed that wrong number for a brief moment before a live check quietly corrected it — which, glanced at quickly or caught by a screenshot, looks exactly like the app "reverting" to an old version. The app now reads the version from one single, correctly-updated place, so this can\'t drift out of sync again.',
  ],
  '2.22.2': [
    'FOLLOW-UP FIX: 2.22.1 stopped NEW stale copies from being cached, but on a network with a caching proxy in the path, a copy already cached BEFORE that fix shipped could keep being served indefinitely, since that fix could not reach in and remove something already stored elsewhere. The collector-status indicator and version number in the sidebar now bust that cache directly on every check, so they can never be served a stored answer again, regardless of what any proxy already has saved or how it behaves.',
  ],
  '2.22.1': [
    'URGENT FIX: every API and page response was missing any explicit "do not cache" instruction — only a weak validity marker (ETag) that some networks\' caching proxies/security appliances treat as permission to cache anyway. On a network with such a proxy in the path, this could show different users (or the same user reloading) a stale, out-of-date copy of the app intermittently — a hard refresh or private/incognito browsing does NOT fix this, because that kind of cache lives on network infrastructure, not in the browser. Every response now explicitly forbids caching.',
    'Fixed a real bug where a background idle-timeout check was silently failing on every page load (blocked by the browser for security reasons) because it was checking the wrong server for a setting it should have checked locally. No user-visible symptom before this fix — it silently fell back to its default value — but worth fixing since it was a genuine bug once found.',
  ],
  '2.22.0': [
    'Performance: the app was shipping the code for ALL 10 tabs (Dashboard, Log Explorer, Live Tail, Alerts, Network Health, Security, Intelligence, Known Hosts, Reports, Settings) on every page load, regardless of which one you actually opened — around 1.4MB of JavaScript loaded upfront every time. The 9 tabs other than Dashboard now load their code on-demand, the first time you click into them, instead of all at once on login.',
    'This is a separate fix from the recent backend query-speed work — that made individual API responses much faster, this reduces how much the browser has to download and run before the page can even start rendering. Both contribute to a snappier feel, especially on first load.',
  ],
  '2.21.1': [
    'Performance: several Security tab endpoints (Summary, Auth Failures, Brute Force, Failed Logins by Country) carried a leftover "double-check" pattern from before every log parser reliably tagged failed-login events — a live 30-day check proved that double-check now catches zero events the primary detection misses, while making these queries dramatically slower to plan. Removed; verified byte-for-byte identical results before and after. Measured 11-40x faster on the affected queries.',
  ],
  '2.21.0': [
    'Performance: the dashboard\'s Severity Summary, Timeline (24h+ ranges), Top Talkers, and Vendor Breakdown widgets no longer scan the full raw log table on every load. A live investigation found the Top Talkers widget alone taking 1.6+ seconds and spilling ~300MB to disk on a single request; these 4 widgets now read from small, pre-aggregated hourly summary tables maintained automatically in the background instead.',
    'This is the first step toward keeping the dashboard fast as more devices are added — these widgets\' load time is no longer directly tied to total log volume.',
    'IMPORTANT (server operator only): after updating, run "node scripts/backfill-rollups.js" once to populate historical data for the new summary tables — widgets will show partial data for the last 30 days until it completes (a few minutes). See CLAUDE.md "Dashboard-widget hourly rollups" for full detail and a recommended one-time Postgres tuning step.',
  ],
  '2.20.1': [
    'Reports tab: added support for area-style charts in the live preview (a PDF-export chart type that had no matching preview renderer yet), and fixed the "No data" message so it actually shows for a genuinely empty report instead of never appearing.',
  ],
  '2.20.0': [
    'New: a Reports tab with 3 exportable report types — Security Summary (severity/category breakdown, top talkers/blocked/failures, log-volume trend), Site/Device Activity (per-site log volume, vendor breakdown, top devices, active alerts), and MITRE ATT&CK Coverage (technique-level event/alert counts). Each is available as a live in-app preview or a downloadable CSV/PDF.',
    'Reports are automatically scoped to your assigned sites, same as every other page in LogVault — there is no separate site picker to configure.',
    'Every report generation (preview, CSV, or PDF) is logged to a new report history table for future auditing.',
  ],
  '2.19.3': [
    'Hardened the in-app "Update" button: it now writes a full transcript of the update run to installer\\logs\\ — previously a failed in-app-triggered update left no record of what happened (only a handful of start/fail/complete milestone lines), since that button runs fully in the background with no live output.',
  ],
  '2.19.2': [
    'Fixed: links back to the NocVault hub (sign-out, home button, license page, session-expiry redirect) always pointed at the server\'s original install-time IP address, regardless of what hostname you actually used to reach LogVault. Every hub link now follows your current hostname instead.',
  ],
  '2.19.1': [
    'Security fix: the per-user app-access block shipped in 2.19.0 only stopped a denied user from reaching LogVault pages — a valid session could still call the API directly and get full data. The API now enforces the same check.',
    'Security fix: LogVault\'s legacy direct-login path (unused by the UI, but still reachable) never carried the allowed-apps claim, so a user denied LogVault could log in that way and bypass the block entirely. It now resolves and enforces the same claim as SSO login.',
  ],
  '2.19.0': [
    'Per-user app-access enforcement: LogVault now blocks users who are not granted the LogVault app at the app level, not just on the hub launcher. A user without LogVault access is redirected to the NocVault hub launcher with a "denied" banner instead of reaching any LogVault page.',
    'The allowed-apps claim now flows end-to-end through SSO: NetVault mints it into the SSO token, and LogVault carries it into its own NextAuth session so the edge middleware (proxy.ts) can enforce it on every page request.',
    'Fail-open by design: tokens with no apps claim (or an empty list) are treated as default-all, so existing sessions and older SSO tokens are never locked out. NetVault (the hub) is always allowed.',
    'Unauthenticated handling is unchanged — no session still redirects to the hub login. Only a valid session that explicitly lacks LogVault access is bounced to the launcher.',
  ],
  '2.18.11': [
    'Installer: the post-update health check now uses 127.0.0.1 instead of localhost, so it can no longer stall waiting on IPv6 (::1) when the app listens on IPv4 — the update reports the service healthy as soon as it is actually up.',
  ],
  '2.18.10': [
    'Updater hardening: the update script now pins the build directory to its true on-disk casing, so a build can no longer fail with a duplicate-React "useContext" error when the updater is invoked with a different path casing than a previous run (Next.js caches absolute paths, so a casing change between runs collided).',
  ],
  '2.18.9': [
    'Update check hardening: the git-based update check + banner now run asynchronously, so a slow or unreachable GitHub can no longer briefly stall the server (and log ingestion) while checking for updates.',
  ],
  '2.18.8': [
    'Fixed "Could not check for updates" in Settings → Updates. The update check (and the update-available banner) was calling GitHub\'s public web APIs (api.github.com + raw.githubusercontent.com), which are rate-limited per source IP — from a shared network with several apps checking, raw.githubusercontent started returning 429 and the check failed. Both now check via git (the same transport the updater already uses), which is not rate-limited.',
  ],
  '2.18.7': [
    'Fix: the trial/license banner now renders directly below the top header (in the content flow) instead of above the LogVault logo. It pushes content down like the rest of the NocVault suite, and the header avatar dropdown correctly stacks above it.',
  ],
  '2.18.6': [
    'Fix: the in-app "Update" now works on suite installs. The updater was resolving the app folder from a hardcoded path (C:\\Apps\\logvault) instead of the actual install location (C:\\Apps\\LogVault\\app), so it ran git/npm in the wrong directory, failed, and left the services stopped. It now self-locates its app folder from the script path, and the git safe.directory + server-side launcher were corrected to match.',
  ],
  '2.18.5': [
    'Dashboard: the Top Talkers, Logs by Vendor and Top Destinations cards no longer clip their last row — each list now scrolls within the card (whole rows only), so all entries are reachable without changing the card height. Works in both light and dark mode.',
  ],
  '2.18.4': [
    'Fix: the NocVault Hub\'s cross-DB read role now self-heals on every update. The shared nocvault_readonly SELECT grant is re-applied by the schema step the updater runs as postgres, so tables added by future releases stay visible to the Hub instead of becoming invisible (the grant was previously provisioned only by the fresh suite installer).',
    'ALTER DEFAULT PRIVILEGES (FOR ROLE postgres) auto-covers any future LogVault tables for the read role. SELECT-only - the change does not touch the append-only tamper model on syslog_entries/audit_log, and no-ops on a standalone LogVault without the role.',
  ],
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
    const remoteHash = await remoteCommitHash();

    // Any differing commit = update available. If either hash is missing,
    // keep the last known state so a blip never shows a false banner.
    updateAvailable = (localHash && remoteHash && remoteHash !== localHash)
      ? { current: version, latest: await remoteVersion(version) }
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

// Update-LogVault.ps1 writes a structured result of the last update attempt to
// logs/last-update-status.json on every run (success or failure) - see the
// script's Write-StatusJson function. This route just surfaces that file so the
// frontend can show a banner the moment a failed update needs attention, without
// anyone having to go looking at the updater's log files. Same public access
// level as /api/system/update-available (no auth required) - matches its sibling
// exactly, including the enforceLicense exemption below and proxy.ts's
// PUBLIC_API_PATHS (both must list this path - see CLAUDE.md's "Adding a new
// intentionally-public API route").
app.get('/api/system/last-update-status', (_req, res) => {
  const statusPath = path.join(appRoot, 'logs', 'last-update-status.json');
  if (!fs.existsSync(statusPath)) {
    return res.json({ exists: false });
  }
  try {
    const BOM = String.fromCharCode(0xfeff);
    const raw = fs.readFileSync(statusPath, 'utf8');
    const status = JSON.parse(raw.startsWith(BOM) ? raw.slice(1) : raw);
    res.json({ exists: true, ...status });
  } catch (e) {
    res.json({ exists: false, error: 'Could not read update status file' });
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
    // Read the latest commit over GIT TRANSPORT (git ls-remote) rather than the
    // GitHub web APIs, which are per-IP rate-limited — from Thai Union's shared
    // egress raw.githubusercontent returns 429 and api.github.com times out. Git
    // push/pull already work on the server, so ls-remote does too.
    const remoteHash = await remoteCommitHash();

    // If the remote hash is unreadable, degrade gracefully to the same
    // "Could not check for updates" response as a hard failure.
    if (!remoteHash) {
      console.error('[update-status] could not read remote commit hash (git ls-remote)');
      // Same field set as the success shape (minus what genuinely can't be known),
      // so a client never has to special-case the degraded response.
      // current_commit/current_hash are LOCAL facts and are still known here;
      // omitting them blanked the "current commit" readout on an offline check.
      return res.json({
        current_version: localVersion,
        current_commit: localHash,
        current_hash: localHash,
        up_to_date: true,
        update_available: false,
        error: 'Could not check for updates',
      });
    }

    // Any differing commit = update available; both hashes must be present.
    const updateAvail = !!remoteHash && !!localHash && remoteHash !== localHash;

    // Only fetch the remote version (a network round-trip) when there is
    // actually a new commit; otherwise the version is display-identical to local.
    const remoteVer = updateAvail ? await remoteVersion(localVersion) : localVersion;

    // Release notes keyed by the latest version, with a generic fallback.
    const release_notes = releaseNotes[remoteVer] || releaseNotes['default'];

    // Keep the cached banner state in sync with this on-demand check.
    updateAvailable = updateAvail ? { current: localVersion, latest: remoteVer } : null;
    res.json({
      current_version:  localVersion,
      latest_version:   remoteVer,
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
    res.json({
      current_version: localVersion,
      current_commit: localHash,
      current_hash: localHash,
      up_to_date: true,
      update_available: false,
      error: 'Could not check for updates',
    });
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

  // Concurrency guard: refuse to schedule a second update run while one is
  // already in flight — e.g. a manual on-server run racing this in-app
  // trigger, or a double-click of "Update Now". Reads the SAME PID-stamped
  // lock file Update-LogVault.ps1 itself writes/removes (logs/update.lock),
  // with the identical "PID no longer running = stale, ignore it" logic, so a
  // crashed prior run never permanently wedges the in-app trigger. This is a
  // best-effort check (there's a small window between this check and the
  // scheduled task actually starting/writing its own lock) — the script's own
  // lock is the authoritative guard; this just avoids scheduling a run that's
  // very likely to collide.
  const lockPath = path.join(appRoot, 'logs', 'update.lock');
  if (fs.existsSync(lockPath)) {
    try {
      const BOM = String.fromCharCode(0xfeff);
      let raw = fs.readFileSync(lockPath, 'utf8').trim();
      if (raw.startsWith(BOM)) raw = raw.slice(1);
      const lockedPid = parseInt(raw, 10);
      if (lockedPid) {
        let stillRunning = true;
        try { process.kill(lockedPid, 0); } catch (_e) { stillRunning = false; }
        if (stillRunning) {
          return res.status(409).json({ error: `An update is already running (PID ${lockedPid}). Wait for it to finish before starting another.` });
        }
      }
    } catch (_e) {
      // Unreadable lock file — fall through and let the scheduled run proceed;
      // the script's own guard is authoritative and will sort out a stale lock.
    }
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
      `-File \\"${scriptPath}\\" ` +
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
// Unauthenticated widget (no req.rbac, so no site scoping — suite-wide
// totals). Reads syslog_stats_rollup/syslog_source_host_rollup (scripts/
// schema.sql "HOURLY ROLLUP TABLES"/"PHASE 3") instead of scanning raw
// syslog_entries — this was the one dashboard-shaped aggregate query the
// original rollup passes missed (perf sweep, 2026-07).
app.get('/api/stats', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  try {
    const [logsToday, sources, alerts] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS c FROM syslog_stats_rollup WHERE hour_bucket >= date_trunc('hour', NOW() - INTERVAL '24 hours')`),
      pool.query(`SELECT COUNT(DISTINCT source_host) AS c FROM syslog_source_host_rollup WHERE hour_bucket >= date_trunc('hour', NOW() - INTERVAL '24 hours')`),
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
