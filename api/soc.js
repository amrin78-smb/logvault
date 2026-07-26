'use strict';

/**
 * soc.js — SOC console / analyst-overview router for LogVault.
 *
 * Factory-router module, mirroring api/reports.js's createReportsRouter(pool)
 * pattern: `createSocRouter(pool)` returns an express.Router() that is mounted
 * in api/server.js at /api/soc, AFTER rbacMiddleware (so req.rbac exists) and
 * enforceLicense (same license gate as every other business route).
 *
 * NOTHING here is a new data source — every endpoint is compute-on-read over
 * the SAME tables/rollups the existing /api/stats/*, /api/security/*,
 * /api/ueba/*, /api/anomalies/*, /api/alerts/* and /api/threats/* endpoints
 * already read, reusing their EXACT SQL and the SAME site-scope helpers from
 * ./rbac (getSiteFilter / getAlertSiteFilter / getRollupSiteFilter, plus the
 * local anomalySiteFilter null-allowance wrapper copied from server.js). No
 * table/column/schema change is required or introduced.
 *
 * These routes COMPOSE existing aggregates so the SOC UI makes fewer round
 * trips: /overview (one dashboard payload), /digest (deterministic templated
 * NLG — no randomness, no LLM, no email), /killchain/:alertId (the underlying
 * syslog entries behind a fired alert) and /entity-timeline/:type/:value.
 */

const express = require('express');
const { getSiteFilter, getAlertSiteFilter, getRollupSiteFilter } = require('./rbac');

// Same one-liner as api/server.js — asyncHandler is module-private there.
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ── Short-TTL cache (mirrors server.js getCached/rbacCacheKey, which are
//    module-private there). Keyed incl. the RBAC scope so site-restricted
//    results never leak across users. ──────────────────────────────────────
const socCache = new Map();
async function getCached(key, ttlMs, fn) {
  const cached = socCache.get(key);
  if (cached && Date.now() - cached.at < ttlMs) return cached.data;
  const data = await fn();
  socCache.set(key, { data, at: Date.now() });
  return data;
}
function rbacCacheKey(rbac) {
  if (!rbac || rbac.allowedSiteIds == null) return 'all';
  return 'sites:' + [...rbac.allowedSiteIds].sort((a, b) => a - b).join(',');
}

// ── Input validation (same shapes as api/server.js) ───────────────────────
function safeHours(val, max = 720) {
  const n = Math.min(parseInt(val || '24') || 24, max);
  return isNaN(n) || n <= 0 ? 24 : n;
}
function safeInt(val, def = 10, max = 500) {
  const n = parseInt(val || String(def));
  return isNaN(n) || n <= 0 ? def : Math.min(n, max);
}

// anomalySiteFilter — copied verbatim from server.js:1867. The anomaly/UEBA
// tables (anomaly_events.source_ip / entity_risk.source_ip) can legitimately
// carry a NULL source_ip; the strict getSiteFilter would drop those rows for
// site-scoped users, so we OR in "<alias>.source_ip IS NULL". For admins the
// strict clause is empty → no restriction at all.
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

// Thousands-separator formatting for the deterministic digest.
const fmt = (n) => Number(n || 0).toLocaleString('en-US');
// MITRE technique IDs live in structured_data.mitre as a JSON array (node-pg
// returns JSONB as a JS object, so .mitre is already an array when present).
function techsOf(sd) {
  if (!sd || typeof sd !== 'object') return [];
  return Array.isArray(sd.mitre) ? sd.mitre : [];
}

// Correlation-rule → look-back window (minutes), copied from server.js's
// ALERT_LOG_WINDOW_MINUTES map — used as the fallback when a rule has no
// threshold_window. Mirrors the windows in collector/correlationEngine.js.
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

// ════════════════════════════════════════════════════════════
// GATHER HELPERS — each reuses the EXACT SQL of an existing endpoint and
// builds its own site filter (helpers return cheap { clause, params } objects,
// so recomputing per query is fine). Shared by /overview and /digest.
// ════════════════════════════════════════════════════════════

// Severity distribution — reuses GET /api/stats/summary (syslog_stats_rollup,
// getRollupSiteFilter).
async function gatherSeverity(pool, rbac, hours) {
  const sf = getRollupSiteFilter(rbac, 2);
  const { rows } = await pool.query(`
    SELECT severity, severity_label, SUM(log_count)::bigint AS log_count
    FROM syslog_stats_rollup
    WHERE hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1))
    ${sf.clause}
    GROUP BY severity, severity_label
    ORDER BY severity
  `, [hours, ...sf.params]);
  return rows.map(r => ({
    severity: r.severity,
    severity_label: r.severity_label,
    log_count: parseInt(r.log_count) || 0,
  }));
}

// Top entities by risk — reuses GET /api/ueba/top (entity_risk, anomalySiteFilter
// on 'er'), top 5 by risk_score.
async function gatherTopEntities(pool, rbac) {
  const conditions = ['TRUE'];
  const params = [];
  let p = 1;
  const sf = anomalySiteFilter(rbac, p, 'er');
  if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }
  params.push(5);
  const { rows } = await pool.query(`
    SELECT er.entity_type, er.entity_value, er.risk_score,
           er.anomaly_count, er.event_count
    FROM entity_risk er
    WHERE ${conditions.join(' AND ')}
    ORDER BY er.risk_score DESC
    LIMIT $${p}
  `, params);
  return rows.map(r => ({
    entity_type: r.entity_type,
    entity_value: r.entity_value,
    risk_score: parseInt(r.risk_score) || 0,
    anomaly_count: parseInt(r.anomaly_count) || 0,
    event_count: parseInt(r.event_count) || 0,
  }));
}

// Top attacker countries — reuses GET /api/stats/geo (failed/auth-login scope,
// srccountry → known_hosts.country_name, current vs prior window), getSiteFilter.
async function gatherTopCountries(pool, rbac, hours, limit) {
  const sf = getSiteFilter(rbac, 2, 'se');
  const limitIdx = sf.nextParamIndex;
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
      )::bigint AS prev_count
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
    LIMIT $${limitIdx}
  `, [hours, ...sf.params, limit]);
  return rows.map(r => ({
    country: r.country,
    country_code: r.country_code,
    count: parseInt(r.count) || 0,
    prev_count: parseInt(r.prev_count) || 0,
  }));
}

// Active incidents — alert_events JOIN alert_rules over the last <hours>,
// unacked first then most recent, limit 12. Relay-based site scoping
// (getAlertSiteFilter), same as GET /api/alerts/events.
async function gatherIncidents(pool, rbac, hours) {
  const sf = getAlertSiteFilter(rbac, 2, 'ae');
  const { rows } = await pool.query(`
    SELECT ae.id, ae.rule_id, ar.name AS rule_name, ar.mitre_techniques,
           ae.source_host, ae.source_ip::text AS source_ip, ae.match_count,
           ae.fired_at, ae.acknowledged
    FROM alert_events ae
    LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
    WHERE ae.fired_at > NOW() - make_interval(hours => $1)
    ${sf.clause}
    ORDER BY ae.acknowledged ASC, ae.fired_at DESC
    LIMIT 12
  `, [hours, ...sf.params]);
  return rows.map(r => ({
    id: r.id,
    rule_id: r.rule_id,
    rule_name: r.rule_name,
    techniques: r.mitre_techniques || [],
    source_host: r.source_host,
    source_ip: r.source_ip,
    match_count: r.match_count,
    fired_at: r.fired_at,
    acknowledged: r.acknowledged,
  }));
}

// Security counters — reuses the EXACT sub-queries of GET /api/security/summary
// (auth_fail / deny / vpn / ips / after_hours / brute_force only).
async function gatherSecurity(pool, rbac, hours) {
  const sf  = getSiteFilter(rbac, 2, 'syslog_entries'); // bare-table subqueries
  const sfA = getSiteFilter(rbac, 2, 'a');               // brute-force success alias
  const sfRollupDenies = getRollupSiteFilter(rbac, 2);
  const sfRollupVpn    = getRollupSiteFilter(rbac, 2);
  const sfRollupIps    = getRollupSiteFilter(rbac, 2);
  const [authFail, denies, vpn, ips, afterHours, bruteSuccess] = await Promise.all([
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory' IN ('login_failed','auth_failed') ${sf.clause}`, [hours, ...sf.params]),
    pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'action' AND value = 'blocked' AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1)) ${sfRollupDenies.clause}`, [hours, ...sfRollupDenies.params]),
    pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'subtype' AND value = 'vpn' AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1)) ${sfRollupVpn.clause}`, [hours, ...sfRollupVpn.params]),
    pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'type' AND value = 'utm' AND hour_bucket >= date_trunc('hour', NOW() - make_interval(hours => $1)) ${sfRollupIps.clause}`, [hours, ...sfRollupIps.params]),
    pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > NOW() - make_interval(hours => $1) AND structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19 ${sf.clause}`, [hours, ...sf.params]),
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
  ]);
  return {
    auth_fail:    parseInt(authFail.rows[0].count) || 0,
    deny:         parseInt(denies.rows[0].count) || 0,
    vpn:          parseInt(vpn.rows[0].count) || 0,
    ips:          parseInt(ips.rows[0].count) || 0,
    after_hours:  parseInt(afterHours.rows[0].count) || 0,
    brute_force:  parseInt(bruteSuccess.rows[0].count) || 0,
  };
}

// Alert totals — unacked (current state) + fired in last 24h. Relay-based
// scoping, same as GET /api/stats/alerts-summary.
async function gatherAlertTotals(pool, rbac) {
  const sf = getAlertSiteFilter(rbac, 1, 'ae');
  const { rows } = await pool.query(`
    SELECT COUNT(*) FILTER (WHERE ae.acknowledged = FALSE)::int AS unacked,
           COUNT(*) FILTER (WHERE ae.fired_at > NOW() - make_interval(hours => 24))::int AS h24
    FROM alert_events ae
    WHERE TRUE
    ${sf.clause}
  `, sf.params);
  return rows[0];
}

// Anomaly totals — unacked (current state) + detected in last 24h. Same
// RBAC-with-null-allowance as GET /api/anomalies/summary.
async function gatherAnomalyTotals(pool, rbac) {
  const sf = anomalySiteFilter(rbac, 1, 'ae');
  const { rows } = await pool.query(`
    SELECT COUNT(*) FILTER (WHERE ae.acknowledged = FALSE)::int AS unacked,
           COUNT(*) FILTER (WHERE ae.detected_at > NOW() - make_interval(hours => 24))::int AS h24
    FROM anomaly_events ae
    WHERE TRUE
    ${sf.clause}
  `, sf.params);
  return rows[0];
}

// Active known-bad host count — same predicate + site scoping as the header of
// GET /api/threats/known-bad (known_hosts flagged is_known_bad OR abuse >= 50).
async function gatherKnownBadActive(pool, rbac) {
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
  const { rows } = await pool.query(`
    SELECT COUNT(*)::int AS c
    FROM known_hosts kh
    WHERE (kh.is_known_bad = TRUE OR kh.abuse_score >= 50)
    ${khWhere}
  `, params);
  return rows[0].c;
}

// Incident stats over the window — total fired + unacked. Used by the digest
// headline/incidents section (getAlertSiteFilter).
async function gatherIncidentStats(pool, rbac, hours) {
  const sf = getAlertSiteFilter(rbac, 2, 'ae');
  const { rows } = await pool.query(`
    SELECT COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE ae.acknowledged = FALSE)::int AS unacked
    FROM alert_events ae
    WHERE ae.fired_at > NOW() - make_interval(hours => $1)
    ${sf.clause}
  `, [hours, ...sf.params]);
  return rows[0];
}

// Anomaly stats over the window — total + critical/warning + unacked. Severity
// values are 'info'|'warning'|'critical' (schema.sql anomaly_events.severity).
async function gatherAnomalyWindow(pool, rbac, hours) {
  const sf = anomalySiteFilter(rbac, 2, 'ae');
  const { rows } = await pool.query(`
    SELECT COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE ae.severity = 'critical')::int AS critical,
           COUNT(*) FILTER (WHERE ae.severity = 'warning')::int AS warning,
           COUNT(*) FILTER (WHERE ae.acknowledged = FALSE)::int AS unacked
    FROM anomaly_events ae
    WHERE ae.detected_at > NOW() - make_interval(hours => $1)
    ${sf.clause}
  `, [hours, ...sf.params]);
  return rows[0];
}

// "What's changed" totals — reuses the EXACT anti-join of GET
// /api/stats/whats-changed (syslog_distinct_value_rollup, getRollupSiteFilter),
// returning only the per-dimension NEW-value totals the digest needs.
async function gatherWhatsChanged(pool, rbac, days) {
  function buildAntiJoin(dimension) {
    const sfR = getRollupSiteFilter(rbac, 3);
    const sfB = getRollupSiteFilter(rbac, 3 + sfR.params.length);
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
    return { sql, params: [days, dimension, ...sfR.params, ...sfB.params] };
  }
  const q = {
    new_countries: buildAntiJoin('country'),
    new_users:     buildAntiJoin('user'),
    new_sources:   buildAntiJoin('source'),
    new_services:  buildAntiJoin('service'),
  };
  const [countries, users, sources, services] = await Promise.all([
    pool.query(q.new_countries.sql, q.new_countries.params),
    pool.query(q.new_users.sql,     q.new_users.params),
    pool.query(q.new_sources.sql,   q.new_sources.params),
    pool.query(q.new_services.sql,  q.new_services.params),
  ]);
  const total = (r) => (r.rows.length ? (parseInt(r.rows[0].total, 10) || r.rows.length) : 0);
  return {
    new_countries: total(countries),
    new_users:     total(users),
    new_sources:   total(sources),
    new_services:  total(services),
  };
}

// ════════════════════════════════════════════════════════════
// ROUTER
// ════════════════════════════════════════════════════════════
function createSocRouter(pool) {
  const router = express.Router();

  // ── 1) GET /api/soc/overview?hours=24 — one composed dashboard payload ──
  router.get('/overview', asyncHandler(async (req, res) => {
    const hours = safeHours(req.query.hours);
    const cacheKey = `soc:overview:${hours}:${rbacCacheKey(req.rbac)}`;
    const data = await getCached(cacheKey, 30000, async () => {
      const rbac = req.rbac;
      const [severity, topEntities, topCountries, incidents, security, alertTotals, anomalyTotals, knownBadActive] =
        await Promise.all([
          gatherSeverity(pool, rbac, hours),
          gatherTopEntities(pool, rbac),
          gatherTopCountries(pool, rbac, hours, 10),
          gatherIncidents(pool, rbac, hours),
          gatherSecurity(pool, rbac, hours),
          gatherAlertTotals(pool, rbac),
          gatherAnomalyTotals(pool, rbac),
          gatherKnownBadActive(pool, rbac),
        ]);
      const totalLogs = severity.reduce((a, b) => a + (b.log_count || 0), 0);
      return {
        hours,
        generated_at: new Date().toISOString(),
        severity,
        totals: {
          logs:              totalLogs,
          alerts_unacked:    alertTotals.unacked,
          alerts_24h:        alertTotals.h24,
          anomalies_unacked: anomalyTotals.unacked,
          anomalies_24h:     anomalyTotals.h24,
          known_bad_active:  knownBadActive,
        },
        top_entities:     topEntities,
        top_countries:    topCountries,
        active_incidents: incidents,
        security,
      };
    });
    res.json(data);
  }));

  // ── 2) GET /api/soc/digest?hours=24 — deterministic templated NLG ──
  // No randomness, no LLM, no email. Batches the whole window into one digest.
  router.get('/digest', asyncHandler(async (req, res) => {
    const hours = safeHours(req.query.hours);
    const days = Math.max(1, Math.round(hours / 24));
    const cacheKey = `soc:digest:${hours}:${rbacCacheKey(req.rbac)}`;
    const data = await getCached(cacheKey, 30000, async () => {
      const rbac = req.rbac;
      const [severity, incStats, anomWindow, incidents, topEntities, topCountries, knownBadActive, whatsChanged] =
        await Promise.all([
          gatherSeverity(pool, rbac, hours),
          gatherIncidentStats(pool, rbac, hours),
          gatherAnomalyWindow(pool, rbac, hours),
          gatherIncidents(pool, rbac, hours),
          gatherTopEntities(pool, rbac),
          gatherTopCountries(pool, rbac, hours, 5),
          gatherKnownBadActive(pool, rbac),
          gatherWhatsChanged(pool, rbac, days),
        ]);
      const totalLogs = severity.reduce((a, b) => a + (b.log_count || 0), 0);
      const plural = (n, s = 's') => (n === 1 ? '' : s);

      // ── Incidents section ──
      const incidentsSec = { id: 'incidents', title: 'Incidents' };
      if (incStats.unacked > 0) {
        incidentsSec.severity = 'critical';
        incidentsSec.sentences = [
          `${fmt(incStats.unacked)} unacknowledged incident${plural(incStats.unacked)} require attention, out of ${fmt(incStats.total)} alert${plural(incStats.total)} fired in the last ${hours} hours.`,
        ];
        const top = incidents.find(i => !i.acknowledged) || incidents[0];
        if (top) {
          incidentsSec.sentences.push(`The most recent is "${top.rule_name || 'Unnamed rule'}" from ${top.source_host || 'an unidentified host'}.`);
        }
      } else if (incStats.total > 0) {
        incidentsSec.severity = 'warning';
        incidentsSec.sentences = [
          `${fmt(incStats.total)} alert${plural(incStats.total)} fired in the last ${hours} hours; all have been acknowledged.`,
        ];
      } else {
        incidentsSec.severity = 'ok';
        incidentsSec.sentences = [`No active incidents in the last ${hours} hours.`];
      }

      // ── Anomalies section ──
      const anomaliesSec = { id: 'anomalies', title: 'Anomalies' };
      if (anomWindow.critical > 0) anomaliesSec.severity = 'critical';
      else if (anomWindow.total > 0) anomaliesSec.severity = 'warning';
      else anomaliesSec.severity = 'ok';
      if (anomWindow.total > 0) {
        anomaliesSec.sentences = [
          `${fmt(anomWindow.total)} behavioral anomal${anomWindow.total === 1 ? 'y' : 'ies'} detected in the last ${hours} hours${anomWindow.critical > 0 ? `, including ${fmt(anomWindow.critical)} rated critical` : ''}.`,
        ];
        if (anomWindow.unacked > 0) {
          anomaliesSec.sentences.push(`${fmt(anomWindow.unacked)} remain unacknowledged.`);
        }
      } else {
        anomaliesSec.sentences = [`No behavioral anomalies detected in the last ${hours} hours.`];
      }

      // ── Riskiest entities section ──
      const entitiesSec = { id: 'entities', title: 'Riskiest entities' };
      const topEntity = topEntities[0];
      if (!topEntity) {
        entitiesSec.severity = 'ok';
        entitiesSec.sentences = ['No entities have accrued a risk score yet.'];
      } else {
        const score = topEntity.risk_score || 0;
        entitiesSec.severity = score >= 70 ? 'critical' : score >= 40 ? 'warning' : 'info';
        entitiesSec.sentences = [
          `The riskiest entity is ${topEntity.entity_type} "${topEntity.entity_value}" with a risk score of ${fmt(score)} (${fmt(topEntity.anomaly_count)} anomal${topEntity.anomaly_count === 1 ? 'y' : 'ies'} across ${fmt(topEntity.event_count)} events).`,
        ];
        if (topEntities[1]) {
          entitiesSec.sentences.push(`Next highest: ${topEntities[1].entity_type} "${topEntities[1].entity_value}" at risk score ${fmt(topEntities[1].risk_score || 0)}.`);
        }
      }

      // ── External threats section ──
      const threatsSec = { id: 'threats', title: 'External threats', sentences: [] };
      if (knownBadActive > 0) threatsSec.severity = 'critical';
      else if (topCountries.length && topCountries[0].count > 0) threatsSec.severity = 'warning';
      else threatsSec.severity = 'ok';
      if (knownBadActive > 0) {
        threatsSec.sentences.push(`${fmt(knownBadActive)} known-bad IP${plural(knownBadActive)} (threat-flagged or high AbuseIPDB score) are present in your inventory.`);
      }
      if (topCountries.length) {
        const tc = topCountries.slice(0, 3).map(c => `${c.country} (${fmt(c.count)})`).join(', ');
        threatsSec.sentences.push(`Top source countries for failed logins: ${tc}.`);
      }
      if (!threatsSec.sentences.length) {
        threatsSec.sentences.push(`No external threat indicators in the last ${hours} hours.`);
      }

      // ── Volume & change section ──
      const volumeSec = { id: 'volume', title: 'Volume & change' };
      volumeSec.severity = whatsChanged.new_countries > 0 ? 'warning' : (totalLogs > 0 ? 'info' : 'ok');
      volumeSec.sentences = [`${fmt(totalLogs)} events processed in the last ${hours} hours.`];
      const changes = [];
      if (whatsChanged.new_sources > 0)   changes.push(`${fmt(whatsChanged.new_sources)} new source IP${plural(whatsChanged.new_sources)}`);
      if (whatsChanged.new_countries > 0) changes.push(`${fmt(whatsChanged.new_countries)} new countr${whatsChanged.new_countries === 1 ? 'y' : 'ies'}`);
      if (whatsChanged.new_users > 0)     changes.push(`${fmt(whatsChanged.new_users)} new user${plural(whatsChanged.new_users)}`);
      if (whatsChanged.new_services > 0)  changes.push(`${fmt(whatsChanged.new_services)} new service${plural(whatsChanged.new_services)}`);
      if (changes.length) {
        volumeSec.sentences.push(`Compared with the prior 30 days, ${changes.join(', ')} appeared for the first time.`);
      } else {
        volumeSec.sentences.push('No new countries, users, sources, or services appeared compared with the prior 30 days.');
      }

      const headline = `${hours}-hour security summary: ${fmt(incStats.unacked)} active incident${plural(incStats.unacked)}, ${fmt(anomWindow.total)} anomal${anomWindow.total === 1 ? 'y' : 'ies'} (${fmt(anomWindow.critical)} critical), and ${fmt(totalLogs)} events processed.`;

      return {
        hours,
        generated_at: new Date().toISOString(),
        headline,
        sections: [incidentsSec, anomaliesSec, entitiesSec, threatsSec, volumeSec],
      };
    });
    res.json(data);
  }));

  // ── 3) GET /api/soc/killchain/:alertId — the underlying syslog entries
  //    behind a fired alert, chronological. Reuses the EXACT lookback query of
  //    GET /api/alerts/events/:id/logs; window prefers the rule's
  //    threshold_window, falling back to the correlation-window map / default. ──
  router.get('/killchain/:alertId', asyncHandler(async (req, res) => {
    const id = parseInt(req.params.alertId, 10);
    if (isNaN(id) || id < 1) return res.status(400).json({ error: 'Invalid alert id' });

    // 1) Look up the alert (RBAC site-filtered on ae.source_ip, exactly as
    //    /api/alerts/events/:id/logs). 404 if not found or not visible.
    const af = getSiteFilter(req.rbac, 2, 'ae');
    const alertResult = await pool.query(`
      SELECT ae.*, ar.name AS rule_name, ar.description, ar.mitre_techniques,
             EXTRACT(EPOCH FROM ar.threshold_window)::float / 60 AS window_minutes
      FROM alert_events ae
      LEFT JOIN alert_rules ar ON ar.id = ae.rule_id
      WHERE ae.id = $1
      ${af.clause}
    `, [id, ...af.params]);
    if (!alertResult.rows.length) return res.status(404).json({ error: 'Alert not found' });
    const alert = alertResult.rows[0];

    // 2) Look-back window: prefer the rule's threshold_window, else the
    //    per-rule-name correlation window, else the default. make_interval(mins)
    //    needs an integer → round up.
    const rawWindow = alert.window_minutes || ALERT_LOG_WINDOW_MINUTES[alert.rule_name] || ALERT_LOG_WINDOW_DEFAULT;
    const windowMinutes = Math.max(1, Math.ceil(Number(rawWindow) || ALERT_LOG_WINDOW_DEFAULT));

    // 3) Fetch matching logs around fired_at from the SAME ACTOR — the EXACT
    //    src-match + window logic of /api/alerts/events/:id/logs.
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
      SELECT se.received_at AS ts, se.severity, se.severity_label, se.source_host,
             se.source_ip::text AS source_ip, se.structured_data->>'srcip' AS srcip,
             se.category, se.message, se.structured_data
      FROM syslog_entries se
      WHERE se.received_at BETWEEN ($2::timestamptz - make_interval(mins => $1))
                              AND ($2::timestamptz + interval '1 minute')
        AND (${srcMatch.join(' OR ')})
      ${sf.clause}
      ORDER BY se.received_at ASC
      LIMIT 200
    `, [...params, ...sf.params]);

    const events = logsResult.rows.map(r => ({
      ts: r.ts,
      severity: r.severity,
      severity_label: r.severity_label,
      source_host: r.source_host,
      srcip: r.srcip || r.source_ip,
      category: r.category,
      message: r.message,
      techniques: techsOf(r.structured_data),
    }));

    res.json({
      alert: {
        id: alert.id,
        rule_id: alert.rule_id,
        rule_name: alert.rule_name,
        description: alert.description,
        techniques: alert.mitre_techniques || [],
        source_host: alert.source_host,
        source_ip: alert.source_ip,
        match_count: alert.match_count,
        sample_message: alert.sample_message,
        fired_at: alert.fired_at,
        acknowledged: alert.acknowledged,
      },
      events,
      events_total: events.length, // capped at 200 (the query LIMIT)
    });
  }));

  // ── 4) GET /api/soc/entity-timeline/:type/:value?days=14 ──
  router.get('/entity-timeline/:type/:value', asyncHandler(async (req, res) => {
    const { type, value } = req.params;
    if (!['device', 'user', 'srcip'].includes(type)) {
      return res.status(400).json({ error: 'Invalid entity type' });
    }
    const days = safeInt(req.query.days, 14, 90);

    // Daily activity from syslog_entity_activity_rollup (getRollupSiteFilter),
    // matching GET /api/ueba/entity/:type/:value's rollup read.
    const sf = getRollupSiteFilter(req.rbac, 4);
    const seriesRes = await pool.query(`
      SELECT to_char(date_trunc('day', hour_bucket), 'YYYY-MM-DD') AS date,
             SUM(log_count)::bigint AS count,
             SUM(failed_login_count)::bigint AS failed_logins
      FROM syslog_entity_activity_rollup
      WHERE entity_type = $1 AND entity_value = $2
        AND hour_bucket >= date_trunc('hour', NOW() - make_interval(days => $3))
      ${sf.clause}
      GROUP BY 1
      ORDER BY 1
    `, [type, value, days, ...sf.params]);

    // Anomalies for this entity over the same window (keyed by entity, same as
    // the anomalies branch of /api/ueba/entity/:type/:value — no site filter).
    const anomRes = await pool.query(`
      SELECT detected_at, anomaly_type, severity, title
      FROM anomaly_events
      WHERE entity_type = $1 AND entity_value = $2
        AND detected_at > NOW() - make_interval(days => $3)
      ORDER BY detected_at DESC
      LIMIT 100
    `, [type, value, days]);

    res.json({
      type,
      value,
      series: seriesRes.rows.map(r => ({
        date: r.date,
        count: parseInt(r.count) || 0,
        failed_logins: parseInt(r.failed_logins) || 0,
      })),
      anomalies: anomRes.rows,
    });
  }));

  return router;
}

module.exports = { createSocRouter };
