'use strict';

/**
 * uebaRollup.js — LogVault Phase 2 UEBA entity-risk rollup.
 *
 * For every entity active in the last 24h (device + user + EXTERNAL srcip),
 * computes a 0-100 rolling risk via EWMA(previous entity_risk.risk_score,
 * freshScore). freshScore is a clamped weighted combination of:
 *   - avg(risk_score) of the entity's recent events       (behavioral baseline)
 *   - count of recent UNacknowledged anomalies, severity-weighted
 *   - failed-login count (subcategory login_failed/auth_failed)
 *   - known-bad hits (join known_hosts: is_known_bad / abuse_score)
 *
 * factors jsonb = [{label, contribution}] explaining the score; also stores
 * event_count / anomaly_count / last_activity / source_ip. Upserts entity_risk.
 *
 * Pure local SQL/JS — no external calls. Never throws out (try/catch +
 * console.error), matching the collector scheduled-job contract.
 *
 * Exports: { rollupEntityRisk }
 */

const EWMA_ALPHA = 0.4;   // weight of the fresh score vs. the previous risk
const LOOKBACK   = '24 hours';

// freshScore weights (each clamped contribution sums, then overall clamp 0-100)
const W_AVG_RISK    = 0.6;   // recent avg event risk → up to ~60
const W_ANOMALY     = 12;    // per severity-weighted anomaly point
const W_FAILED      = 2;     // per failed login (capped)
const FAILED_CAP    = 30;
const KNOWN_BAD_PTS = 40;    // flat bump if the entity hit a known-bad host

function log(m) {
  console.log('[' + new Date().toISOString() + '] [UEBA] ' + m);
}

function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

function safeInet(v) {
  if (v == null) return null;
  const s = String(v).replace(/\/\d+$/, '').trim();
  if (!s) return null;
  if (/^[0-9.]+$/.test(s) || s.includes(':')) return s;
  return null;
}

function isPrivateIPv4(s) {
  if (!s) return false;
  const ip = String(s).replace(/\/\d+$/, '').trim();
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

// Build factors + fresh score from one aggregated entity row.
function computeFresh(r) {
  const factors = [];
  let fresh = 0;

  const avgRisk = Number(r.avg_risk) || 0;
  const avgPts = clamp(avgRisk * W_AVG_RISK, 0, 60);
  if (avgPts > 0) { fresh += avgPts; factors.push({ label: 'Avg event risk (' + avgRisk.toFixed(0) + ')', contribution: Math.round(avgPts) }); }

  const sevWeighted = Number(r.anomaly_weighted) || 0;
  const anomPts = clamp(sevWeighted * W_ANOMALY, 0, 60);
  if (anomPts > 0) { fresh += anomPts; factors.push({ label: 'Recent anomalies (' + (Number(r.anomaly_count) || 0) + ')', contribution: Math.round(anomPts) }); }

  const failed = Number(r.failed_logins) || 0;
  const failPts = clamp(failed * W_FAILED, 0, FAILED_CAP);
  if (failPts > 0) { fresh += failPts; factors.push({ label: 'Failed logins (' + failed + ')', contribution: Math.round(failPts) }); }

  const knownBad = r.known_bad === true || (Number(r.abuse_score) || 0) >= 50;
  if (knownBad) { fresh += KNOWN_BAD_PTS; factors.push({ label: 'Known-bad host hit', contribution: KNOWN_BAD_PTS }); }

  return { fresh: clamp(Math.round(fresh), 0, 100), factors };
}

// Upsert one entity's risk with EWMA smoothing against the stored prior score.
async function upsertRisk(pool, entityType, r) {
  const { fresh, factors } = computeFresh(r);

  const prev = await pool.query(
    `SELECT risk_score FROM entity_risk WHERE entity_type = $1 AND entity_value = $2`,
    [entityType, r.entity_value]
  );
  const prior = prev.rows.length && prev.rows[0].risk_score != null
    ? Number(prev.rows[0].risk_score) : null;
  const smoothed = prior == null
    ? fresh
    : Math.round(EWMA_ALPHA * fresh + (1 - EWMA_ALPHA) * prior);

  const ip = entityType === 'user' ? null : safeInet(r.ip);

  await pool.query(
    `INSERT INTO entity_risk
       (entity_type, entity_value, source_ip, risk_score, factors,
        event_count, anomaly_count, last_activity, updated_at)
     VALUES ($1, $2, $3::inet, $4, $5::jsonb, $6, $7, $8, NOW())
     ON CONFLICT (entity_type, entity_value) DO UPDATE SET
       source_ip     = COALESCE(EXCLUDED.source_ip, entity_risk.source_ip),
       risk_score    = EXCLUDED.risk_score,
       factors       = EXCLUDED.factors,
       event_count   = EXCLUDED.event_count,
       anomaly_count = EXCLUDED.anomaly_count,
       last_activity = EXCLUDED.last_activity,
       updated_at    = NOW()`,
    [
      entityType, r.entity_value, ip, smoothed, JSON.stringify(factors),
      Number(r.event_count) || 0, Number(r.anomaly_count) || 0, r.last_activity,
    ]
  );
}

async function rollupEntityRisk(pool) {
  let processed = 0;

  // ── Devices ──
  try {
    const { rows } = await pool.query(
      `SELECT COALESCE(s.source_host, s.source_ip::text) AS entity_value,
              max(s.source_ip)::text AS ip,
              count(*)               AS event_count,
              avg(s.risk_score)::real AS avg_risk,
              count(*) FILTER (WHERE s.structured_data->>'subcategory'
                                     IN ('login_failed','auth_failed')) AS failed_logins,
              max(s.received_at)     AS last_activity,
              COALESCE(a.anomaly_count, 0)    AS anomaly_count,
              COALESCE(a.anomaly_weighted, 0) AS anomaly_weighted
       FROM syslog_entries s
       LEFT JOIN (
         SELECT entity_value,
                count(*) AS anomaly_count,
                sum(CASE severity WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END) AS anomaly_weighted
         FROM anomaly_events
         WHERE entity_type = 'device'
           AND acknowledged = FALSE
           AND detected_at > now() - ($1)::interval
         GROUP BY entity_value
       ) a ON a.entity_value = COALESCE(s.source_host, s.source_ip::text)
       WHERE s.received_at > now() - ($1)::interval
       GROUP BY 1, a.anomaly_count, a.anomaly_weighted`,
      [LOOKBACK]
    );
    for (const r of rows) {
      try { await upsertRisk(pool, 'device', r); processed++; }
      catch (e) { log('device risk upsert failed (' + r.entity_value + '): ' + e.message); }
    }
  } catch (e) {
    log('device rollup failed: ' + e.message);
  }

  // ── Users ──
  try {
    const { rows } = await pool.query(
      `SELECT s.structured_data->>'user' AS entity_value,
              NULL::text                  AS ip,
              count(*)                    AS event_count,
              avg(s.risk_score)::real     AS avg_risk,
              count(*) FILTER (WHERE s.structured_data->>'subcategory'
                                     IN ('login_failed','auth_failed')) AS failed_logins,
              max(s.received_at)          AS last_activity,
              COALESCE(a.anomaly_count, 0)    AS anomaly_count,
              COALESCE(a.anomaly_weighted, 0) AS anomaly_weighted
       FROM syslog_entries s
       LEFT JOIN (
         SELECT entity_value,
                count(*) AS anomaly_count,
                sum(CASE severity WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END) AS anomaly_weighted
         FROM anomaly_events
         WHERE entity_type = 'user'
           AND acknowledged = FALSE
           AND detected_at > now() - ($1)::interval
         GROUP BY entity_value
       ) a ON a.entity_value = s.structured_data->>'user'
       WHERE s.received_at > now() - ($1)::interval
         AND s.structured_data->>'user' IS NOT NULL
         AND btrim(s.structured_data->>'user') NOT IN ('', 'N/A')
       GROUP BY 1, a.anomaly_count, a.anomaly_weighted`,
      [LOOKBACK]
    );
    for (const r of rows) {
      try { await upsertRisk(pool, 'user', r); processed++; }
      catch (e) { log('user risk upsert failed (' + r.entity_value + '): ' + e.message); }
    }
  } catch (e) {
    log('user rollup failed: ' + e.message);
  }

  // ── External source IPs (the real attacker IP, structured_data.srcip) ──
  // Only EXTERNAL (non-private) srcip — internal hosts are already covered by the
  // device entity. Joins known_hosts for abuse_score / is_known_bad.
  try {
    const { rows } = await pool.query(
      `SELECT s.srcip AS entity_value,
              s.srcip AS ip,
              count(*) AS event_count,
              avg(s.risk_score)::real AS avg_risk,
              count(*) FILTER (WHERE s.subcategory IN ('login_failed','auth_failed')) AS failed_logins,
              max(s.received_at) AS last_activity,
              max(kh.abuse_score) AS abuse_score,
              bool_or(kh.is_known_bad) AS known_bad,
              COALESCE(a.anomaly_count, 0)    AS anomaly_count,
              COALESCE(a.anomaly_weighted, 0) AS anomaly_weighted
       FROM (
         SELECT structured_data->>'srcip' AS srcip,
                structured_data->>'subcategory' AS subcategory,
                risk_score, received_at
         FROM syslog_entries
         WHERE received_at > now() - ($1)::interval
           AND structured_data->>'srcip' IS NOT NULL
           AND btrim(structured_data->>'srcip') <> ''
       ) s
       LEFT JOIN known_hosts kh ON host(kh.ip_address) = s.srcip
       LEFT JOIN (
         SELECT entity_value,
                count(*) AS anomaly_count,
                sum(CASE severity WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END) AS anomaly_weighted
         FROM anomaly_events
         WHERE entity_type = 'srcip'
           AND acknowledged = FALSE
           AND detected_at > now() - ($1)::interval
         GROUP BY entity_value
       ) a ON a.entity_value = s.srcip
       GROUP BY s.srcip, a.anomaly_count, a.anomaly_weighted`,
      [LOOKBACK]
    );
    for (const r of rows) {
      // Skip private / non-IPv4 srcip — those are internal and not separate entities.
      if (isPrivateIPv4(r.entity_value) || !safeInet(r.entity_value)) continue;
      try { await upsertRisk(pool, 'srcip', r); processed++; }
      catch (e) { log('srcip risk upsert failed (' + r.entity_value + '): ' + e.message); }
    }
  } catch (e) {
    log('srcip rollup failed: ' + e.message);
  }

  log('rollupEntityRisk complete: ' + processed + ' entities scored');
  return { entities: processed };
}

module.exports = { rollupEntityRisk };
