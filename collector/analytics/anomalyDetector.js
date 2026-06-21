'use strict';

/**
 * anomalyDetector.js — LogVault Phase 2 anomaly detection.
 *
 * Compares recent activity against the learned `entity_baselines` and records
 * anomalies into `anomaly_events`. Pure local SQL/JS — no external calls. Each
 * check is isolated in its own try/catch so one failure never aborts the rest,
 * and the function never throws out (collector scheduled-job contract).
 *
 * Checks:
 *   - VOLUME (volume_spike): for the CURRENT dow/hour bucket, compare the last
 *     completed hour's event count per entity to baseline avg + k*stddev
 *     (k=3 → warning, k=4 → critical), with an absolute floor (ignore baselines
 *     whose avg < MIN_BASELINE_AVG so tiny/noisy entities don't fire).
 *   - SILENT (silent): baseline avg is high (>= SILENT_MIN_AVG) for the current
 *     bucket but the last completed hour's count is ~0.
 *   - NEW_GEO (new_geo): a structured_data->>'srccountry' seen in the last hour
 *     for a user/device that did NOT appear in the prior 30 days (anti-join).
 *   - NEW_SERVICE (new_service): same anti-join pattern on structured_data->>'service'.
 *
 * Dedup: recordAnomaly() skips if an UNacknowledged anomaly of the same
 * entity_type + entity_value + anomaly_type exists within the last hour.
 *
 * source_ip is set for device/IP entities (the entity's IP), NULL for users.
 *
 * Exports: { detectAnomalies, recordAnomaly }
 */

const { RELAY_HOSTS } = require('./relayHosts');

const MIN_BASELINE_AVG = 10;  // ignore baselines quieter than this (absolute floor)
const SILENT_MIN_AVG   = 50;  // only flag 'silent' when the entity is normally busy
const K_WARNING        = 3;   // z-score for 'warning'
const K_CRITICAL       = 4;   // z-score for 'critical'

function log(m) {
  console.log('[' + new Date().toISOString() + '] [Anomaly] ' + m);
}

// Coerce an entity's IP-ish string into a value safe to bind as ::inet, or null.
// Strips any CIDR suffix; returns null for empty / obviously-non-IP values so the
// INSERT never fails on a bad inet literal.
function safeInet(v) {
  if (v == null) return null;
  const s = String(v).replace(/\/\d+$/, '').trim();
  if (!s) return null;
  // Accept IPv4 or anything containing ':' (IPv6) — Postgres validates on cast;
  // we only pre-filter clearly-empty values here. A bad literal is caught by the
  // try/catch around the INSERT and stored as NULL instead.
  if (/^[0-9.]+$/.test(s) || s.includes(':')) return s;
  return null;
}

/**
 * recordAnomaly — dedup + insert. Returns the inserted row, or null if deduped
 * or on a (logged) failure. Dedup window: 60 minutes, same entity_type +
 * entity_value + anomaly_type, only against UNacknowledged rows.
 */
async function recordAnomaly(pool, a) {
  const {
    entityType, entityValue, sourceIp = null,
    anomalyType, severity, score = 0, title, detail = {},
  } = a;
  try {
    const dup = await pool.query(
      `SELECT 1 FROM anomaly_events
        WHERE entity_type = $1
          AND entity_value = $2
          AND anomaly_type = $3
          AND acknowledged = FALSE
          AND detected_at > NOW() - INTERVAL '60 minutes'
        LIMIT 1`,
      [entityType, entityValue, anomalyType]
    );
    if (dup.rows.length > 0) return null;

    const ip = safeInet(sourceIp);
    let ins;
    try {
      ins = await pool.query(
        `INSERT INTO anomaly_events
           (detected_at, entity_type, entity_value, source_ip, anomaly_type,
            severity, score, title, detail, acknowledged)
         VALUES (NOW(), $1, $2, $3::inet, $4, $5, $6, $7, $8::jsonb, FALSE)
         RETURNING id`,
        [entityType, entityValue, ip, anomalyType, severity,
         Number(score) || 0, title, JSON.stringify(detail || {})]
      );
    } catch (e) {
      // Most likely a bad inet literal — retry once with NULL source_ip.
      ins = await pool.query(
        `INSERT INTO anomaly_events
           (detected_at, entity_type, entity_value, source_ip, anomaly_type,
            severity, score, title, detail, acknowledged)
         VALUES (NOW(), $1, $2, NULL, $3, $4, $5, $6, $7::jsonb, FALSE)
         RETURNING id`,
        [entityType, entityValue, anomalyType, severity,
         Number(score) || 0, title, JSON.stringify(detail || {})]
      );
    }
    return ins.rows[0];
  } catch (e) {
    log('recordAnomaly failed (' + anomalyType + '/' + entityValue + '): ' + e.message);
    return null;
  }
}

// ── VOLUME + SILENT ─────────────────────────────────────────────
// For the CURRENT dow/hour, join the last completed hour's per-entity counts to
// the matching baseline. One query per entity_type (device/user) so the entity
// expression + IP column differ cleanly.
async function detectVolume(pool, summary) {
  const variants = [
    {
      entityType:  'device',
      entityExpr:  `COALESCE(source_host, source_ip::text)`,
      ipExpr:      `max(source_ip)::text`,
      filter:      ``,
      // exclude the relay/log-source from the driving baseline set (defence in
      // depth: relay baselines are also removed at build + cleanup time)
      relayClause: `AND lower(b.entity_value) <> ALL($3::text[])`,
      relay:       true,
    },
    {
      entityType:  'user',
      entityExpr:  `structured_data->>'user'`,
      ipExpr:      `NULL::text`,
      filter:      `AND structured_data->>'user' IS NOT NULL
                   AND btrim(structured_data->>'user') NOT IN ('', 'N/A')`,
      relayClause: ``,
      relay:       false,
    },
  ];

  for (const v of variants) {
    try {
      // Last completed hour's counts for entities that HAVE a baseline for the
      // current dow/hour. RIGHT-style: drive from baselines so 'silent' entities
      // (zero recent rows) still surface via the LEFT JOIN.
      const sql = `
        WITH recent AS (
          SELECT ${v.entityExpr} AS entity_value,
                 ${v.ipExpr}     AS ip,
                 count(*)        AS observed
          FROM syslog_entries
          WHERE received_at >= date_trunc('hour', now()) - interval '1 hour'
            AND received_at <  date_trunc('hour', now())
            ${v.filter}
          GROUP BY 1
        )
        SELECT b.entity_value,
               b.avg_count, b.stddev_count, b.sample_count,
               COALESCE(r.observed, 0) AS observed,
               r.ip
        FROM entity_baselines b
        LEFT JOIN recent r ON r.entity_value = b.entity_value
        WHERE b.entity_type = $1
          AND b.dow  = EXTRACT(DOW  FROM now())::int
          AND b.hour = EXTRACT(HOUR FROM now())::int
          AND b.avg_count >= $2
          ${v.relayClause}
      `;
      const params = [v.entityType, MIN_BASELINE_AVG];
      if (v.relay) params.push(RELAY_HOSTS);
      const { rows } = await pool.query(sql, params);

      for (const r of rows) {
        const observed = Number(r.observed);
        const avg      = Number(r.avg_count);
        const stddev   = Number(r.stddev_count);
        if (!Number.isFinite(observed) || !Number.isFinite(avg)) continue;

        const warnThresh = avg + K_WARNING  * stddev;
        const critThresh = avg + K_CRITICAL * stddev;

        // VOLUME SPIKE — needs a real spike above the warning threshold AND a
        // meaningful absolute jump so near-zero-stddev baselines don't fire on
        // a few extra events.
        if (observed > warnThresh && observed - avg >= MIN_BASELINE_AVG) {
          const severity = observed > critThresh ? 'critical' : 'warning';
          const score = stddev > 0
            ? Math.min(100, Math.round(((observed - avg) / stddev) * 10))
            : 60;
          const res = await recordAnomaly(pool, {
            entityType:  v.entityType,
            entityValue: r.entity_value,
            sourceIp:    v.entityType === 'device' ? r.ip : null,
            anomalyType: 'volume_spike',
            severity,
            score,
            title: 'Volume spike: ' + v.entityType + ' ' + r.entity_value +
                   ' — ' + observed + ' events (expected ~' + avg.toFixed(0) + ')',
            detail: {
              observed, expected: avg, stddev,
              sample_count: Number(r.sample_count),
              threshold_warning: warnThresh, threshold_critical: critThresh,
            },
          });
          if (res) summary.volume_spike++;
          continue;
        }

        // SILENT — a normally-busy entity has gone (near) quiet this hour.
        if (avg >= SILENT_MIN_AVG && observed <= Math.max(1, avg * 0.02)) {
          const res = await recordAnomaly(pool, {
            entityType:  v.entityType,
            entityValue: r.entity_value,
            sourceIp:    v.entityType === 'device' ? r.ip : null,
            anomalyType: 'silent',
            severity:    'warning',
            score:       50,
            title: 'Silent entity: ' + v.entityType + ' ' + r.entity_value +
                   ' — ' + observed + ' events (expected ~' + avg.toFixed(0) + ')',
            detail: { observed, expected: avg, stddev, sample_count: Number(r.sample_count) },
          });
          if (res) summary.silent++;
        }
      }
    } catch (e) {
      log('volume/silent (' + v.entityType + ') failed: ' + e.message);
    }
  }
}

// ── NEW_GEO / NEW_SERVICE anti-join ─────────────────────────────
// Per entity_type, a field value seen in the last hour that did NOT appear in
// the prior 30 days. One generic helper for both srccountry and service.
async function detectNewField(pool, summary, field, anomalyType, label) {
  // entityExpr     — yields entity_value over the un-aliased syslog_entries
  // priorEntityExpr — the SAME expression qualified for the `p` alias in the anti-join
  const variants = [
    {
      entityType:      'device',
      entityExpr:      `COALESCE(source_host, source_ip::text)`,
      priorEntityExpr: `COALESCE(p.source_host, p.source_ip::text)`,
      ipExpr:          `source_ip::text`,
      // exclude the relay/log-source so it never produces new_geo/new_service
      filter:          `AND lower(COALESCE(source_host, source_ip::text)) <> ALL($1::text[])`,
      relay:           true,
    },
    {
      entityType:      'user',
      entityExpr:      `structured_data->>'user'`,
      priorEntityExpr: `p.structured_data->>'user'`,
      ipExpr:          `NULL::text`,
      filter:          `AND structured_data->>'user' IS NOT NULL
                        AND btrim(structured_data->>'user') NOT IN ('', 'N/A')`,
      relay:           false,
    },
  ];

  for (const v of variants) {
    try {
      const sql = `
        WITH recent AS (
          SELECT DISTINCT
                 ${v.entityExpr}                       AS entity_value,
                 structured_data->>'${field}'          AS fval,
                 ${v.ipExpr}                           AS ip
          FROM syslog_entries
          WHERE received_at > now() - interval '1 hour'
            AND structured_data->>'${field}' IS NOT NULL
            AND btrim(structured_data->>'${field}') NOT IN ('', 'N/A')
            ${v.filter}
        )
        SELECT r.entity_value, r.fval, r.ip
        FROM recent r
        WHERE r.entity_value IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM syslog_entries p
            WHERE p.received_at > now() - interval '30 days'
              AND p.received_at < now() - interval '1 hour'
              AND ${v.priorEntityExpr} = r.entity_value
              AND p.structured_data->>'${field}' = r.fval
          )
        LIMIT 500
      `;
      const { rows } = await pool.query(sql, v.relay ? [RELAY_HOSTS] : []);
      for (const r of rows) {
        const res = await recordAnomaly(pool, {
          entityType:  v.entityType,
          entityValue: r.entity_value,
          sourceIp:    v.entityType === 'device' ? r.ip : null,
          anomalyType,
          severity:    'info',
          score:       30,
          title: label + ': ' + v.entityType + ' ' + r.entity_value +
                 ' — first ' + label.toLowerCase() + ' "' + r.fval + '" in 30 days',
          detail: { [field]: r.fval },
        });
        if (res) summary[anomalyType]++;
      }
    } catch (e) {
      log(anomalyType + ' (' + v.entityType + ') failed: ' + e.message);
    }
  }
}

async function detectAnomalies(pool) {
  const summary = { volume_spike: 0, silent: 0, new_geo: 0, new_service: 0 };

  await detectVolume(pool, summary);
  await detectNewField(pool, summary, 'srccountry', 'new_geo', 'New geo');
  await detectNewField(pool, summary, 'service', 'new_service', 'New service');

  log('detectAnomalies complete: ' +
      Object.entries(summary).map(([k, v]) => k + '=' + v).join(' '));
  return summary;
}

module.exports = { detectAnomalies, recordAnomaly };
