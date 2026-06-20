'use strict';

/**
 * baselineBuilder.js — LogVault Phase 2 behavioral baselining.
 *
 * Builds per-entity hour×day-of-week event-volume baselines from syslog_entries
 * and upserts them into `entity_baselines`. Two entity types:
 *   - 'device': entity_value = source_host, fallback source_ip::text
 *   - 'user'  : entity_value = structured_data->>'user' (excludes null/''/'N/A')
 *
 * Algorithm (per entity_type):
 *   1. Bucket events into per-hour counts (date_trunc('hour', received_at)) over
 *      the trailing BASELINE_DAYS, ignoring the current (partial) hour.
 *   2. Cap to the top-N entities by total volume so it scales at ~2,500 devices.
 *   3. Aggregate those hourly counts by EXTRACT(DOW)/EXTRACT(HOUR): AVG +
 *      STDDEV_SAMP + COUNT(*) (sample_count = number of distinct hours observed
 *      in that dow/hour slot). Only keep slots with >= MIN_SAMPLES history.
 *   4. Upsert into entity_baselines ON CONFLICT (entity_type,entity_value,dow,hour).
 *
 * Pure local SQL/JS — no external calls. Never throws out (wraps in try/catch +
 * console.error), matching the collector's scheduled-job contract.
 *
 * Exports: { buildBaselines }
 */

const BASELINE_DAYS = 21;     // trailing window for baseline history
const TOP_N_ENTITIES = 2500;  // cap entities per type (scales at ~2,500 devices)
const MIN_SAMPLES = 3;        // require >= N distinct hours of history per dow/hour slot

function log(m) {
  console.log('[' + new Date().toISOString() + '] [Baseline] ' + m);
}

// Shared aggregation: returns the (entity_value,dow,hour,avg,stddev,sample) rows
// for a given entity-selection SQL fragment. `entityExpr` must be a SQL scalar
// expression yielding the entity_value; `entityFilter` is an extra WHERE clause
// (may be empty). Both are STATIC strings (no user input) — safe to interpolate.
async function aggregate(pool, entityExpr, entityFilter) {
  const sql = `
    WITH hourly AS (
      SELECT ${entityExpr} AS entity_value,
             date_trunc('hour', received_at) AS hr,
             count(*) AS cnt
      FROM syslog_entries
      WHERE received_at >= now() - ($1 || ' days')::interval
        AND received_at <  date_trunc('hour', now())
        ${entityFilter}
      GROUP BY 1, 2
    ),
    topn AS (
      SELECT entity_value
      FROM hourly
      GROUP BY entity_value
      ORDER BY sum(cnt) DESC
      LIMIT $2
    )
    SELECT h.entity_value,
           EXTRACT(DOW  FROM h.hr)::int          AS dow,
           EXTRACT(HOUR FROM h.hr)::int          AS hour,
           AVG(h.cnt)::real                       AS avg_count,
           COALESCE(STDDEV_SAMP(h.cnt), 0)::real  AS stddev_count,
           COUNT(*)::int                          AS sample_count
    FROM hourly h
    JOIN topn t USING (entity_value)
    WHERE h.entity_value IS NOT NULL
    GROUP BY 1, 2, 3
    HAVING COUNT(*) >= $3
  `;
  const { rows } = await pool.query(sql, [BASELINE_DAYS, TOP_N_ENTITIES, MIN_SAMPLES]);
  return rows;
}

// Upsert one aggregated baseline row.
async function upsert(pool, entityType, r) {
  await pool.query(
    `INSERT INTO entity_baselines
       (entity_type, entity_value, dow, hour, avg_count, stddev_count, sample_count, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
     ON CONFLICT (entity_type, entity_value, dow, hour) DO UPDATE SET
       avg_count    = EXCLUDED.avg_count,
       stddev_count = EXCLUDED.stddev_count,
       sample_count = EXCLUDED.sample_count,
       updated_at   = NOW()`,
    [
      entityType,
      r.entity_value,
      r.dow,
      r.hour,
      r.avg_count != null ? Number(r.avg_count) : 0,
      r.stddev_count != null ? Number(r.stddev_count) : 0,
      Number(r.sample_count),
    ]
  );
}

async function buildBaselines(pool) {
  let upserted = 0;

  // ── Devices: source_host, fallback to source_ip::text ──
  try {
    const rows = await aggregate(pool, `COALESCE(source_host, source_ip::text)`, ``);
    for (const r of rows) {
      try { await upsert(pool, 'device', r); upserted++; }
      catch (e) { log('device upsert failed (' + r.entity_value + '): ' + e.message); }
    }
    log('device baselines: ' + rows.length + ' slots aggregated');
  } catch (e) {
    log('device aggregation failed: ' + e.message);
  }

  // ── Users: structured_data->>'user', excluding null/''/'N/A' ──
  try {
    const rows = await aggregate(
      pool,
      `structured_data->>'user'`,
      `AND structured_data->>'user' IS NOT NULL
       AND btrim(structured_data->>'user') NOT IN ('', 'N/A')`
    );
    for (const r of rows) {
      try { await upsert(pool, 'user', r); upserted++; }
      catch (e) { log('user upsert failed (' + r.entity_value + '): ' + e.message); }
    }
    log('user baselines: ' + rows.length + ' slots aggregated');
  } catch (e) {
    log('user aggregation failed: ' + e.message);
  }

  log('buildBaselines complete: ' + upserted + ' baseline rows upserted');
  return { baselines: upserted };
}

module.exports = { buildBaselines };
