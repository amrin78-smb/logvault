/**
 * One-time backfill for the srcip perf pass (2026-07):
 *
 *   (a) Backfills the new syslog_entries.srcip column on existing rows —
 *       ~5.8M rows, batched by DAY (the table is partitioned daily,
 *       syslog_entries_pYYYYMMDD, so a day-scoped UPDATE naturally stays
 *       within one partition's lock scope; never one giant UPDATE across
 *       the whole table).
 *   (b) Backfills syslog_stats_rollup + syslog_talker_rollup for every hour
 *       in the same window, using the EXACT same DELETE+INSERT-per-bucket
 *       logic as the live collector job (collector/collector.js's
 *       runRollupMaintenance / recomputeRollupBucket), just looped across
 *       every hour instead of only the current+previous hour.
 *
 * (b) for a given day always runs AFTER (a) for that same day, so srcip is
 * populated before that day's talker rollup reads it.
 *
 * Both halves are idempotent (safe to re-run):
 *   - (a) only touches rows where srcip IS NULL.
 *   - (b) DELETEs a bucket before re-INSERTing it, so a re-run recomputes
 *     the same numbers rather than double-counting.
 *
 * MUST run as the postgres superuser — syslog_entries is append-only for
 * logvault_user (UPDATE/DELETE revoked for tamper prevention, Phase 3), so
 * (a)'s UPDATE would fail as logvault_user. Connects with POSTGRES_PASSWORD
 * from .env.local, same privileged role the update script + the other
 * scripts/backfill-*.js maintenance scripts use.
 *
 *   node scripts/backfill-rollups.js
 *
 * Window is the last 30 days by default; override with BACKFILL_DAYS.
 */
'use strict';

const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const DAYS       = parseInt(process.env.BACKFILL_DAYS || '30', 10);
const DAY_MS     = 24 * 60 * 60 * 1000;
const HOUR_MS    = 60 * 60 * 1000;
const DAY_DELAY_MS = 300; // brief pause between day-batches — avoid hammering I/O on a live server

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// (a) Backfill srcip for one day (oldest→newest caller loop), one UPDATE per
// day so the lock scope stays within that day's partition.
async function backfillSrcipForDay(pool, dayStart) {
  const res = await pool.query(
    `UPDATE syslog_entries
        SET srcip = COALESCE(NULLIF(btrim(structured_data->>'srcip'), ''), host(source_ip))
      WHERE received_at >= $1 AND received_at < $1 + interval '1 day'
        AND srcip IS NULL`,
    [dayStart]
  );
  return res.rowCount;
}

// (b) Recompute both rollup tables for ONE hour bucket. Same shape as the
// live collector's recomputeRollupBucket — DELETE then INSERT...SELECT,
// site_id resolved via known_hosts.ip_address = source_ip (the relay, NOT
// srcip) in both tables, matching getStatsSiteFilter()'s RBAC semantics.
async function backfillRollupForHour(pool, hourBucket) {
  await pool.query(`DELETE FROM syslog_stats_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_stats_rollup (hour_bucket, severity, severity_label, category, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at), se.severity, se.severity_label,
           COALESCE(se.category, 'uncategorized'), se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
    GROUP BY 1, 2, 3, 4, 5, 6
  `, [hourBucket]);

  await pool.query(`DELETE FROM syslog_talker_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_talker_rollup (hour_bucket, srcip, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at),
           COALESCE(se.srcip, host(se.source_ip)) AS srcip,
           se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
    GROUP BY 1, 2, 3, 4
  `, [hourBucket]);
}

// Runs the full two-phase backfill against the supplied pool. Does NOT
// create or close the pool — callers (the CLI entrypoint below) own that.
async function runBackfill(pool) {
  const now        = new Date();
  const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

  // Oldest → newest day boundaries covering the last DAYS days (today included).
  const dayStarts = [];
  for (let i = DAYS - 1; i >= 0; i--) {
    dayStarts.push(new Date(todayStart.getTime() - i * DAY_MS));
  }

  console.log(`[Backfill] Starting srcip + rollup backfill for the last ${DAYS} days (${dayStarts.length} days, ${dayStarts.length * 24} hours).`);

  let totalSrcipRows = 0;
  let hoursDone = 0;
  const totalHours = dayStarts.length * 24;

  for (const dayStart of dayStarts) {
    const dayLabel = dayStart.toISOString().slice(0, 10);

    // (a) srcip for this day FIRST, so (b)'s talker rollup for this day reads populated srcip.
    const rowsUpdated = await backfillSrcipForDay(pool, dayStart);
    totalSrcipRows += rowsUpdated;
    console.log(`[Backfill] srcip — ${dayLabel}: ${rowsUpdated} rows updated (running total ${totalSrcipRows}).`);

    // (b) 24 hourly rollup buckets for this day.
    for (let h = 0; h < 24; h++) {
      const hourBucket = new Date(dayStart.getTime() + h * HOUR_MS);
      await backfillRollupForHour(pool, hourBucket);
      hoursDone++;
      if (hoursDone % 24 === 0 || hoursDone === totalHours) {
        console.log(`[Backfill] rollups — hour ${hoursDone} of ${totalHours} (${hourBucket.toISOString()}).`);
      }
    }

    await sleep(DAY_DELAY_MS);
  }

  console.log(`[Backfill] Done. srcip rows updated: ${totalSrcipRows}. Rollup hours recomputed: ${hoursDone} of ${totalHours}.`);
}

module.exports = { runBackfill, backfillSrcipForDay, backfillRollupForHour };

// CLI entrypoint — only runs when invoked directly (node scripts/backfill-rollups.js).
// Owns its own pool + process exit code, mirroring scripts/cleanup.js.
if (require.main === module) {
  if (!process.env.POSTGRES_PASSWORD) {
    console.error('[Backfill] POSTGRES_PASSWORD is not set (.env.local) — this script must run as postgres.');
    process.exit(1);
  }

  const pool = new Pool({
    host:     process.env.DB_HOST    || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.LV_DB_NAME || 'logvault',
    user:     'postgres',                       // privileged role — logvault_user can't UPDATE syslog_entries
    password: process.env.POSTGRES_PASSWORD,
    max:      5,
  });

  runBackfill(pool)
    .catch((err) => { console.error('[Backfill] Error:', err.message); process.exitCode = 1; })
    .finally(() => pool.end());
}
