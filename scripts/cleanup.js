'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
const { Pool } = require('pg');

// Days of partitions to pre-create ahead of "today" so an INSERT always lands
// in a real daily partition rather than the DEFAULT catch-all.
const PARTITION_DAYS_AHEAD = 7;

// Run retention + partition maintenance against the supplied pool.
// Does NOT create or close the pool and NEVER calls process.exit, so it is safe
// to call in-process from the collector (which schedules it daily) as well as
// from the CLI entrypoint below. Throws on error — callers decide what to do.
async function runCleanup(pool) {
  const days = parseInt(process.env.RETENTION_DAYS || '30', 10);
  console.log(`[Cleanup] Starting — retention: ${days} days`);

  // 1. syslog_entries is time-partitioned (daily). Retention is enforced by
  //    dropping whole old partitions, NOT by row DELETE (DELETE on
  //    syslog_entries is revoked from logvault_user for tamper prevention).
  //    First make sure upcoming partitions exist, then drop the expired ones.
  const ensured = await pool.query(
    `SELECT ensure_syslog_partitions($1) AS n`,
    [PARTITION_DAYS_AHEAD]
  );
  console.log(`[Cleanup] Ensured partitions — created ${ensured.rows[0].n} new (up to ${PARTITION_DAYS_AHEAD} days ahead)`);

  const dropped = await pool.query(
    `SELECT drop_old_syslog_partitions($1) AS n`,
    [days]
  );
  console.log(`[Cleanup] Dropped ${dropped.rows[0].n} partitions older than ${days} days`);

  // 2. Auto-acknowledge alerts older than 7 days
  const autoAck = await pool.query(
    `UPDATE alert_events SET acknowledged = TRUE, acknowledged_at = NOW()
     WHERE acknowledged = FALSE AND fired_at < NOW() - INTERVAL '7 days'`
  );
  console.log(`[Cleanup] Auto-acknowledged ${autoAck.rowCount} alerts older than 7 days`);

  // 3. Delete acknowledged alert events older than 30 days
  const alerts = await pool.query(
    `DELETE FROM alert_events WHERE acknowledged = TRUE AND fired_at < NOW() - INTERVAL '30 days'`
  );
  console.log(`[Cleanup] Deleted ${alerts.rowCount} old acknowledged alert events`);

  console.log('[Cleanup] Done.');
}

module.exports = { runCleanup };

// CLI entrypoint — only runs when invoked directly (node scripts/cleanup.js),
// not when required by the collector. Owns its own pool + process exit code.
if (require.main === module) {
  const pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.LV_DB_NAME  || 'logvault',
    user:     process.env.LV_DB_USER  || 'logvault_user',
    password: process.env.LV_DB_PASS,
  });
  runCleanup(pool)
    .catch((err) => { console.error('[Cleanup] Error:', err.message); process.exitCode = 1; })
    .finally(() => pool.end());
}
