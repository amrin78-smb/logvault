'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME  || 'logvault',
  user:     process.env.LV_DB_USER  || 'logvault_user',
  password: process.env.LV_DB_PASS,
});

async function cleanup() {
  const days = parseInt(process.env.RETENTION_DAYS || '30');
  console.log(`[Cleanup] Starting — retention: ${days} days`);

  try {
    // 1. Delete old syslog entries
    const logs = await pool.query(
      `DELETE FROM syslog_entries WHERE received_at < NOW() - INTERVAL '${days} days'`
    );
    console.log(`[Cleanup] Deleted ${logs.rowCount} log rows older than ${days} days`);

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
  } catch (err) {
    console.error('[Cleanup] Error:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

cleanup();
