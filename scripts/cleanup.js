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
  console.log(`[Cleanup] Deleting logs older than ${days} days...`);
  try {
    const result = await pool.query(
      `DELETE FROM syslog_entries WHERE received_at < NOW() - INTERVAL '${days} days'`
    );
    console.log(`[Cleanup] Deleted ${result.rowCount} rows.`);

    // Also clean up old acknowledged alert events older than 30 days
    const alerts = await pool.query(
      `DELETE FROM alert_events WHERE acknowledged = TRUE AND fired_at < NOW() - INTERVAL '30 days'`
    );
    console.log(`[Cleanup] Deleted ${alerts.rowCount} old alert events.`);
  } catch (err) {
    console.error('[Cleanup] Error:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

cleanup();