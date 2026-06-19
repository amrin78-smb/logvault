/**
 * One-off backfill: tag recent syslog_entries with MITRE ATT&CK techniques.
 *
 * The collector tags new entries at ingest (collector/mitreMapper.js writes
 * structured_data.mitre). This script applies the SAME tagging logic to rows
 * that predate the feature so the ATT&CK Coverage view and the Log Explorer
 * technique filter have history to show immediately after deploy.
 *
 *   node scripts/backfill-mitre-tags.js
 *
 * MUST run as the postgres superuser. syslog_entries is append-only for
 * logvault_user (UPDATE/DELETE revoked for tamper prevention, Phase 3), so this
 * UPDATE will fail as logvault_user. It connects with POSTGRES_PASSWORD from
 * .env.local — the same privileged role the update script uses to apply schema.
 *
 * Safe to re-run (idempotent): only rows that do NOT already have a 'mitre' key
 * in structured_data are processed, and the UPDATE re-checks that key, so it
 * never overwrites collector-written tags. Only rows that actually map to a
 * technique get the key (matching the collector, which omits empty arrays);
 * no-technique rows are left untouched (re-scanned cheaply on any re-run).
 *
 * Range is the last 30 days by default; override with BACKFILL_DAYS.
 */
'use strict';

const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const { mapTechniques } = require('../collector/mitreMapper');

const pool = new Pool({
  host:     process.env.DB_HOST    || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME || 'logvault',
  user:     'postgres',                       // privileged role — logvault_user can't UPDATE
  password: process.env.POSTGRES_PASSWORD,
  max:      5,
});

const BATCH = 1000;
const DAYS  = parseInt(process.env.BACKFILL_DAYS || '30');

async function run() {
  if (!process.env.POSTGRES_PASSWORD) {
    console.error('[Backfill] POSTGRES_PASSWORD is not set (.env.local) — this script must run as postgres.');
    process.exit(1);
  }
  console.log(`[Backfill] Tagging MITRE techniques on syslog_entries from the last ${DAYS} days (batches of ${BATCH})...`);

  let scanned = 0, tagged = 0, lastId = 0, nextLog = 10000;
  for (;;) {
    // Cursor on id (globally unique). The received_at bound prunes partitions; the
    // "no mitre key yet" guard makes the scan idempotent across re-runs.
    const { rows } = await pool.query(
      `SELECT id, vendor, message, category, structured_data
         FROM syslog_entries
        WHERE received_at > NOW() - make_interval(days => $1)
          AND id > $2
          AND NOT (structured_data ? 'mitre')
        ORDER BY id
        LIMIT $3`,
      [DAYS, lastId, BATCH]
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;
    scanned += rows.length;

    // Build [{ id, mitre: [...] }] for only the rows that map to >=1 technique,
    // mirroring the collector (which omits an empty mitre array).
    const patch = [];
    for (const r of rows) {
      const entry = { vendor: r.vendor, message: r.message, category: r.category, structured_data: r.structured_data || {} };
      const ids = mapTechniques(entry);
      if (ids.length) patch.push({ id: String(r.id), mitre: ids });
    }

    if (patch.length) {
      const res = await pool.query(
        `UPDATE syslog_entries s
            SET structured_data = s.structured_data || jsonb_build_object('mitre', x.mitre)
           FROM (
             SELECT (e->>'id')::bigint AS id, e->'mitre' AS mitre
               FROM jsonb_array_elements($1::jsonb) AS e
           ) x
          WHERE s.id = x.id
            AND NOT (s.structured_data ? 'mitre')`,
        [JSON.stringify(patch)]
      );
      tagged += res.rowCount;
    }

    if (scanned >= nextLog) {
      console.log(`[Backfill] Scanned ${scanned} rows, tagged ${tagged} with techniques...`);
      nextLog += 10000;
    }
  }

  console.log(`[Backfill] Done. Scanned ${scanned} rows, tagged ${tagged} with MITRE techniques.`);
  await pool.end();
}

run().catch(err => {
  console.error('[Backfill] Error:', err.message);
  process.exit(1);
});
