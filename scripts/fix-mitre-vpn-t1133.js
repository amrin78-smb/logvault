/**
 * One-off corrective: strip the over-broad event-level T1133 tag.
 *
 * Earlier mitreMapper.js tagged EVERY VPN-category/subtype event as T1133
 * (External Remote Services), which labelled routine IPsec negotiate / SSL-alert
 * traffic as a technique and drowned the ATT&CK Coverage view in benign VPN volume.
 * mitreMapper.js no longer tags T1133 at the event level (it remains only on the
 * VPN_BRUTE_FORCE correlation rule). This script removes T1133 from the rows the
 * old logic / backfill already tagged:
 *   - if other techniques remain, keep them (mitre = remaining array)
 *   - if T1133 was the only one, drop the 'mitre' key entirely (matches the
 *     collector, which omits an empty array)
 *
 *   node scripts/fix-mitre-vpn-t1133.js
 *
 * MUST run as postgres (syslog_entries is append-only for logvault_user). Uses
 * POSTGRES_PASSWORD from .env.local. Idempotent and safe to re-run: it only
 * touches rows whose structured_data.mitre still contains T1133 (GIN-indexed
 * containment), so cleaned rows drop out of scope immediately.
 */
'use strict';

const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const pool = new Pool({
  host:     process.env.DB_HOST    || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME || 'logvault',
  user:     'postgres',
  password: process.env.POSTGRES_PASSWORD,
  max:      5,
});

const BATCH = 1000;

async function run() {
  if (!process.env.POSTGRES_PASSWORD) {
    console.error('[FixT1133] POSTGRES_PASSWORD is not set (.env.local) — this script must run as postgres.');
    process.exit(1);
  }
  console.log(`[FixT1133] Removing event-level T1133 tags (batches of ${BATCH})...`);

  let scanned = 0, cleared = 0, dropped = 0, lastId = 0, nextLog = 10000;
  for (;;) {
    // GIN-indexed containment finds the rows still carrying T1133; the id cursor
    // walks forward. Cleaned rows no longer match @> so the scope shrinks each pass.
    const { rows } = await pool.query(
      `SELECT id, structured_data->'mitre' AS mitre
         FROM syslog_entries
        WHERE structured_data @> '{"mitre":["T1133"]}'::jsonb
          AND id > $1
        ORDER BY id
        LIMIT $2`,
      [lastId, BATCH]
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;
    scanned += rows.length;

    // Build [{ id, mitre: [...] | null }]: remaining techniques, or null to drop the key.
    const payload = rows.map(r => {
      const remaining = (Array.isArray(r.mitre) ? r.mitre : []).filter(t => t !== 'T1133');
      if (remaining.length) cleared++; else dropped++;
      return { id: String(r.id), mitre: remaining.length ? remaining : null };
    });

    await pool.query(
      `UPDATE syslog_entries s
          SET structured_data = CASE
                WHEN x.mitre = 'null'::jsonb THEN s.structured_data - 'mitre'
                ELSE jsonb_set(s.structured_data, '{mitre}', x.mitre)
              END
         FROM (
           SELECT (e->>'id')::bigint AS id, e->'mitre' AS mitre
             FROM jsonb_array_elements($1::jsonb) AS e
         ) x
        WHERE s.id = x.id
          AND s.structured_data @> '{"mitre":["T1133"]}'::jsonb`,
      [JSON.stringify(payload)]
    );

    if (scanned >= nextLog) {
      console.log(`[FixT1133] Processed ${scanned} rows (${cleared} kept other techniques, ${dropped} dropped 'mitre')...`);
      nextLog += 10000;
    }
  }

  console.log(`[FixT1133] Done. Processed ${scanned} rows: ${cleared} retained other techniques, ${dropped} had 'mitre' removed.`);
  await pool.end();
}

run().catch(err => {
  console.error('[FixT1133] Error:', err.message);
  process.exit(1);
});
