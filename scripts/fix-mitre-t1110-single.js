/**
 * One-off corrective: strip the over-broad event-level T1110 tag from
 * single failed-login events.
 *
 * Earlier mitreMapper.js tagged EVERY auth failure (a lone FortiOS
 * action=ssl-login-fail, a generic "login failed" / "authentication failure")
 * as T1110 Brute Force, which slapped a "Brute Force" badge on routine one-off
 * failures and drowned out real signal. mitreMapper.js no longer tags T1110 at
 * the event level for a single failure — brute force is now determined at the
 * correlation altitude (BRUTE_FORCE_SUCCESS / VPN_BRUTE_FORCE in
 * collector/correlationEngine.js MITRE_BY_RULE). Event-level T1110 is kept ONLY
 * when a SINGLE message itself attests repetition/lockout (an already-correlated
 * signal: "account locked", "password spray", "repeated|multiple|N failed"
 * attempts) or the pre-correlated subcategory === 'brute_force'. This mirrors
 * the T1133 decision (see scripts/fix-mitre-vpn-t1133.js).
 *
 * This script removes T1110 from rows the old logic / backfill already tagged
 * that do NOT meet the new repetition/lockout criteria:
 *   - if other techniques remain, keep them (mitre = remaining array)
 *   - if T1110 was the only one, drop the 'mitre' key entirely (matches the
 *     collector, which omits an empty array)
 * Rows that DO attest repetition/lockout keep T1110 untouched.
 *
 *   node scripts/fix-mitre-t1110-single.js          # dry run (default) — reports only
 *   node scripts/fix-mitre-t1110-single.js --run    # apply the changes
 *
 * MUST run as postgres (syslog_entries is append-only for logvault_user). Uses
 * POSTGRES_PASSWORD from .env.local. Idempotent and safe to re-run: it only
 * touches rows whose structured_data.mitre still contains T1110 (GIN-indexed
 * containment) that fail the repetition/lockout test, so cleaned rows drop out
 * of scope immediately.
 */
'use strict';

const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const APPLY = process.argv.includes('--run');

const pool = new Pool({
  host:     process.env.DB_HOST    || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME || 'logvault',
  user:     'postgres',
  password: process.env.POSTGRES_PASSWORD,
  max:      5,
});

const BATCH = 1000;

// Mirrors collector/mitreMapper.js: event-level T1110 is legitimate ONLY when the
// row's subcategory is the pre-correlated 'brute_force', OR the message itself
// attests repetition/lockout. Anything else carrying T1110 is a single-failure
// mistag and should be stripped.
const REPETITION_RE = /brute.?force|password\s*spray|account.?lock(?:ed|out)?|(?:repeated|multiple|consecutive|\d+)\s+(?:failed|invalid)\s+(?:login|logon|auth|password|sign)/i;

function attestsRepetition(row) {
  const s   = (row && row.structured_data) || {};
  const sub = String(s.subcategory || '').toLowerCase();
  const msg = (row && row.message) || '';
  return sub === 'brute_force' || REPETITION_RE.test(msg);
}

async function run() {
  if (!process.env.POSTGRES_PASSWORD) {
    console.error('[FixT1110] POSTGRES_PASSWORD is not set (.env.local) — this script must run as postgres.');
    process.exit(1);
  }
  console.log(`[FixT1110] ${APPLY ? 'APPLYING' : 'DRY RUN'} — removing event-level T1110 tags from single-failure events (batches of ${BATCH}).`);
  if (!APPLY) console.log('[FixT1110] No changes will be written. Re-run with --run to apply.');

  let scanned = 0, kept = 0, cleared = 0, dropped = 0, lastId = 0, nextLog = 10000;
  for (;;) {
    // GIN-indexed containment finds the rows still carrying T1110; the id cursor
    // walks forward. We need message + subcategory to apply the repetition test.
    const { rows } = await pool.query(
      `SELECT id,
              structured_data->'mitre' AS mitre,
              structured_data         AS structured_data,
              message
         FROM syslog_entries
        WHERE structured_data @> '{"mitre":["T1110"]}'::jsonb
          AND id > $1
        ORDER BY id
        LIMIT $2`,
      [lastId, BATCH]
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;
    scanned += rows.length;

    // Only rows that do NOT attest repetition/lockout are mistags to strip.
    const toFix = rows.filter(r => !attestsRepetition(r));
    kept += rows.length - toFix.length;

    // Build [{ id, mitre: [...] | null }]: remaining techniques, or null to drop the key.
    const payload = toFix.map(r => {
      const remaining = (Array.isArray(r.mitre) ? r.mitre : []).filter(t => t !== 'T1110');
      if (remaining.length) cleared++; else dropped++;
      return { id: String(r.id), mitre: remaining.length ? remaining : null };
    });

    if (APPLY && payload.length) {
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
            AND s.structured_data @> '{"mitre":["T1110"]}'::jsonb`,
        [JSON.stringify(payload)]
      );
    }

    if (scanned >= nextLog) {
      console.log(`[FixT1110] Processed ${scanned} rows (${kept} kept T1110 [real repetition], ${cleared} kept other techniques, ${dropped} would drop 'mitre')...`);
      nextLog += 10000;
    }
  }

  const verb = APPLY ? 'had' : 'would have';
  console.log(`[FixT1110] Done. Processed ${scanned} rows: ${kept} kept T1110 (real repetition/lockout), ${cleared} ${verb} T1110 stripped (other techniques retained), ${dropped} ${verb} 'mitre' removed.`);
  if (!APPLY && (cleared + dropped) > 0) console.log('[FixT1110] DRY RUN — re-run with --run to apply these changes.');
  await pool.end();
}

run().catch(err => {
  console.error('[FixT1110] Error:', err.message);
  process.exit(1);
});
