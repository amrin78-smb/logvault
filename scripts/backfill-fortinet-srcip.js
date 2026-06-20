/**
 * One-time backfill: recover the real remote source IP / user / country for
 * pre-fix historical Fortinet events.
 *
 * Before the Fortinet parser learned to surface the remote-client fields
 * (remip -> srcip, plus user/srccountry/reason/logdesc etc.), ~1,200 SSL-VPN /
 * auth rows were ingested with `remip=` in raw_message but NO `srcip` in
 * structured_data. As a result historical slide-in detail + CSV export show the
 * reporting firewall instead of the real remote user/attacker, and they don't
 * match rows ingested after the fix.
 *
 * This script re-parses each affected row's raw_message through the CURRENT
 * Fortinet parser (parsers/fortinet.js — the exact same code live ingestion
 * uses) and MERGES the recovered normalized fields back into the existing
 * structured_data. It is purely ADDITIVE:
 *   - it only fills keys that are currently null/undefined,
 *   - it never overwrites an existing non-null value,
 *   - it never removes existing keys (mitre, category, etc. are preserved).
 * If a row would not change, it is skipped, so the script is idempotent and safe
 * to re-run (rows that already have srcip are excluded by the WHERE clause).
 *
 * MUST run as postgres (syslog_entries is append-only for logvault_user — UPDATE
 * is REVOKEd). Uses POSTGRES_PASSWORD from .env.local, matching the other
 * scripts/fix-mitre-*.js maintenance scripts.
 *
 *   node scripts/backfill-fortinet-srcip.js          # dry run (default) — counts + samples only
 *   node scripts/backfill-fortinet-srcip.js --run    # apply the updates
 */
'use strict';

const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
const { parseFortinet } = require('../parsers/fortinet');

const APPLY = process.argv.includes('--run');

const pool = new Pool({
  host:     process.env.DB_HOST    || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME || 'logvault',
  user:     'postgres',
  password: process.env.POSTGRES_PASSWORD,
  max:      5,
});

const BATCH = 500;

// The normalized fields the current Fortinet parser recovers for VPN/auth rows.
// We only ever ADD these when the existing structured_data lacks them.
const MERGE_KEYS = [
  'srcip', 'remip', 'user', 'srccountry', 'reason', 'logdesc',
  'dstip', 'dstport', 'srcport', 'group', 'dst_host',
  'subcategory', 'action', 'subtype',
];

function isEmpty(v) {
  return v === null || v === undefined;
}

/**
 * Merge the re-parsed fields into the existing structured_data.
 * Returns { merged, changed, added } — `merged` is a new object, `added` lists
 * the keys that were filled in. Additive only: existing non-null values and any
 * keys not in MERGE_KEYS (mitre, category, devname, ...) are preserved untouched.
 */
function mergeRecovered(existing, parsed) {
  const base = (existing && typeof existing === 'object') ? existing : {};
  const recovered = (parsed && parsed.structured_data) || {};
  const merged = Object.assign({}, base);
  const added = [];
  for (const key of MERGE_KEYS) {
    if (!isEmpty(recovered[key]) && isEmpty(base[key])) {
      merged[key] = recovered[key];
      added.push(key);
    }
  }
  return { merged, changed: added.length > 0, added };
}

const TARGET_WHERE =
  `vendor = 'fortinet'
     AND NOT (structured_data ? 'srcip')
     AND raw_message ~ 'remip=[0-9]'`;

async function run() {
  if (!process.env.POSTGRES_PASSWORD) {
    console.error('[BackfillSrcip] POSTGRES_PASSWORD is not set (.env.local) — this script must run as postgres.');
    process.exit(1);
  }

  console.log(`[BackfillSrcip] ${APPLY ? 'APPLYING' : 'DRY RUN'} — recovering remip/srcip/user/country for pre-fix Fortinet rows (batches of ${BATCH}).`);
  if (!APPLY) console.log('[BackfillSrcip] No changes will be written. Re-run with --run to apply.');

  // Up-front candidate count (rows matching the target predicate).
  const { rows: cntRows } = await pool.query(
    `SELECT COUNT(*)::bigint AS n FROM syslog_entries WHERE ${TARGET_WHERE}`
  );
  console.log(`[BackfillSrcip] ${cntRows[0].n} candidate rows match the target predicate.`);

  let scanned = 0, changed = 0, skipped = 0, lastId = 0, nextLog = 5000;
  let samplesShown = 0;
  const MAX_SAMPLES = 5;

  for (;;) {
    const { rows } = await pool.query(
      `SELECT id, source_ip, raw_message, structured_data
         FROM syslog_entries
        WHERE ${TARGET_WHERE}
          AND id > $1
        ORDER BY id
        LIMIT $2`,
      [lastId, BATCH]
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;
    scanned += rows.length;

    const payload = [];
    for (const r of rows) {
      const parsed = parseFortinet(r.raw_message, r.source_ip);
      if (!parsed) { skipped++; continue; }
      const { merged, changed: didChange, added } = mergeRecovered(r.structured_data, parsed);
      if (!didChange) { skipped++; continue; }
      changed++;
      payload.push({ id: String(r.id), data: merged });

      // Dry-run: print a few before/after samples to prove the recovery.
      if (!APPLY && samplesShown < MAX_SAMPLES) {
        samplesShown++;
        const before = r.structured_data || {};
        console.log(`\n[BackfillSrcip] --- SAMPLE ${samplesShown} (id=${r.id}) ---`);
        console.log(`  source_ip (syslog sender): ${r.source_ip}`);
        console.log(`  recovered keys: ${added.join(', ')}`);
        console.log(`  BEFORE: srcip=${JSON.stringify(before.srcip)} remip=${JSON.stringify(before.remip)} user=${JSON.stringify(before.user)} srccountry=${JSON.stringify(before.srccountry)} subcategory=${JSON.stringify(before.subcategory)}`);
        console.log(`  AFTER : srcip=${JSON.stringify(merged.srcip)} remip=${JSON.stringify(merged.remip)} user=${JSON.stringify(merged.user)} srccountry=${JSON.stringify(merged.srccountry)} subcategory=${JSON.stringify(merged.subcategory)}`);
        console.log(`  preserved keys (sample): mitre=${JSON.stringify(before.mitre)} category=${JSON.stringify(before.category)} devname=${JSON.stringify(before.devname)} type=${JSON.stringify(before.type)}`);
      }
    }

    if (APPLY && payload.length) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        for (const p of payload) {
          await client.query(
            `UPDATE syslog_entries SET structured_data = $1::jsonb WHERE id = $2`,
            [JSON.stringify(p.data), p.id]
          );
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    }

    if (scanned >= nextLog) {
      console.log(`[BackfillSrcip] Processed ${scanned} rows (${changed} ${APPLY ? 'updated' : 'would update'}, ${skipped} skipped)...`);
      nextLog += 5000;
    }
  }

  const verb = APPLY ? 'updated' : 'would update';
  console.log(`\n[BackfillSrcip] Done. Processed ${scanned} rows: ${changed} ${verb}, ${skipped} skipped (no change / unparseable).`);
  if (!APPLY && changed > 0) console.log('[BackfillSrcip] DRY RUN — re-run with --run to apply these changes.');
  await pool.end();
}

run().catch(err => {
  console.error('[BackfillSrcip] Error:', err.message);
  process.exit(1);
});
