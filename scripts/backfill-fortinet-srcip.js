/**
 * One-time backfill: recover ALL parser-captured fields for historical Fortinet
 * events (originally just the remote source IP — now generalized).
 *
 * The Fortinet parser has been substantially expanded over time. Early versions
 * surfaced only a handful of normalized fields, so historical rows are missing
 * dozens of values that the CURRENT parser now extracts from the same
 * raw_message: the remote-client fields (remip -> srcip, user/srccountry/
 * reason/logdesc), plus ~40 newer fields — service, dstcountry, proto,
 * srcintf/dstintf, sessionid, policyname, bytes/pkts, app; VPN gateway/port/
 * IPsec status/XAuth user; UTM eventtype/threattype/cert/hostname/virus/attack;
 * webfilter url/cat/catdesc/crscore/crlevel; admin ui/user; etc. As a result
 * historical rows power empty widgets (e.g. "Top Services") and blank IPS threat
 * names, and they don't match rows ingested after each parser improvement.
 *
 * This script re-parses each Fortinet row's raw_message through the CURRENT
 * Fortinet parser (parsers/fortinet.js — the exact same code live ingestion
 * uses) and MERGES every recovered field back into the existing structured_data.
 * It is purely ADDITIVE and generalized:
 *   - it adds ANY key the fresh parse produced that is missing/null in the
 *     existing structured_data (no fixed key list to maintain — new parser
 *     fields are recovered automatically),
 *   - it never overwrites an existing non-null value,
 *   - it never removes existing keys (mitre, category, etc. are preserved).
 * If a row would not change, it is skipped (per-row no-op skip), so the script
 * is idempotent and safe to re-run. The earlier srcip-only version has already
 * been run on this deployment; re-running this recovers the remaining fields and
 * leaves srcip rows that gain nothing untouched.
 *
 * NOTE: log_timestamp is intentionally NOT touched here — existing timestamps
 * are already correct for this deployment; the parser's tz fix is forward-looking
 * for newly-ingested logs only.
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

function isEmpty(v) {
  return v === null || v === undefined;
}

/**
 * Merge the re-parsed fields into the existing structured_data.
 * Returns { merged, changed, added } — `merged` is a new object, `added` lists
 * the keys that were filled in. Generalized + additive only: ANY key the fresh
 * parse produced that the existing structured_data lacks (missing or null) is
 * added; existing non-null values and any keys the parser no longer emits
 * (mitre, category, devname, ...) are preserved untouched. No fixed key list —
 * new parser fields are recovered automatically.
 */
function mergeRecovered(existing, parsed) {
  const base = (existing && typeof existing === 'object') ? existing : {};
  const recovered = (parsed && parsed.structured_data) || {};
  const merged = Object.assign({}, base);
  const added = [];
  for (const key of Object.keys(recovered)) {
    if (!isEmpty(recovered[key]) && isEmpty(base[key])) {
      merged[key] = recovered[key];
      added.push(key);
    }
  }
  return { merged, changed: added.length > 0, added };
}

// All Fortinet rows can potentially gain newly-captured fields. The per-row
// no-op skip below keeps this idempotent: a row that gains nothing is never
// rewritten, so an UPDATE only happens when the merged object actually differs.
const TARGET_WHERE = `vendor = 'fortinet'`;

async function run() {
  if (!process.env.POSTGRES_PASSWORD) {
    console.error('[Backfill] POSTGRES_PASSWORD is not set (.env.local) — this script must run as postgres.');
    process.exit(1);
  }

  console.log(`[Backfill] ${APPLY ? 'APPLYING' : 'DRY RUN'} — recovering ALL parser-captured fields for Fortinet rows (batches of ${BATCH}).`);
  if (!APPLY) console.log('[Backfill] No changes will be written. Re-run with --run to apply.');

  // Up-front candidate count (rows matching the target predicate).
  const { rows: cntRows } = await pool.query(
    `SELECT COUNT(*)::bigint AS n FROM syslog_entries WHERE ${TARGET_WHERE}`
  );
  console.log(`[Backfill] ${cntRows[0].n} candidate rows match the target predicate.`);

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
        console.log(`\n[Backfill] --- SAMPLE ${samplesShown} (id=${r.id}) ---`);
        console.log(`  source_ip (syslog sender): ${r.source_ip}`);
        console.log(`  recovered keys (${added.length}): ${added.join(', ')}`);
        console.log(`  BEFORE: srcip=${JSON.stringify(before.srcip)} service=${JSON.stringify(before.service)} eventtype=${JSON.stringify(before.eventtype)} user=${JSON.stringify(before.user)} subcategory=${JSON.stringify(before.subcategory)}`);
        console.log(`  AFTER : srcip=${JSON.stringify(merged.srcip)} service=${JSON.stringify(merged.service)} eventtype=${JSON.stringify(merged.eventtype)} user=${JSON.stringify(merged.user)} subcategory=${JSON.stringify(merged.subcategory)}`);
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
      console.log(`[Backfill] Processed ${scanned} rows (${changed} ${APPLY ? 'updated' : 'would update'}, ${skipped} skipped)...`);
      nextLog += 5000;
    }
  }

  const verb = APPLY ? 'updated' : 'would update';
  console.log(`\n[Backfill] Done. Processed ${scanned} rows: ${changed} ${verb}, ${skipped} skipped (no change / unparseable).`);
  if (!APPLY && changed > 0) console.log('[Backfill] DRY RUN — re-run with --run to apply these changes.');
  await pool.end();
}

run().catch(err => {
  console.error('[Backfill] Error:', err.message);
  process.exit(1);
});
