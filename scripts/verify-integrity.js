'use strict';
/**
 * LogVault Integrity Verifier
 *
 * Walks syslog_entries (only rows where entry_hash IS NOT NULL) in id ASC order
 * and verifies the tamper-evident HMAC-SHA256 hash chain written by
 * collector/collector.js:
 *
 *   1. Recomputes each row's entry_hash from its stored prev_hash + the canonical
 *      field join (HMAC keyed by LOG_INTEGRITY_KEY) and checks it matches the
 *      stored entry_hash.
 *   2. Checks chain continuity — each row's prev_hash must equal the previous
 *      verified row's entry_hash.
 *
 * Reports the first break (id, received_at) and a summary. Exits non-zero on a
 * break. The canonical/HMAC logic below MUST stay byte-for-byte identical to the
 * collector's (canonicalString + computeEntryHash) or the verifier will disagree.
 *
 * Usage: LOG_INTEGRITY_KEY=... node scripts/verify-integrity.js
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
const crypto   = require('crypto');
const { Pool } = require('pg');

const INTEGRITY_KEY = process.env.LOG_INTEGRITY_KEY || null;
const PAGE_SIZE     = 5000;

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME  || 'logvault',
  user:     process.env.LV_DB_USER  || 'logvault_user',
  password: process.env.LV_DB_PASS,
});

// ── Shared integrity helpers — MUST match collector/collector.js EXACTLY ──
// Canonical: stable '|'-joined string of immutable fields in this exact order:
//   received_at (ISO), source_ip, severity, vendor, message, raw_message.
// '' for null/undefined. received_at: Date → .toISOString(), else as-is string.
function canonicalString(entry) {
  let receivedAt = entry.received_at;
  if (receivedAt instanceof Date) receivedAt = receivedAt.toISOString();
  else if (receivedAt == null)    receivedAt = '';
  else                            receivedAt = String(receivedAt);
  const fields = [
    receivedAt,
    entry.source_ip,
    entry.severity,
    entry.vendor,
    entry.message,
    entry.raw_message,
  ];
  return fields.map(f => (f == null ? '' : String(f))).join('|');
}

// entry_hash (Buffer) = HMAC-SHA256(key, prevHex + '|' + canonical)
function computeEntryHash(prevHash, entry) {
  const prevHex = prevHash ? prevHash.toString('hex') : '';
  return crypto.createHmac('sha256', INTEGRITY_KEY)
    .update(prevHex + '|' + canonicalString(entry))
    .digest();
}

function bufEq(a, b) {
  if (a == null && b == null) return true;
  if (a == null || b == null) return false;
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
}

async function verify() {
  if (!INTEGRITY_KEY) {
    console.error('[Verify] LOG_INTEGRITY_KEY not set — cannot verify hash chain.');
    process.exit(2);
  }

  let checked   = 0;
  let lastId    = 0;
  let prevHash  = null;  // entry_hash of the previously verified row
  let firstRow  = true;  // chain continuity is not enforced on the very first row
  let broken    = null;  // { id, received_at, reason }

  console.log('[Verify] Starting integrity verification...');

  while (!broken) {
    const { rows } = await pool.query(
      `SELECT id, received_at, source_ip, severity, vendor, message, raw_message,
              prev_hash, entry_hash
       FROM syslog_entries
       WHERE entry_hash IS NOT NULL AND id > $1
       ORDER BY id ASC
       LIMIT $2`,
      [lastId, PAGE_SIZE]
    );
    if (rows.length === 0) break;

    for (const row of rows) {
      lastId = row.id;

      // 1. Recompute entry_hash from stored prev_hash + canonical fields.
      const recomputed = computeEntryHash(row.prev_hash, row);
      if (!bufEq(recomputed, row.entry_hash)) {
        broken = { id: row.id, received_at: row.received_at, reason: 'entry_hash mismatch (row content or stored hash altered)' };
        break;
      }

      // 2. Chain continuity — prev_hash must equal previous row's entry_hash.
      if (!firstRow && !bufEq(row.prev_hash, prevHash)) {
        broken = { id: row.id, received_at: row.received_at, reason: 'chain broken (prev_hash does not match previous entry_hash — a row was inserted/deleted/reordered)' };
        break;
      }

      prevHash = row.entry_hash;
      firstRow = false;
      checked++;
    }
  }

  console.log(`[Verify] Rows checked: ${checked}`);
  if (broken) {
    console.error(`[Verify] CHAIN BROKEN at id=${broken.id} (received_at=${broken.received_at && broken.received_at.toISOString ? broken.received_at.toISOString() : broken.received_at})`);
    console.error(`[Verify] Reason: ${broken.reason}`);
    console.error('[Verify] RESULT: FAIL');
    return 1;
  }

  console.log(`[Verify] OK — all ${checked} hashed rows verified, chain intact.`);
  console.log('[Verify] RESULT: PASS');
  return 0;
}

verify()
  .then(code => pool.end().then(() => process.exit(code)))
  .catch(err => {
    console.error('[Verify] Error:', err.message);
    pool.end().finally(() => process.exit(1));
  });
