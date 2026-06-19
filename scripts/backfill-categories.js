/**
 * One-off backfill: assign `category` and `risk_score` to historical
 * syslog_entries rows that predate the universal-taxonomy collector.
 *
 * Reuses collector/taxonomy.js and collector/riskScorer.js so the values
 * are identical to what the live collector now writes for new logs.
 *
 * Safe to re-run: only touches rows where category IS NULL or ''.
 *
 *   node scripts/backfill-categories.js
 *
 * NOTE (Phase 3+): syslog_entries is now append-only for logvault_user
 * (UPDATE/DELETE revoked for tamper prevention). This one-off UPDATEs rows,
 * so if you ever need to re-run it, point DB_* / LV_DB_* at a privileged role
 * (e.g. postgres) — it will fail with a permission error as logvault_user.
 */
'use strict';

const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const { getCategory } = require('../collector/taxonomy');
const { scoreLog }    = require('../collector/riskScorer');

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME  || 'logvault',
  user:     process.env.LV_DB_USER  || 'logvault_user',
  password: process.env.LV_DB_PASS,
  max:      5,
});

const BATCH = 1000;

async function run() {
  let total = 0;
  let lastId = 0;  // cursor — advances every batch so rows that stay 'network' aren't re-selected forever
  for (;;) {
    const { rows } = await pool.query(
      `SELECT id, vendor, message, severity, structured_data
         FROM syslog_entries
        WHERE (category IS NULL OR category = '' OR category = 'network')
          AND id > $1
        ORDER BY id
        LIMIT $2`,
      [lastId, BATCH]
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;

    const ids = [], cats = [], risks = [];
    for (const r of rows) {
      const structured = r.structured_data || {};
      const category = getCategory(r.vendor, structured, r.message) || 'network';
      structured.category = category;                 // so risk scoring sees it
      const risk = scoreLog({ severity: r.severity, message: r.message, structured_data: structured });
      ids.push(r.id); cats.push(category); risks.push(risk);
    }

    await pool.query(
      `UPDATE syslog_entries AS s
          SET category = v.category, risk_score = v.risk_score
         FROM (
           SELECT UNNEST($1::bigint[]) AS id,
                  UNNEST($2::text[])   AS category,
                  UNNEST($3::int[])    AS risk_score
         ) AS v
        WHERE s.id = v.id`,
      [ids, cats, risks]
    );

    total += rows.length;
    console.log(`[Backfill] Updated ${total} rows...`);
  }
  console.log(`[Backfill] Done. Total rows updated: ${total}`);
  await pool.end();
}

run().catch(err => {
  console.error('[Backfill] Error:', err.message);
  process.exit(1);
});
