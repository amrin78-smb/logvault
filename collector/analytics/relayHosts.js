'use strict';

/**
 * relayHosts.js — shared list of log-SOURCE / relay hostnames.
 *
 * These hosts are the syslog SENDER (the forwarder/relay), not actors. Because
 * EVERY log arrives through them, a relay wins on raw volume by construction and
 * would otherwise dominate device baselines, anomalies and UEBA risk — surfacing
 * the firewall itself as the "riskiest entity", which is meaningless. UEBA must
 * score real actors (users, attacker srcips, monitored assets), never the relay.
 *
 * Comma-separated env override (UEBA_RELAY_HOSTS); matched case-insensitively
 * against source_host. On-prem single-relay default: the Fortinet relay.
 *
 * Used by baselineBuilder / anomalyDetector / uebaRollup to exclude these hosts
 * from the 'device' entity type. Pure local — no external calls.
 */

const RELAY_HOSTS = (process.env.UEBA_RELAY_HOSTS || 'FGT200E_TUS')
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

/**
 * purgeRelayEntities — remove any 'device' rows for relay hosts that were written
 * BEFORE the exclusion was in place (the producers UPSERT only, never delete, so a
 * stale relay row would otherwise linger forever and keep topping Riskiest
 * Entities). Idempotent + env-aware, so it also self-heals if UEBA_RELAY_HOSTS
 * changes. Cleans entity_risk / anomaly_events / entity_baselines. Never throws.
 */
async function purgeRelayEntities(pool) {
  if (!RELAY_HOSTS.length) return 0;
  let removed = 0;
  for (const table of ['entity_risk', 'anomaly_events', 'entity_baselines']) {
    try {
      const res = await pool.query(
        `DELETE FROM ${table}
          WHERE entity_type = 'device'
            AND lower(entity_value) = ANY($1::text[])`,
        [RELAY_HOSTS]
      );
      removed += res.rowCount || 0;
    } catch (e) {
      console.error('[' + new Date().toISOString() + '] [Relay] purge ' + table +
                    ' failed: ' + e.message);
    }
  }
  return removed;
}

module.exports = { RELAY_HOSTS, purgeRelayEntities };
