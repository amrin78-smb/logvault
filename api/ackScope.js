'use strict';

/**
 * Input validation + site-scoped SQL for the ACKNOWLEDGE write paths
 * (`alert_events` and `anomaly_events`).
 *
 * WHAT WAS WRONG (fixed 2026-11)
 * ------------------------------
 * All four acknowledge routes were registered BARE — no `requireAdmin`, and,
 * unlike every read path on the same tables, no site filter at all. `rbacMiddleware`
 * only ATTACHES `req.rbac`; it never blocks, so "no guard" meant "any session".
 * Three distinct bugs fell out of that:
 *
 *   - `PATCH /api/alerts/events/acknowledge-all` with an EMPTY body took the
 *     else-branch and ran `UPDATE alert_events SET acknowledged = TRUE WHERE
 *     acknowledged = FALSE` — EVERY open alert estate-wide, triggered by a
 *     read-only `user` scoped to one site who cannot even READ those alerts.
 *     `/api/anomalies/acknowledge-all` was identical.
 *   - the single-id variants were a cross-site IDOR: any id, any site.
 *   - a non-numeric `:id` reached an int column and 500'd with Postgres 22P02.
 *
 * THE THREE RULES THIS MODULE ENFORCES
 * ------------------------------------
 *  1. An id list is REQUIRED. A missing/empty/all-invalid `ids` is a 400, never
 *     "all" — "acknowledge everything" is not a thing a caller can ask for by
 *     omission. (The UI always sends explicit ids, so nothing regresses.)
 *  2. Ids are validated as positive int4 before they reach the query, so a
 *     non-numeric or out-of-range id is a 400 and never a 22P02 500.
 *  3. The UPDATE carries the SAME site predicate the matching READ endpoint
 *     uses, so what a caller can acknowledge is exactly what they can see.
 *     This mirrors SpanVault's `alertWriteSiteClause` reasoning: read scope and
 *     write scope must be the same rule by construction, or an operator ends up
 *     looking at rows an ack silently matches 0 of (or worse, the reverse).
 *
 * WHICH SITE FILTER — THIS MATTERS, THEY ARE NOT INTERCHANGEABLE
 * --------------------------------------------------------------
 * The caller passes in the already-built filter, so the choice stays next to
 * the route and next to its read twin:
 *   - `alert_events`   -> `getAlertSiteFilter` (scopes on `ae.source_host` ->
 *     `known_hosts.hostname`). NOT `getSiteFilter`: `alert_events.source_ip` is
 *     the internal ACTOR ip, almost never registered in `known_hosts` with a
 *     site, so an ip-keyed filter collapses to zero rows for every site-scoped
 *     user. `GET /api/alerts/events` already uses the hostname filter, so this
 *     makes the write match the read exactly. See `api/rbac.js`.
 *   - `anomaly_events` -> server.js's `anomalySiteFilter` (`getSiteFilter` on
 *     `ae.source_ip`, OR `source_ip IS NULL`), the same helper `GET
 *     /api/anomalies` uses — user/behavioural anomalies legitimately carry a
 *     NULL source_ip and are visible to everyone, so they must stay ackable by
 *     everyone who can see them.
 *
 * The role gate itself is NOT here (it is Express middleware on the route):
 * `requireAdmin`, i.e. LogVault's exact analogue of DDIVault's `requireWrite`
 * admin floor. LogVault has only super_admin / admin / user, with no
 * site-scoped WRITER role like SpanVault's site_admin, and `user` holds no
 * write capability anywhere else in the app — so the admin floor is the
 * faithful port. The site predicate below is still applied on top of it (today
 * a no-op for admins, who are unscoped) so the write is already correct the day
 * a site-scoped writer role does exist, and so the two halves can never drift
 * apart silently.
 */

// Bulk ack is one statement over an id array; cap the array so a single request
// can't hand Postgres a megabyte-long literal.
const MAX_ACK_IDS = 1000;
const INT4_MAX = 2147483647;

// Only these two tables are ever acknowledged. The table name is interpolated
// into the SQL (it cannot be a bind parameter), so it is matched against this
// allow-list rather than trusted — belt and braces, since both call sites pass
// a literal.
const ACK_TABLES = new Set(['alert_events', 'anomaly_events']);

/**
 * Validate ONE id (the `:id` route param).
 * @returns a positive int4, or null when it is not one.
 */
function parseAckId(raw) {
  // Reject anything that isn't purely digits BEFORE parseInt: parseInt('7abc')
  // is 7, a different but perfectly valid row.
  const s = String(raw == null ? '' : raw).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 1 || n > INT4_MAX) return null;
  return n;
}

/**
 * Validate the `ids` array from a bulk-ack body.
 * @returns { ids } on success, or { error } with a client-safe message.
 */
function parseAckIds(body) {
  const raw = body && Array.isArray(body.ids) ? body.ids : null;
  if (!raw) {
    return { error: 'ids must be a non-empty array of numeric ids' };
  }
  const ids = [];
  const seen = new Set();
  for (const v of raw) {
    const n = parseAckId(typeof v === 'number' ? (Number.isInteger(v) ? v : NaN) : v);
    if (n === null || seen.has(n)) continue;
    seen.add(n);
    ids.push(n);
    if (ids.length >= MAX_ACK_IDS) break;
  }
  if (!ids.length) {
    return { error: 'ids must be a non-empty array of numeric ids' };
  }
  return { ids };
}

/**
 * Build the site-scoped acknowledge UPDATE.
 *
 * @param table       'alert_events' | 'anomaly_events'
 * @param ids         validated positive int4 array (never empty)
 * @param ackBy       acknowledged_by value (NetVault user id as text, or null)
 * @param siteFilter  { clause, params } from the table's matching site helper,
 *                    built with startParamIndex = 3 (ids=$1, ackBy=$2)
 * @returns { sql, params }
 */
function buildAckUpdate(table, ids, ackBy, siteFilter) {
  if (!ACK_TABLES.has(table)) throw new Error(`buildAckUpdate: unsupported table ${table}`);
  if (!Array.isArray(ids) || ids.length === 0) throw new Error('buildAckUpdate: ids must be non-empty');
  const sf = siteFilter || { clause: '', params: [] };

  // `UPDATE <table> ae SET ...` — the alias is what the site clauses qualify
  // their columns with ('ae' for both helpers). SET columns stay unqualified,
  // as Postgres requires. RETURNING id lets the caller report what actually
  // changed instead of assuming the request succeeded.
  const sql = `
    UPDATE ${table} ae
       SET acknowledged = TRUE, acknowledged_at = NOW(), acknowledged_by = $2
     WHERE ae.id = ANY($1::int[])
     ${sf.clause}
    RETURNING ae.id
  `;
  return { sql, params: [ids, ackBy, ...sf.params] };
}

module.exports = { MAX_ACK_IDS, parseAckId, parseAckIds, buildAckUpdate };
