'use strict';

/**
 * Pagination input clamping.
 *
 * `limit` was already clamped everywhere via server.js's safeInt(); `page` had
 * a FLOOR but no CEILING, which made two different problems reachable from one
 * query string on /api/logs:
 *
 *   1. ?page=100000000 -> OFFSET 9,999,999,900. Postgres has to walk and throw
 *      away every row before the offset, so that single request scans the whole
 *      `received_at` index across every daily partition of a ~10.5M-row / 43GB
 *      table. The API pool is `max: 10`, so a handful of concurrent requests
 *      saturate it and the rest of the app queues behind them.
 *   2. ?page=1e23 -> parseInt('1e23') is 1, but ?page=100000000000000000000
 *      yields a float (1e20) that Postgres rejects for a bigint parameter, so
 *      the endpoint 500s unconditionally.
 *
 * Both are fixed by clamping the OFFSET rather than the page number: the cap is
 * expressed in rows, so it holds no matter what `limit` is in play. Callers get
 * the effective page back and should echo it to the client (plus a `clamped`
 * flag) so a caller paging through an API script can tell it was capped instead
 * of silently re-reading the same page forever.
 *
 * MAX_OFFSET_ROWS is deliberately generous (100k rows = page 1001 at the
 * default limit of 100, page 501 at the 200 the UI uses) — far past any real
 * human paging session, and past the 5,000-row cap the free-text count query
 * already imposes, while still bounding the worst-case index walk to something
 * the pool can absorb. The LogVault UI never sends `page` at all (LogExplorer
 * re-queries with filters instead of paging), so nothing in the app is affected
 * by the cap; it exists for direct/API callers.
 */

const MAX_OFFSET_ROWS = 100000;

/**
 * @param  val    raw req.query.page
 * @param  limit  the ALREADY-CLAMPED page size
 * @returns { page, offset, clamped }
 */
function safePage(val, limit) {
  const size = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 1;
  const maxPage = Math.max(1, Math.floor(MAX_OFFSET_ROWS / size) + 1);

  // parseInt (not Number) so a trailing-garbage value degrades to its leading
  // digits exactly as before; Number.isFinite rejects NaN AND Infinity.
  const n = parseInt(val, 10);
  const requested = Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
  const page = Math.min(requested, maxPage);

  return { page, offset: (page - 1) * size, clamped: page !== requested };
}

module.exports = { MAX_OFFSET_ROWS, safePage };
