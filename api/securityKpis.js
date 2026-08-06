'use strict';

// ── Shared security KPI computation ──────────────────────────────────────────
//
// ONE implementation of the security headline numbers, used by BOTH
// `GET /api/security/summary` (server.js) and the Security Overview KPI strip
// (`gatherSecurity` in soc.js).
//
// These existed as two hand-written copies of the same SQL and had already
// drifted: /api/security/summary picked up two extra metrics plus the
// `action='blocked'` correctness fix (the parser never emits 'deny', so that
// card read 0 for its whole life), while soc.js's copy sat untouched. Two code
// paths rendering the same six numbers on two different tabs is exactly how a
// user ends up seeing "Auth Failures 12" on one screen and "0" on another.
//
// Cost/selectivity notes worth keeping in mind before editing any of these:
//   * denies / vpn / ips read `syslog_fortinet_field_rollup` (Phase 4) and cost
//     ~15-20ms. The other five scan raw `syslog_entries` at ~0.6-1.3s each,
//     measured live 2026-08-06. If you add a metric, prefer a rollup dimension.
//   * `vendor='fortinet'` and `severity <= 4` have effectively ZERO selectivity
//     on this single-vendor deployment (~100% of rows), so no index helps a
//     query shaped that way — only pre-aggregation does. See the Phase 2/3/4
//     sections of CLAUDE.md.
//   * brute_force_success is a SELF-JOIN over syslog_entries (~1.3s) and, on
//     this deployment, is structurally incapable of returning non-zero: it
//     requires subcategory='login_success', and this FortiGate has never sent a
//     single login-success event (0 rows in 47 days / 10.9M rows, verified
//     2026-08-06 — it sends ssl-login-fail but no successes). Left in place
//     because that is a firewall logging-config gap, not a code bug, and it
//     starts working the moment those events arrive.

const { getSiteFilter, getRollupSiteFilter } = require('./rbac');

/**
 * Compute the security headline metrics for a window.
 * @param {import('pg').Pool} pool
 * @param {object} rbac  req.rbac — site scoping is applied per-query
 * @param {number} hours already validated by the caller (safeHours)
 * @returns {Promise<object>} all eight metrics
 */
async function gatherSecurityKpis(pool, rbac, hours) {
  // $1 is an explicit CUTOFF TIMESTAMP, not an hours integer — this is a ~30x
  // difference, and it is all planning time, not execution.
  //
  // `syslog_entries` has 56 daily partitions. With the old
  // `received_at > NOW() - make_interval(hours => $1)` form, the cutoff is not a
  // plan-time constant (NOW() is STABLE, not IMMUTABLE), so the planner cannot
  // prune partitions while planning and instead considers all 56 with their
  // indexes on EVERY call. Measured live 2026-08-06 on the auth-failures query:
  //
  //   NOW() - make_interval(hours => $1)   planning 566ms + execution   6ms  -> 624ms round-trip
  //   received_at > $1 (timestamptz)       planning 2.5ms + execution   6ms  ->  21ms round-trip
  //
  // Both prune to the same 19 partitions at execution and return identical
  // results; the difference is purely that a real parameter value lets the
  // planner prune up front. Do NOT "tidy" these back into make_interval — it
  // reads cleaner and costs ~600ms per query. The same pattern is still present
  // elsewhere in api/ and is worth converting the same way.
  const since = new Date(Date.now() - hours * 3600 * 1000);
  const sf  = getSiteFilter(rbac, 2, 'syslog_entries'); // bare-table subqueries
  const sfA = getSiteFilter(rbac, 2, 'a');              // brute-force success alias
  const sfSe = getSiteFilter(rbac, 2, 'se');            // known-bad join alias
  const sfRollupDenies = getRollupSiteFilter(rbac, 2);
  const sfRollupVpn    = getRollupSiteFilter(rbac, 2);
  const sfRollupIps    = getRollupSiteFilter(rbac, 2);

  const [authFail, denies, vpn, ips, afterHours, bruteSuccess, vpnLoginFail, knownBadFail] =
    await Promise.all([
      // Real auth failure = normalized subcategory (vendor-agnostic). The broad
      // %fail%/%error% message match this replaced counted SSL teardown noise
      // (ssl-exit-error / ssl-alert / negotiate) as login failures. The message
      // ILIKE fallback that sat alongside it was dropped too — a live 30-day
      // check found it caught zero rows subcategory did not already cover, at
      // ~60x the cost (3-way BitmapOr across subcategory + message-trigram).
      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > $1 AND structured_data->>'subcategory' IN ('login_failed','auth_failed') ${sf.clause}`, [since, ...sf.params]),

      // dimension='action', value='blocked' — NOT 'deny'. This deployment's
      // Fortinet parser never emits 'deny' (confirmed live: 'blocked' 546
      // rows/24h, 'deny' always 0), which is why this card silently read 0.
      pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'action' AND value = 'blocked' AND hour_bucket >= date_trunc('hour', $1::timestamptz) ${sfRollupDenies.clause}`, [since, ...sfRollupDenies.params]),

      pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'subtype' AND value = 'vpn' AND hour_bucket >= date_trunc('hour', $1::timestamptz) ${sfRollupVpn.clause}`, [since, ...sfRollupVpn.params]),

      pool.query(`SELECT COALESCE(SUM(log_count), 0)::bigint AS count FROM syslog_fortinet_field_rollup WHERE dimension = 'type' AND value = 'utm' AND hour_bucket >= date_trunc('hour', $1::timestamptz) ${sfRollupIps.clause}`, [since, ...sfRollupIps.params]),

      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > $1 AND structured_data->>'subcategory' IN ('login_failed','config_change','auth_failed') AND EXTRACT(HOUR FROM received_at) NOT BETWEEN 7 AND 19 ${sf.clause}`, [since, ...sf.params]),

      pool.query(`SELECT COUNT(DISTINCT COALESCE(a.structured_data->>'srcip', a.source_ip::text)) AS count
        FROM syslog_entries a
        INNER JOIN syslog_entries b
          ON COALESCE(b.structured_data->>'srcip', b.source_ip::text) = COALESCE(a.structured_data->>'srcip', a.source_ip::text)
          AND b.structured_data->>'subcategory' = 'login_failed'
          AND b.received_at > $1
          AND b.received_at < a.received_at
        WHERE a.received_at > $1
          AND a.structured_data->>'subcategory' = 'login_success'
        ${sfA.clause}`, [since, ...sfA.params]),

      pool.query(`SELECT COUNT(*) AS count FROM syslog_entries WHERE received_at > $1 AND (category='vpn' OR structured_data->>'subtype'='vpn') AND structured_data->>'subcategory' IN ('login_failed','auth_failed') ${sf.clause}`, [since, ...sf.params]),

      pool.query(`SELECT COUNT(*) AS count
        FROM syslog_entries se
        LEFT JOIN known_hosts kh
          ON COALESCE(se.structured_data->>'srcip', se.source_ip::text) ~ '^[0-9.]+$'
         AND host(kh.ip_address) = COALESCE(se.structured_data->>'srcip', se.source_ip::text)
        WHERE se.received_at > $1
          AND se.structured_data->>'subcategory' IN ('login_failed','auth_failed')
          AND (kh.is_known_bad = TRUE OR kh.abuse_score >= 50)
        ${sfSe.clause}`, [since, ...sfSe.params]),
    ]);

  const n = (r) => parseInt(r.rows[0].count) || 0;
  return {
    auth_failures:       n(authFail),
    firewall_denies:     n(denies),
    vpn_events:          n(vpn),
    ips_events:          n(ips),
    after_hours_events:  n(afterHours),
    brute_force_success: n(bruteSuccess),
    vpn_login_failures:  n(vpnLoginFail),
    known_bad_failures:  n(knownBadFail),
  };
}

module.exports = { gatherSecurityKpis };
