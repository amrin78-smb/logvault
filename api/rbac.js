'use strict';

/**
 * RBAC middleware — site-based access control aligned with NetVault SSO.
 *
 * Roles (from netvault.users.role): super_admin, admin, user
 *   - super_admin / admin → see everything (no site filter)
 *   - user               → restricted to sites assigned in netvault.user_sites
 *
 * User identity reaches this Express API via the X-User-Id / X-User-Role
 * request headers, which are set by the Next.js edge middleware
 * (frontend/src/proxy.ts) AFTER it verifies the NextAuth session token via
 * getToken(). The API is internal-only (port 3005, never firewalled open), so
 * the proxy is the sole trusted caller. We deliberately do NOT decode the
 * NextAuth session cookie here: next-auth v4 JWE-encrypts the JWT, so a plain
 * jsonwebtoken.decode() cannot read it.
 *
 * Site filtering links logs to sites through known_hosts:
 *   syslog_entries.source_ip -> known_hosts.ip_address -> known_hosts.site_id
 *   known_hosts.site_id matches netvault.sites.id / netvault.user_sites.site_id
 */

const { Pool } = require('pg');

// NetVault DB connection (read-only use — user_sites lookup)
const nvPool = new Pool({
  host:     process.env.NETVAULT_DB_HOST || 'localhost',
  port:     parseInt(process.env.NETVAULT_DB_PORT || '5432'),
  database: process.env.NETVAULT_DB_NAME || 'netvault',
  user:     process.env.NETVAULT_DB_USER || 'netvault',
  password: process.env.NETVAULT_DB_PASS,
  ssl:      false,
  max:      3,
  idleTimeoutMillis: 30000,
});

// Cache site assignments per user — refresh every 5 minutes
const siteCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

async function getUserSites(userId) {
  const cached = siteCache.get(userId);
  if (cached && Date.now() - cached.at < CACHE_TTL) return cached.sites;

  const { rows } = await nvPool.query(
    'SELECT site_id FROM user_sites WHERE user_id = $1',
    [userId]
  );
  const sites = rows.map(r => r.site_id).filter(s => s != null);
  siteCache.set(userId, { sites, at: Date.now() });
  return sites;
}

// Express middleware — attaches req.rbac to every request
async function rbacMiddleware(req, res, next) {
  try {
    // Identity is supplied by the trusted Next.js proxy via headers.
    const userId = parseInt(req.headers['x-user-id'] || '0') || 0;
    const role   = req.headers['x-user-role'] || 'user';

    req.rbac = {
      userId,
      role,
      isSuperAdmin: role === 'super_admin',
      isAdmin:      role === 'admin' || role === 'super_admin',
    };

    // super_admin and admin see everything — no site filter
    if (req.rbac.isAdmin) {
      req.rbac.allowedSiteIds = null; // null = no filter
      return next();
    }

    // Regular users — resolve their assigned sites
    req.rbac.allowedSiteIds = userId ? await getUserSites(userId) : [];
    next();
  } catch (err) {
    // Fail CLOSED for regular users: a NetVault DB blip must never turn a
    // site-restricted user into an all-sites viewer. We still trust the role
    // from the proxy-verified header, so admins keep null (no filter) and stay
    // unblocked during an outage; a 'user' gets [] (sees nothing) instead of
    // the old null (saw everything).
    console.error('[RBAC] Middleware error:', err.message);
    const role   = req.headers['x-user-role'] || 'user';
    const userId = parseInt(req.headers['x-user-id'] || '0') || 0;
    const isAdmin = role === 'admin' || role === 'super_admin';
    req.rbac = {
      userId,
      role,
      isSuperAdmin: role === 'super_admin',
      isAdmin,
      allowedSiteIds: isAdmin ? null : [],
    };
    next();
  }
}

// Express middleware — restrict an endpoint to admin or super_admin.
function requireAdmin(req, res, next) {
  if (!req.rbac || !req.rbac.isAdmin) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
}

// Express middleware — restrict an endpoint to super_admin only
function requireSuperAdmin(req, res, next) {
  if (!req.rbac || !req.rbac.isSuperAdmin) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
}

/**
 * SQL helper — returns a WHERE-clause fragment that limits rows to source IPs
 * belonging to the user's allowed sites.
 *
 * @param rbac            req.rbac object (may be undefined)
 * @param startParamIndex next free $N parameter index for the query
 * @param tableAlias      alias (or table name) holding the source_ip column
 * @returns { clause, params, nextParamIndex }
 *
 * - rbac missing or allowedSiteIds === null → no filter (empty clause)
 * - allowedSiteIds === []                   → "AND 1=0" (user sees nothing)
 * - allowedSiteIds populated                → IN-subquery against known_hosts
 *
 * The returned clause is prefixed with "AND " so it can be appended directly
 * to an existing WHERE clause. For endpoints that build a conditions array
 * joined by " AND ", strip the leading "AND ".
 */
function getSiteFilter(rbac, startParamIndex, tableAlias = 'se') {
  if (!rbac || rbac.allowedSiteIds === null || rbac.allowedSiteIds === undefined) {
    return { clause: '', params: [], nextParamIndex: startParamIndex };
  }
  if (rbac.allowedSiteIds.length === 0) {
    // User has no sites assigned — return nothing
    return { clause: 'AND 1=0', params: [], nextParamIndex: startParamIndex };
  }
  const clause = `AND ${tableAlias}.source_ip IN (
    SELECT kh.ip_address FROM known_hosts kh
    WHERE kh.site_id = ANY($${startParamIndex}::int[])
  )`;
  return {
    clause,
    params: [rbac.allowedSiteIds],
    nextParamIndex: startParamIndex + 1,
  };
}

/**
 * Permissive variant of getSiteFilter for AGGREGATE DASHBOARD STATS only
 * (summary, timeline, top-talkers, top-security-events, top-failures,
 * top-blocked). These widgets are firewall-centric: the source_ip is almost
 * always a single firewall/collector device. If that device is unregistered or
 * has no site assigned in known_hosts, the strict getSiteFilter matched ZERO
 * rows for every non-admin, so the widgets rendered empty for regular users
 * even though super_admin (no filter) saw data.
 *
 * Here a row is visible when its source_ip belongs to one of the user's sites
 * OR when source_ip is NOT assigned to ANY site — i.e. unregistered/unassigned
 * devices are visible to everyone, only explicitly site-assigned devices are
 * restricted. Detailed log access (/api/logs, /api/logs/export, alert events)
 * deliberately keeps the strict getSiteFilter — this loosening is scoped to the
 * aggregate dashboard tiles only.
 *
 * Same parameter footprint as getSiteFilter (one $N array param, or none for a
 * user with no sites) so call sites need no parameter reindexing.
 */
function getStatsSiteFilter(rbac, startParamIndex, tableAlias = 'se') {
  if (!rbac || rbac.allowedSiteIds === null || rbac.allowedSiteIds === undefined) {
    return { clause: '', params: [], nextParamIndex: startParamIndex };
  }
  // "Assigned" = source IPs that belong to some site in known_hosts. Anything
  // not in that set is unregistered/unassigned and visible to all. The
  // ip_address IS NOT NULL guard is required: a single NULL inside a NOT IN
  // subquery makes the whole predicate return no rows.
  const unassigned = `${tableAlias}.source_ip NOT IN (
    SELECT kh.ip_address FROM known_hosts kh
    WHERE kh.site_id IS NOT NULL AND kh.ip_address IS NOT NULL
  )`;
  if (rbac.allowedSiteIds.length === 0) {
    // User has no sites — still sees unassigned/unregistered devices.
    return { clause: `AND (${unassigned})`, params: [], nextParamIndex: startParamIndex };
  }
  const clause = `AND (
    ${tableAlias}.source_ip IN (
      SELECT kh.ip_address FROM known_hosts kh WHERE kh.site_id = ANY($${startParamIndex}::int[])
    )
    OR ${unassigned}
  )`;
  return {
    clause,
    params: [rbac.allowedSiteIds],
    nextParamIndex: startParamIndex + 1,
  };
}

/**
 * SQL helper for ALERT-branch site scoping (correlation + threshold alerts).
 *
 * alert_events.source_ip is the INTERNAL srcip of the triggering host (the real
 * actor), which is almost never registered in known_hosts with a site — so the
 * plain getSiteFilter (which keys on source_ip) collapses alert-derived MITRE
 * techniques to zero for every site-scoped user, even though an admin sees them.
 *
 * Events are attributed to a site via the RELAY: syslog_entries.source_ip is the
 * firewall/relay device, mapped through known_hosts.ip_address -> site_id. Every
 * alert_event carries that same relay in ae.source_host (the firewall hostname,
 * e.g. 'FGT200E_TUS'). To keep alert visibility CONSISTENT with event visibility
 * (a technique an admin sees is also seen by the site-scoped user whose site
 * produced it) WITHOUT leaking another site's data, we scope alerts by that relay:
 *   ae.source_host -> known_hosts.hostname -> known_hosts.site_id
 * This mirrors the event branch's relay attribution exactly (same physical
 * device, same site mapping), so the two branches stay in lockstep and a user
 * whose site does not own the relay sees neither its events nor its alerts.
 *
 * Same parameter footprint as getSiteFilter (one $N array param, or none).
 *
 * @param rbac            req.rbac object (may be undefined)
 * @param startParamIndex next free $N parameter index for the query
 * @param tableAlias      alias holding source_host (defaults to 'ae')
 */
function getAlertSiteFilter(rbac, startParamIndex, tableAlias = 'ae') {
  if (!rbac || rbac.allowedSiteIds === null || rbac.allowedSiteIds === undefined) {
    return { clause: '', params: [], nextParamIndex: startParamIndex };
  }
  if (rbac.allowedSiteIds.length === 0) {
    return { clause: 'AND 1=0', params: [], nextParamIndex: startParamIndex };
  }
  const clause = `AND ${tableAlias}.source_host IN (
    SELECT kh.hostname FROM known_hosts kh
    WHERE kh.hostname IS NOT NULL AND kh.site_id = ANY($${startParamIndex}::int[])
  )`;
  return {
    clause,
    params: [rbac.allowedSiteIds],
    nextParamIndex: startParamIndex + 1,
  };
}

/**
 * SQL helper for the HOURLY ROLLUP TABLES (syslog_stats_rollup /
 * syslog_talker_rollup — see scripts/schema.sql "HOURLY ROLLUP TABLES").
 *
 * Unlike getStatsSiteFilter (which live-joins syslog_entries.source_ip against
 * known_hosts on every read), the rollup tables already carry a PRE-RESOLVED
 * site_id column, computed by the collector at rollup-build time using the
 * SAME site-scoping logic as getStatsSiteFilter (site_id = the device's
 * known_hosts.site_id, or NULL when source_ip has no site-assigned match in
 * known_hosts). So filtering a rollup read needs only a plain column
 * comparison, not a subquery/join — but it must preserve getStatsSiteFilter's
 * exact permissive semantics: a row is visible when site_id is one of the
 * user's allowed sites OR site_id IS NULL (unassigned/unregistered devices
 * stay visible to everyone).
 *
 * Same parameter footprint as getStatsSiteFilter (one $N array param, or none).
 *
 * @param rbac            req.rbac object (may be undefined)
 * @param startParamIndex next free $N parameter index for the query
 * @returns { clause, params, nextParamIndex }
 */
function getRollupSiteFilter(rbac, startParamIndex) {
  if (!rbac || rbac.allowedSiteIds === null || rbac.allowedSiteIds === undefined) {
    return { clause: '', params: [], nextParamIndex: startParamIndex };
  }
  if (rbac.allowedSiteIds.length === 0) {
    // User has no sites — still sees unassigned/unregistered devices (site_id IS NULL),
    // matching getStatsSiteFilter's permissive semantics exactly.
    return { clause: `AND site_id IS NULL`, params: [], nextParamIndex: startParamIndex };
  }
  return {
    clause: `AND (site_id = ANY($${startParamIndex}::int[]) OR site_id IS NULL)`,
    params: [rbac.allowedSiteIds],
    nextParamIndex: startParamIndex + 1,
  };
}

module.exports = { rbacMiddleware, requireSuperAdmin, requireAdmin, getSiteFilter, getStatsSiteFilter, getAlertSiteFilter, getRollupSiteFilter };
