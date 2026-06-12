'use strict';

/**
 * RBAC middleware — site-based access control aligned with NetVault SSO.
 *
 * Roles (from netvault.users.role): super_admin, admin, user
 *   - super_admin / admin → see everything (no site filter)
 *   - user               → restricted to sites assigned in netvault.user_sites
 *
 * User identity reaches this Express API via the X-User-Id / X-User-Role
 * request headers, which are set server-side by the Next.js proxy route
 * (frontend/src/app/api/[...path]/route.ts) AFTER it validates the NextAuth
 * session. The API is internal-only (port 3005, never firewalled open), so
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

module.exports = { rbacMiddleware, requireSuperAdmin, requireAdmin, getSiteFilter };
