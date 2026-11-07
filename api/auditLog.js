'use strict';

/**
 * Audit-trail writer for LogVault sensitive actions.
 *
 * writeAudit() inserts one append-only row into the audit_log table for a
 * security-relevant action (settings change, data export, host sync, system
 * update, alert acknowledge, ...). Identity comes from req.rbac (set by
 * rbacMiddleware in api/rbac.js); the client IP is best-effort and may be the
 * Next.js proxy rather than the true browser.
 *
 * CRITICAL: auditing must NEVER break the user's action. The insert is wrapped
 * in try/catch and never throws — on failure it only logs to console. Callers
 * may await it (it always resolves) but do not need to.
 *
 * detail must stay small and MUST NOT contain secrets (e.g. for a settings
 * update log the list of changed KEYS, never the values / SMTP password).
 */

// Best-effort client IP for the audit row.
//
// ⛔ DO NOT go back to `String(fwd).split(',')[0]`. The FIRST hop of
// x-forwarded-for is whatever the CLIENT sent: a browser can set the header
// itself, and frontend/src/proxy.ts copies the inbound headers through
// verbatim, so any authenticated user could make an append-only audit_log row
// for their own settings.update / logs.export / alert.acknowledge attribute to
// someone else's IP. An append-only trail that records a forgeable actor
// address is worse than one that records none, because it is trusted.
//
// Taking [0] is wrong even behind a trusted proxy that APPENDS: a proxy appends
// the peer it saw to the end of the chain, so the trustworthy value is the LAST
// hop, and everything before it is client-supplied. We prefer the socket peer
// (unforgeable, though with the Next.js proxy in front it is the proxy itself
// on loopback) and fall back to the last x-forwarded-for hop when there is no
// socket address to read.
//
// NET EFFECT TO BE AWARE OF: because proxy.ts is the only caller of port 3005,
// the recorded address is now the proxy's own loopback address rather than the
// browser's. That is the honest answer — the true browser IP is simply not
// recoverable here today, since nothing in the chain stamps it in a way a
// client cannot overwrite. Capturing it properly means proxy.ts DERIVING a
// value itself (and stripping the inbound x-forwarded-for the way it already
// strips x-user-*), which is a separate change, deliberately not made here.
// The actor identity in the row (actor_user_id / actor_role) comes from the
// proxy-verified session and was never forgeable.
function clientIp(req) {
  try {
    const peer = (req && req.socket && req.socket.remoteAddress) || null;
    if (peer) return peer;
    const fwd = req && req.headers && req.headers['x-forwarded-for'];
    if (fwd) {
      const hops = String(fwd).split(',');
      return hops[hops.length - 1].trim() || null;
    }
    return null;
  } catch (_e) {
    return null;
  }
}

/**
 * @param pool    pg Pool
 * @param req     Express request (for req.rbac + headers)
 * @param action  short dotted action name, e.g. 'settings.update'
 * @param opts    { target, detail, result }
 *                  target  optional identifier acted on (string)
 *                  detail  small JSON-serialisable context object (no secrets)
 *                  result  'success' | 'error' (defaults to 'success')
 */
async function writeAudit(pool, req, action, opts) {
  const { target, detail, result } = opts || {};
  try {
    const rbac = (req && req.rbac) || {};
    const actorUserId = rbac.userId != null ? String(rbac.userId) : null;
    const actorRole   = rbac.role || null;
    const sourceIp    = clientIp(req);
    const res         = result || 'success';

    await pool.query(
      `INSERT INTO audit_log
         (actor_user_id, actor_role, action, target, detail, source_ip, result)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        actorUserId,
        actorRole,
        action,
        target != null ? String(target) : null,
        detail != null ? JSON.stringify(detail) : null,
        sourceIp,
        res,
      ]
    );
  } catch (err) {
    // Never throw — auditing failure must not break the user's action.
    console.error('[Audit] Failed to write audit row for action', action, '-', err.message);
  }
}

module.exports = { writeAudit };
