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

// Best-effort client IP. With the Next.js proxy in front, x-forwarded-for is
// the most reliable source; fall back to the socket peer (likely the proxy).
function clientIp(req) {
  try {
    const fwd = req && req.headers && req.headers['x-forwarded-for'];
    if (fwd) {
      // x-forwarded-for can be a comma-separated chain; take the first hop.
      return String(fwd).split(',')[0].trim();
    }
    return (req && req.socket && req.socket.remoteAddress) || null;
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
