'use strict';

/**
 * Risk Scoring — 0..100 per log entry.
 *
 * Combines severity, category, action and known-bad message patterns into a
 * single risk score used for prioritization and the Log Explorer risk badge.
 */

function scoreLog(entry) {
  let score = 0;

  // Severity (0-40 points)
  const sevScores = { 0: 40, 1: 35, 2: 30, 3: 20, 4: 10, 5: 5, 6: 2, 7: 0 };
  score += sevScores[entry.severity] || 0;

  // Category (0-25 points)
  const catScores = {
    security: 25, authentication: 20, vpn: 15,
    firewall: 10, configuration: 15, dlp: 20,
    routing: 10, interface: 5, wireless: 8,
    dns: 8, web: 5, email: 10, system: 8, network: 3,
  };
  const cat = entry.structured_data?.category || 'network';
  score += catScores[cat] || 0;

  const sd = entry.structured_data || {};

  // Action (0-20 points)
  const action = String(sd.action || '').toLowerCase();
  if (action === 'blocked')    score += 5;
  if (action === 'quarantine') score += 10;
  if (action === 'alert')      score += 15;

  // Auth-failure actions / subcategories — brute-force precursors (defensive: fields may be absent)
  const sub = String(sd.subcategory || '').toLowerCase();
  if (action === 'ssl-login-fail' || action === 'ssl-exit-error') score += 18;
  if (sub === 'login_failed') score += 15;
  if (sub === 'auth_failed')  score += 12;

  // Denied/blocked traffic — generic across vendors
  if (/^(deny|drop|block|reject)/.test(action)) score += 8;

  // Bad geography — generic: a denied/failed event from a non-local (foreign) source IP.
  // No customer-specific home country hardcoded; only nudges when the event is already
  // suspicious (denied/blocked or an auth-failure) and the source country is present & non-local.
  const srcCountry = String(sd.srccountry || '').toLowerCase();
  const isSuspicious = /^(deny|drop|block|reject|blocked|ssl-login-fail|ssl-exit-error)/.test(action)
    || sub === 'login_failed' || sub === 'auth_failed';
  const LOCAL_GEO = new Set(['', 'reserved', 'unspecified', 'n/a', 'na', 'private']);
  if (isSuspicious && !LOCAL_GEO.has(srcCountry)) score += 6;

  // FortiOS's own threat signal (URL/IPS reputation rating) when present
  const crlevel = String(sd.crlevel || '').toLowerCase();
  if (crlevel === 'critical') score += 18;
  else if (crlevel === 'high') score += 12;
  const crscore = parseInt(sd.crscore, 10);
  if (!isNaN(crscore)) {
    if (crscore >= 50) score += 12;
    else if (crscore >= 20) score += 6;
  }

  // Known bad patterns (0-15 points bonus each)
  const msg = (entry.message || '').toLowerCase();
  if (/brute.?force|repeated.?fail|account.?lock/i.test(msg)) score += 15;
  if (/malware|ransomware|trojan|exploit/i.test(msg))          score += 15;
  if (/after.?hours|outside.?business/i.test(msg))             score += 10;
  if (/privilege.?escalat|sudo|admin.?login/i.test(msg))       score += 10;
  if (/data.?exfil|dlp|sensitive/i.test(msg))                  score += 15;

  return Math.min(score, 100);
}

module.exports = { scoreLog };
