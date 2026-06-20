'use strict';

/**
 * Risk Scoring — 0..100 per log entry.
 *
 * Combines severity, category, action and known-bad message patterns into a
 * single risk score used for prioritization and the Log Explorer risk badge.
 */

// Human-readable labels for the severity bands used in factor explanations.
const SEV_LABELS = {
  0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
  4: 'warning', 5: 'notice', 6: 'informational', 7: 'debug',
};

/**
 * Risk scoring with explainability. Mirrors the historical scoreLog logic
 * exactly, but records every rule that contributed points so the UI can
 * answer "Why this score?".
 *
 * @returns {{ score: number, factors: Array<{label: string, points: number}> }}
 *   factors is sorted by points descending; score is the same clamped sum.
 *   Kept pure and synchronous (ingest hot path).
 */
function scoreLogExplained(entry) {
  let score = 0;
  const factors = [];
  const add = (label, points) => { score += points; factors.push({ label, points }); };

  // Severity (0-40 points)
  const sevScores = { 0: 40, 1: 35, 2: 30, 3: 20, 4: 10, 5: 5, 6: 2, 7: 0 };
  const sevPts = sevScores[entry.severity] || 0;
  if (sevPts > 0) {
    const sevLabel = SEV_LABELS[entry.severity] || `level ${entry.severity}`;
    add(`Severity: ${sevLabel}`, sevPts);
  }

  // Category (0-25 points)
  const catScores = {
    security: 25, authentication: 20, vpn: 15,
    firewall: 10, configuration: 15, dlp: 20,
    routing: 10, interface: 5, wireless: 8,
    dns: 8, web: 5, email: 10, system: 8, network: 3,
  };
  const cat = entry.structured_data?.category || 'network';
  const catPts = catScores[cat] || 0;
  if (catPts > 0) add(`Category: ${cat}`, catPts);

  const sd = entry.structured_data || {};

  // Action (0-20 points)
  const action = String(sd.action || '').toLowerCase();
  if (action === 'blocked')    add('Action: blocked', 5);
  if (action === 'quarantine') add('Action: quarantine', 10);
  if (action === 'alert')      add('Action: alert', 15);

  // Auth-failure actions / subcategories — brute-force precursors (defensive: fields may be absent)
  const sub = String(sd.subcategory || '').toLowerCase();
  if (action === 'ssl-login-fail' || action === 'ssl-exit-error') add('Action: SSL-VPN login failed', 18);
  if (sub === 'login_failed') add('Subcategory: login failed', 15);
  if (sub === 'auth_failed')  add('Subcategory: authentication failed', 12);

  // Denied/blocked traffic — generic across vendors
  if (/^(deny|drop|block|reject)/.test(action)) add('Action: denied/blocked traffic', 8);

  // Bad geography — generic: a denied/failed event from a non-local (foreign) source IP.
  // No customer-specific home country hardcoded; only nudges when the event is already
  // suspicious (denied/blocked or an auth-failure) and the source country is present & non-local.
  const srcCountry = String(sd.srccountry || '').toLowerCase();
  const isSuspicious = /^(deny|drop|block|reject|blocked|ssl-login-fail|ssl-exit-error)/.test(action)
    || sub === 'login_failed' || sub === 'auth_failed';
  const LOCAL_GEO = new Set(['', 'reserved', 'unspecified', 'n/a', 'na', 'private']);
  if (isSuspicious && !LOCAL_GEO.has(srcCountry)) add('Foreign source on failed-auth', 6);

  // FortiOS's own threat signal (URL/IPS reputation rating) when present
  const crlevel = String(sd.crlevel || '').toLowerCase();
  if (crlevel === 'critical') add('FortiGate threat level: critical', 18);
  else if (crlevel === 'high') add('FortiGate threat level: high', 12);
  const crscore = parseInt(sd.crscore, 10);
  if (!isNaN(crscore)) {
    if (crscore >= 50) add(`FortiGate threat score: ${crscore}`, 12);
    else if (crscore >= 20) add(`FortiGate threat score: ${crscore}`, 6);
  }

  // Cross-vendor threat-name bonus — IPS/threat events from vendors WITHOUT
  // Fortinet's crlevel/crscore (Palo Alto, Check Point, Juniper, Cisco, etc.)
  // still carry a named signature/threat/attack; nudge those up. Complements,
  // not replaces, the crlevel/crscore boosts above.
  const THREAT_NAME_KEYS = ['threat', 'signature', 'attack', 'protection_name', 'situation', 'threat_name'];
  for (const k of THREAT_NAME_KEYS) {
    if (String(sd[k] || '').trim() !== '') { add('Threat signature present', 12); break; }
  }

  // Known bad patterns (0-15 points bonus each)
  const msg = (entry.message || '').toLowerCase();
  if (/brute.?force|repeated.?fail|account.?lock/i.test(msg)) add('Message: brute-force / account lockout', 15);
  if (/malware|ransomware|trojan|exploit/i.test(msg))          add('Message: malware / exploit', 15);
  if (/after.?hours|outside.?business/i.test(msg))             add('Message: after-hours activity', 10);
  if (/privilege.?escalat|sudo|admin.?login/i.test(msg))       add('Message: privilege escalation', 10);
  if (/data.?exfil|dlp|sensitive/i.test(msg))                  add('Message: data exfiltration / DLP', 15);

  factors.sort((a, b) => b.points - a.points);
  return { score: Math.min(score, 100), factors };
}

// Backwards-compatible: returns just the clamped numeric score (unchanged contract).
function scoreLog(entry) {
  return scoreLogExplained(entry).score;
}

module.exports = { scoreLog, scoreLogExplained };
