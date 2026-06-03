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

  // Action (0-20 points)
  const action = entry.structured_data?.action;
  if (action === 'blocked')    score += 5;
  if (action === 'quarantine') score += 10;
  if (action === 'alert')      score += 15;

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
