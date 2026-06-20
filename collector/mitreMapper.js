'use strict';

/**
 * MITRE ATT&CK technique mapper (EVENT-level, technique granularity).
 *
 * Pure synchronous classifier — mirrors collector/taxonomy.js and
 * collector/riskScorer.js. Runs once per ingested entry on the hot path, so it
 * MUST stay pure CPU: no DB, no network, no async. Reuses the same signals the
 * other enrichers already parse (category, structured_data.subcategory /
 * subtype / type — e.g. Fortinet sets subtype='ips'|'vpn' — and message keywords).
 *
 * Returns an array of ATT&CK technique IDs (e.g. ['T1110','T1133']) or [] when
 * nothing applies. Keep the ID set in sync with the catalog in
 * frontend/src/components/mitre.tsx and the rule map in
 * collector/correlationEngine.js (MITRE_BY_RULE).
 */

function mapTechniques(entry) {
  const s    = (entry && entry.structured_data) || {};
  const cat  = s.category || (entry && entry.category) || '';
  const sub  = String(s.subcategory || '').toLowerCase();
  const subt = String(s.subtype || '').toLowerCase();
  const typ  = String(s.type || '').toLowerCase();
  const msg  = (entry && entry.message) || '';
  const ids  = new Set();

  // T1110 Brute Force (Credential Access) — REPEATED auth attempts / lockouts only.
  // A single failed login/logon/auth (e.g. a lone FortiOS action=ssl-login-fail) is NOT
  // brute force — brute force means many attempts. Tagging every individual auth failure
  // T1110 at the event level produced a "Brute Force" badge on routine one-off failures
  // and drowned out real signal, so the generic failed-login triggers (the login.{0,12}fail
  // / "authentication failure" regex and the login_failed/auth_failed subcategories) were
  // REMOVED here. Brute force is now determined at the correlation altitude:
  // BRUTE_FORCE_SUCCESS (3+ failures then success) and VPN_BRUTE_FORCE (5+ VPN failures in
  // 5 min) in collector/correlationEngine.js (MITRE_BY_RULE). This mirrors the T1133
  // decision below.
  // Event-level T1110 is kept ONLY when a SINGLE message itself attests repetition/lockout
  // (an already-correlated signal), e.g. "account locked", "password spray", "repeated" or
  // "multiple failed" attempts — or the pre-correlated sub === 'brute_force' subcategory.
  if (sub === 'brute_force' ||
      /brute.?force|password\s*spray|account.?lock(?:ed|out)?|(?:repeated|multiple|consecutive|\d+)\s+(?:failed|invalid)\s+(?:login|logon|auth|password|sign)/i.test(msg)) {
    ids.add('T1110');
  }
  // NOTE: T1133 External Remote Services is intentionally NOT tagged at the event
  // level. Keying it off VPN category/subtype tagged ALL routine VPN traffic (IPsec
  // negotiate, SSL alerts) as a technique, which is benign tunnel activity and drowned
  // out real signal in the coverage view. T1133 is mapped only on the VPN_BRUTE_FORCE
  // correlation rule (collector/correlationEngine.js MITRE_BY_RULE), which is the
  // security-relevant altitude for "adversary used external remote services".

  // T1046 Network Service Discovery (Discovery) — scanning
  if (/port\s*scan|host\s*sweep|\bnmap\b|network scan/i.test(msg)) {
    ids.add('T1046');
  }
  // T1190 Exploit Public-Facing Application (Initial Access) — IPS/UTM threats.
  // Fortinet/Palo Alto carry the structured discriminator subtype/type='ips'.
  if (subt === 'ips' || typ === 'ips' ||
      /utm\/ips|\bips\b|intrusion|exploit|signature matched|attack detected/i.test(msg)) {
    ids.add('T1190');
  }
  // T1486 Data Encrypted for Impact — ransomware
  if (/ransomware|crypto-?lock/i.test(msg)) ids.add('T1486');
  // T1068 Exploitation for Privilege Escalation
  if (/privilege.?escalat/i.test(msg)) ids.add('T1068');
  // T1078 Valid Accounts (Initial Access) — admin / sudo logins
  if (/\bsudo\b|admin.?login|administrator log(?:on|in)/i.test(msg)) ids.add('T1078');
  // T1562 Impair Defenses (Defense Evasion) — disabling/clearing logging or security
  if (/disabl(?:e|ed).*(?:log|firewall|protection)|clear(?:ed)?.*log|impair/i.test(msg)) {
    ids.add('T1562');
  }
  // T1567 Exfiltration Over Web Service — DLP / data exfil
  if (cat === 'dlp' || /data.?exfil|exfiltrat|\bdlp\b|sensitive data/i.test(msg)) {
    ids.add('T1567');
  }
  // T1498 Network Denial of Service
  if (/denial of service|\bddos\b|\bdos attack\b|syn flood/i.test(msg)) ids.add('T1498');

  return Array.from(ids);
}

module.exports = { mapTechniques };
