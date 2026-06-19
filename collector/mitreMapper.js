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

  // T1110 Brute Force (Credential Access) — failed/repeated auth, lockouts.
  // Message regex covers the dominant phrasings ("login failed", "authentication
  // failure", "failed login/logon/auth"), not just the Cisco-only subcategory enum.
  if (sub === 'brute_force' || sub === 'login_failed' || sub === 'auth_failed' ||
      /brute.?force|password\s*spray|account.?lock|login.{0,12}fail|authentication fail(?:ed|ure)?|failed (?:login|logon|auth)/i.test(msg)) {
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
