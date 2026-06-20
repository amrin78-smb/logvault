/**
 * Palo Alto PAN-OS Syslog Parser
 *
 * PAN-OS logs are CSV-formatted with a type field as the 4th column.
 * Example TRAFFIC: 1,2026/05/12 10:23:01,012345678,TRAFFIC,end,...
 * Example THREAT:  1,2026/05/12 10:23:01,012345678,THREAT,vulnerability,...
 */

'use strict';

// PAN-OS log types
const PANLOG_TYPES = new Set(['TRAFFIC','THREAT','CONFIG','SYSTEM','HIPMATCH','GLOBALPROTECT','AUTHENTICATION','USERID']);

// Map PAN-OS severity strings to syslog severity numbers
const PAN_SEV_MAP = {
  'critical': 2, 'high': 3, 'medium': 4, 'low': 5, 'informational': 6, 'info': 6,
};

// Loose IPv4 validator (4 octets, each 0-255). Used to defensively confirm a
// CSV column actually holds an IP before we trust a schema-dependent index.
function isIpv4(v) {
  if (!v) return false;
  const m = String(v).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}

// Scan a row for the Nth (default first) column that looks like a valid IPv4.
// Fallback for when the exact schema-version column index is uncertain.
function findIp(cols, skip) {
  let seen = 0;
  for (const c of cols) {
    if (isIpv4(c)) { if (seen >= (skip || 0)) return String(c).trim(); seen++; }
  }
  return undefined;
}

function parsePaloAlto(raw, sourceIp) {
  // PAN-OS LEEF or syslog-wrapped CSV
  // Quick detection: contains a PAN-OS log type token in known positions
  const stripped = raw.replace(/^<\d{1,3}>/, '').trim();

  // CSV split (basic - PAN logs don't quote fields generally)
  const cols = stripped.split(',');
  if (cols.length < 5) return null;

  // Check if column 3 (0-indexed) is a known PAN log type
  const logType = cols[3]?.trim().toUpperCase();
  if (!PANLOG_TYPES.has(logType)) return null;

  // Serial number in col 2, timestamp in col 1
  const tsStr   = cols[1]?.trim();   // "2026/05/12 10:23:01"
  const serial  = cols[2]?.trim();
  const subtype = cols[4]?.trim();   // e.g. "end", "vulnerability"

  let logTimestamp = null;
  try { logTimestamp = tsStr ? new Date(tsStr) : null; } catch (_) {}

  // Determine severity from log type
  let severity = 6; let severityLabel = 'info';
  if (logType === 'THREAT') { severity = 4; severityLabel = 'warning'; }
  if (logType === 'SYSTEM') {
    const sev = cols[6]?.trim().toLowerCase();
    if (PAN_SEV_MAP[sev] !== undefined) { severity = PAN_SEV_MAP[sev]; severityLabel = sev; }
  }

  // Build a human-readable message summary
  let message = `PAN-OS ${logType}`;
  if (subtype) message += ` [${subtype}]`;

  // Normalized fields the correlation engine + UI rely on (exact keys).
  // These are populated per log-type below and merged into structured_data.
  // IMPORTANT: PAN-OS CSV field positions VARY by log type AND PAN-OS version
  // (8.x/9.x/10.x/11.x add columns). The indices below are best-effort defaults
  // and WILL need tuning against real PAN-OS samples (we have none yet). To stay
  // robust we validate IPs (isIpv4) and fall back to scanning the row for the
  // first valid-looking IP when the expected column is missing/short.
  const norm = {};        // extra structured_data keys (srcip/dstip/user/...)
  let category = 'system'; // top-level taxonomy category (default for SYSTEM/etc.)

  // For TRAFFIC logs: src/dst IPs are at known columns (8.x+: src=6, dst=7).
  if (logType === 'TRAFFIC' && cols.length > 13) {
    const srcip = isIpv4(cols[7]) ? cols[7].trim() : findIp(cols, 0);
    const dstip = isIpv4(cols[8]) ? cols[8].trim() : findIp(cols, 1);
    const app   = cols[24]?.trim(); const action = cols[30]?.trim();
    if (srcip && dstip) message += `: ${srcip} -> ${dstip}`;
    if (app) message += ` app=${app}`;
    if (action) message += ` action=${action}`;
    // Persist the real src/dst (previously only string-concatenated into message).
    if (srcip) norm.srcip = srcip;
    if (dstip) norm.dstip = dstip;
    category = 'firewall';
  }

  if (logType === 'THREAT' && cols.length > 15) {
    const srcip   = isIpv4(cols[7]) ? cols[7].trim() : findIp(cols, 0);
    const dstip   = isIpv4(cols[8]) ? cols[8].trim() : findIp(cols, 1);
    const threat  = cols[26]?.trim(); const action = cols[28]?.trim();
    if (srcip && dstip) message += `: ${srcip} -> ${dstip}`;
    if (threat) message += ` threat=${threat}`;
    if (action) message += ` action=${action}`;
    if (srcip) norm.srcip = srcip;
    if (dstip) norm.dstip = dstip;
    norm.type = 'ips';           // intrusion-prevention signal for downstream
    category = 'security';
  }

  // GLOBALPROTECT (VPN): the real client is the GlobalProtect public IP, NOT the
  // syslog sender. Subtypes include gateway-auth-fail / portal-auth-fail / *-auth /
  // login etc. PAN-OS 9.1+ GP CSV roughly: ...,public-ip(GP client),...,source-region,...,user.
  // Column layout differs a lot across versions, so we validate + scan as a fallback.
  if (logType === 'GLOBALPROTECT') {
    category = 'vpn';
    const sub = (subtype || '').toLowerCase();
    // GP client public IP — best-effort index (10.x ~ col 8), else first valid IP.
    const pubip = isIpv4(cols[8]) ? cols[8].trim() : findIp(cols, 0);
    if (pubip) norm.srcip = pubip;
    // Source region/country — best-effort index near col 9.
    const region = cols[9]?.trim();
    if (region && !isIpv4(region)) norm.srccountry = region;
    // User/account — best-effort index near col 7; skip if it looks like an IP.
    const user = cols[7]?.trim();
    if (user && !isIpv4(user)) norm.user = user;
    if (/auth-fail|fail|denied/.test(sub))      norm.subcategory = 'login_failed';
    else if (/auth|login|success/.test(sub))    norm.subcategory = 'login_success';
    if (norm.user) message += ` user=${norm.user}`;
    if (norm.srcip) message += ` from=${norm.srcip}`;
  }

  // AUTHENTICATION: map Source IP column -> srcip, User -> user, result -> subcategory.
  // PAN-OS auth CSV roughly: ...,source-ip,...,user,...,event(success/failure).
  if (logType === 'AUTHENTICATION') {
    category = 'authentication';
    // Source IP (the attacker for inbound auth) — best-effort, else first valid IP.
    const srcip = isIpv4(cols[8]) ? cols[8].trim() : findIp(cols, 0);
    if (srcip) norm.srcip = srcip;
    const user = cols[7]?.trim();
    if (user && !isIpv4(user)) norm.user = user;
    // Auth result: look for an explicit success/failure token anywhere in the row.
    const joined = stripped.toLowerCase();
    if (/\bfail|failure|denied|invalid\b/.test(joined))      norm.subcategory = 'login_failed';
    else if (/\bsuccess|succeeded|allowed\b/.test(joined))   norm.subcategory = 'login_success';
    else norm.subcategory = 'login_failed'; // auth events without a token: default to failed (safer for alerting)
    if (norm.user) message += ` user=${norm.user}`;
    if (norm.srcip) message += ` from=${norm.srcip}`;
  }

  return {
    source_ip:       sourceIp,
    source_host:     null,
    facility:        23,
    facility_label:  'local7',
    severity,
    severity_label:  severityLabel,
    vendor:          'paloalto',
    program:         `PAN-OS/${logType}`,
    message,
    raw_message:     raw,
    // Additive: keep log_type/subtype/serial; merge normalized contract keys
    // (srcip/dstip/user/srccountry/subcategory/type) when present.
    structured_data: { log_type: logType, subtype, serial, ...norm },
    category,
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parsePaloAlto };
