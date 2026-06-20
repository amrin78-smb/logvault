/**
 * Generic Syslog Parser
 * Handles RFC 3164 (BSD syslog) and RFC 5424 (structured syslog)
 * This is the fallback parser - runs last in the chain
 */

'use strict';

const SEVERITY_LABELS = ['emergency','alert','critical','error','warning','notice','info','debug'];
const FACILITY_LABELS = [
  'kern','user','mail','daemon','auth','syslog','lpr','news',
  'uucp','cron','authpriv','ftp','ntp','audit','alert2','clock',
  'local0','local1','local2','local3','local4','local5','local6','local7'
];

/**
 * Decode PRI field: <NN> at start of message
 * PRI = (facility * 8) + severity
 */
function decodePRI(pri) {
  const val = parseInt(pri, 10);
  return {
    facility:       Math.floor(val / 8),
    severity:       val % 8,
    severity_label: SEVERITY_LABELS[val % 8] || 'info',
    facility_label: FACILITY_LABELS[Math.floor(val / 8)] || 'local0',
  };
}

/**
 * RFC 3164: <PRI>TIMESTAMP HOST TAG MSG
 * Example: <189>May 12 10:23:01 router1 %SYS-5-CONFIG_I: Configured from console
 */
const RFC3164_RE = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)/s;

/**
 * RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PID MSGID STRUCTURED-DATA MSG
 * Example: <34>1 2026-05-12T10:23:01.123Z myhost sshd 1234 - - Connection closed
 */
const RFC5424_RE = /^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/s;

// --- Opportunistic token-extraction regexes (run on the parsed message) ---
// REAL client/source IP found in the message (NOT the syslog sender).
const SRCIP_LABELED_RE = /\b(?:src(?:ip)?|source(?:[ _-]?ip)?|remip|client(?:[ _-]?ip)?|from(?:\s+ip)?)\s*[=:]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i;
const SRCIP_FROM_RE    = /\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i;
// account/username found in the message
const USER_RE          = /\b(?:user(?:name)?|usr|account|login)\s*[=:]\s*"?([^\s",;]+)/i;
// auth-outcome subcategory
const LOGIN_FAILED_RE  = /login\s*fail|authentication\s*fail|failed\s*(?:login|logon|password|auth)|auth.*denied|access\s*denied/i;
const LOGIN_SUCCESS_RE = /login\s*success|authenticated successfully|accepted password/i;

// Every octet of a dotted-quad must be 0-255.
function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

/**
 * Light, additive enrichment for the fallback parser. Mutates `sd` (the
 * existing structured_data object — preserving its `rfc` key) by adding
 * srcip / user / subcategory ONLY when a regex confidently matches (and,
 * for IPs, every octet validates). Pure, synchronous, regex-only.
 */
function enrichStructuredData(sd, message) {
  if (!message || typeof message !== 'string') return sd;

  // srcip: prefer a labeled source token, fall back to "from <ip>".
  let ipMatch = SRCIP_LABELED_RE.exec(message);
  if (!ipMatch) ipMatch = SRCIP_FROM_RE.exec(message);
  if (ipMatch && isValidIPv4(ipMatch[1])) sd.srcip = ipMatch[1];

  // user
  const userMatch = USER_RE.exec(message);
  if (userMatch) sd.user = userMatch[1];

  // subcategory (auth outcome) — failure takes precedence over success.
  if (LOGIN_FAILED_RE.test(message)) sd.subcategory = 'login_failed';
  else if (LOGIN_SUCCESS_RE.test(message)) sd.subcategory = 'login_success';

  return sd;
}

function parseGeneric(raw, sourceIp) {
  // Try RFC 5424 first (has version number after PRI)
  let m = RFC5424_RE.exec(raw);
  if (m) {
    const pri = decodePRI(m[1]);
    const message = m[8].trim();
    return {
      source_ip:       sourceIp,
      source_host:     m[4] !== '-' ? m[4] : null,
      ...pri,
      vendor:          'generic',
      program:         m[5] !== '-' ? m[5] : null,
      pid:             m[6] !== '-' ? parseInt(m[6]) : null,
      message:         message,
      raw_message:     raw,
      structured_data: enrichStructuredData({ rfc: '5424', msgid: m[7] !== '-' ? m[7] : null }, message),
      is_parsed:       true,
      log_timestamp:   m[3] !== '-' ? new Date(m[3]) : null,
    };
  }

  // Try RFC 3164
  m = RFC3164_RE.exec(raw);
  if (m) {
    const pri = decodePRI(m[1]);
    const year = new Date().getFullYear();
    const message = m[6].trim();
    return {
      source_ip:       sourceIp,
      source_host:     m[3] || null,
      ...pri,
      vendor:          'generic',
      program:         m[4] || null,
      pid:             m[5] ? parseInt(m[5]) : null,
      message:         message,
      raw_message:     raw,
      structured_data: enrichStructuredData({ rfc: '3164' }, message),
      is_parsed:       true,
      log_timestamp:   new Date(`${m[2]} ${year}`),
    };
  }

  // Bare PRI only: <N>message
  const bare = /^<(\d{1,3})>(.*)/.exec(raw);
  if (bare) {
    const pri = decodePRI(bare[1]);
    const message = bare[2].trim();
    return {
      source_ip:       sourceIp,
      source_host:     null,
      ...pri,
      vendor:          'generic',
      program:         null,
      message:         message,
      raw_message:     raw,
      structured_data: enrichStructuredData({ rfc: 'bare' }, message),
      is_parsed:       true,
      log_timestamp:   null,
    };
  }

  // No PRI at all - treat as raw text severity=info
  return {
    source_ip:       sourceIp,
    source_host:     null,
    facility:        1,
    severity:        6,
    severity_label:  'info',
    facility_label:  'user',
    vendor:          'generic',
    program:         null,
    message:         raw,
    raw_message:     raw,
    structured_data: enrichStructuredData({ rfc: 'none' }, raw),
    is_parsed:       false,
    log_timestamp:   null,
  };
}

module.exports = { parseGeneric };
