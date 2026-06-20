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
// These are deliberately conservative: each only fires on an explicitly
// labeled token (key=val / key: val / "from <ip>" / "user '<x>'") so benign
// free-form messages (e.g. "Configured from console") never gain phantom fields.
//
// REAL client/source IP found in the message (NOT the syslog sender).
// Labeled forms: src=, srcip=, source ip=, source-ip=, client ip=, remip=, remote ip=.
const SRCIP_LABELED_RE = /\b(?:src(?:ip)?|source(?:[ _-]?ip)?|rem(?:ip|ote(?:[ _-]?ip)?)|client(?:[ _-]?ip)?)\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})/i;
// "from <ip>" / "from ip <ip>" / "from host <ip>" — a common free-form source idiom.
const SRCIP_FROM_RE    = /\bfrom\s+(?:ip\s+|host\s+)?(\d{1,3}(?:\.\d{1,3}){3})\b/i;
// Destination IP. Labeled: dst=, dstip=, destination ip=, dest ip=. Plus "to <ip>".
const DSTIP_LABELED_RE = /\b(?:dst(?:ip)?|dest(?:ination)?(?:[ _-]?ip)?)\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})/i;
const DSTIP_TO_RE      = /\bto\s+(?:ip\s+|host\s+)?(\d{1,3}(?:\.\d{1,3}){3})\b/i;
// Ports. spt=/sport=/src port=, dpt=/dport=/dst port=.
// NOTE: "port" is mandatory in the src/dst word form (src[_ -]port), because a
// bare "src=10.0.0.1" would otherwise capture the first IP octet as a port.
// spt/sport/dpt/dport are unambiguous port tokens and need no "port" suffix.
const SRCPORT_RE       = /\b(?:spt|sport|src[ _-]?port)\s*[=:]\s*(\d{1,5})\b/i;
const DSTPORT_RE       = /\b(?:dpt|dport|dst[ _-]?port)\s*[=:]\s*(\d{1,5})\b/i;
// account/username found in the message.
// Labeled: user=, usr=, username=, account=, login=.
const USER_LABELED_RE  = /\b(?:user(?:name)?|usr|account|login)\s*[=:]\s*"?([^\s",;]+)/i;
// Quoted/phrased: user 'bob', user "bob", for user bob.
const USER_QUOTED_RE   = /\buser\s+['"]([^'"]+)['"]/i;
const USER_FOR_RE      = /\bfor\s+user\s+([^\s",;]+)/i;
// Protocol. proto=tcp / protocol: udp — restrict to a known set to avoid noise.
const PROTO_RE         = /\bproto(?:col)?\s*[=:]\s*"?(tcp|udp|icmp|icmpv6|gre|esp|ah|igmp|sctp|ip)\b/i;
// Action / verdict. Labeled action=/act= only (a bare word like "deny" anywhere is
// too noisy), restricted to a known verdict set.
const ACTION_RE        = /\b(?:action|act)\s*[=:]\s*"?(allow|allowed|deny|denied|block|blocked|drop|dropped|accept|accepted|reject|rejected|pass|permit)\b/i;
// URL / hostname token. url= or a bare http(s):// URL.
const URL_LABELED_RE   = /\burl\s*[=:]\s*"?(\S+)/i;
const URL_BARE_RE      = /\b(https?:\/\/[^\s",;]+)/i;
// auth-outcome subcategory
const LOGIN_FAILED_RE  = /login\s*fail|logon\s*fail|authentication\s*fail|failed\s*(?:login|logon|password|auth|authentication)|invalid\s*(?:user|password|credentials|login)|auth.*denied|access\s*denied|login\s*denied|permission\s*denied|incorrect\s*password|bad\s*password|account\s*lock/i;
const LOGIN_SUCCESS_RE = /login\s*success|logon\s*success|authentication\s*success|authenticated\s+successfully|accepted\s+password|logged\s+in\s+successfully|successful\s+(?:login|logon|authentication)/i;
// Only classify an auth outcome when the message is plausibly an auth event —
// guards against e.g. a firewall "deny" being mislabeled login_failed.
const AUTH_CONTEXT_RE  = /\b(?:login|logon|log[ _-]?in|auth|authentication|password|credential|user|account|sign[ _-]?in|session)\b/i;

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

// Set sd[key] from the first regex whose capture group validates via `accept`.
// NEVER overwrites an already-present value (preserves caller-supplied fields and
// keeps the first confident match when multiple regexes would fire).
function setFromFirst(sd, key, message, regexes, accept) {
  if (sd[key] !== undefined && sd[key] !== null && sd[key] !== '') return;
  for (let i = 0; i < regexes.length; i++) {
    const m = regexes[i].exec(message);
    if (m && m[1] && (!accept || accept(m[1]))) { sd[key] = m[1]; return; }
  }
}

const isPort = (v) => { const n = Number(v); return Number.isInteger(n) && n >= 0 && n <= 65535; };

/**
 * Light, additive enrichment for the fallback parser. Mutates `sd` (the
 * existing structured_data object — preserving its `rfc` key) by
 * OPPORTUNISTICALLY adding common security fields ONLY when a labeled token
 * confidently matches (and, for IPs/ports, the value validates). Never
 * overwrites a field already on `sd`. Pure, synchronous, regex-only. Does NOT
 * set a top-level `category` — that is taxonomy.js's job.
 */
function enrichStructuredData(sd, message) {
  if (!message || typeof message !== 'string') return sd;

  // srcip: prefer a labeled source token, fall back to "from <ip>/from host <ip>".
  setFromFirst(sd, 'srcip', message, [SRCIP_LABELED_RE, SRCIP_FROM_RE], isValidIPv4);
  // dstip: labeled dst token, fall back to "to <ip>".
  setFromFirst(sd, 'dstip', message, [DSTIP_LABELED_RE, DSTIP_TO_RE], isValidIPv4);

  // ports
  setFromFirst(sd, 'srcport', message, [SRCPORT_RE], isPort);
  setFromFirst(sd, 'dstport', message, [DSTPORT_RE], isPort);

  // user: labeled, then quoted ("user 'bob'"), then "for user bob".
  setFromFirst(sd, 'user', message, [USER_LABELED_RE, USER_QUOTED_RE, USER_FOR_RE]);

  // proto (normalized lower-case) and action (normalized lower-case).
  if (sd.proto === undefined || sd.proto === null || sd.proto === '') {
    const pm = PROTO_RE.exec(message);
    if (pm) sd.proto = pm[1].toLowerCase();
  }
  if (sd.action === undefined || sd.action === null || sd.action === '') {
    const am = ACTION_RE.exec(message);
    if (am) sd.action = am[1].toLowerCase();
  }

  // url / hostname: labeled url= first, then a bare http(s):// token.
  setFromFirst(sd, 'url', message, [URL_LABELED_RE, URL_BARE_RE]);

  // subcategory (auth outcome) — only when the message reads like an auth event,
  // so a firewall "deny" is never mislabeled. Failure takes precedence over success.
  if (sd.subcategory === undefined || sd.subcategory === null || sd.subcategory === '') {
    if (AUTH_CONTEXT_RE.test(message)) {
      if (LOGIN_FAILED_RE.test(message)) sd.subcategory = 'login_failed';
      else if (LOGIN_SUCCESS_RE.test(message)) sd.subcategory = 'login_success';
    }
  }

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
