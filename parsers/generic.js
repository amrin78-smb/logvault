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

function parseGeneric(raw, sourceIp) {
  // Try RFC 5424 first (has version number after PRI)
  let m = RFC5424_RE.exec(raw);
  if (m) {
    const pri = decodePRI(m[1]);
    return {
      source_ip:       sourceIp,
      source_host:     m[4] !== '-' ? m[4] : null,
      ...pri,
      vendor:          'generic',
      program:         m[5] !== '-' ? m[5] : null,
      pid:             m[6] !== '-' ? parseInt(m[6]) : null,
      message:         m[8].trim(),
      raw_message:     raw,
      structured_data: { rfc: '5424', msgid: m[7] !== '-' ? m[7] : null },
      is_parsed:       true,
      log_timestamp:   m[3] !== '-' ? new Date(m[3]) : null,
    };
  }

  // Try RFC 3164
  m = RFC3164_RE.exec(raw);
  if (m) {
    const pri = decodePRI(m[1]);
    const year = new Date().getFullYear();
    return {
      source_ip:       sourceIp,
      source_host:     m[3] || null,
      ...pri,
      vendor:          'generic',
      program:         m[4] || null,
      pid:             m[5] ? parseInt(m[5]) : null,
      message:         m[6].trim(),
      raw_message:     raw,
      structured_data: { rfc: '3164' },
      is_parsed:       true,
      log_timestamp:   new Date(`${m[2]} ${year}`),
    };
  }

  // Bare PRI only: <N>message
  const bare = /^<(\d{1,3})>(.*)/.exec(raw);
  if (bare) {
    const pri = decodePRI(bare[1]);
    return {
      source_ip:       sourceIp,
      source_host:     null,
      ...pri,
      vendor:          'generic',
      program:         null,
      message:         bare[2].trim(),
      raw_message:     raw,
      structured_data: { rfc: 'bare' },
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
    structured_data: { rfc: 'none' },
    is_parsed:       false,
    log_timestamp:   null,
  };
}

module.exports = { parseGeneric };
