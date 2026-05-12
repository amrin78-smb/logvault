/**
 * Fortinet FortiOS Syslog Parser
 *
 * FortiOS logs use key=value pairs after the syslog header.
 * Example: <190>date=2026-05-12 time=10:23:01 devname=FW01 devid=FGT60F logid=0000000013
 *          type=traffic subtype=forward level=notice vd=root srcip=192.168.1.10 dstip=8.8.8.8
 *          action=accept
 */

'use strict';

const FORTI_SEV_MAP = {
  'emergency': 0, 'alert': 1, 'critical': 2, 'error': 3,
  'warning': 4, 'notice': 5, 'information': 6, 'debug': 7,
};

// Fortinet logs always contain date= and devname= or logid=
const FORTI_DETECT_RE = /\bdate=\d{4}-\d{2}-\d{2}\b.*\btype=/;

function parseFortinet(raw, sourceIp) {
  if (!FORTI_DETECT_RE.test(raw)) return null;

  // Strip syslog PRI and header if present
  const stripped = raw.replace(/^<\d{1,3}>/, '').trim();

  // Parse key=value pairs (handles values with and without quotes)
  const kv = {};
  const kvRe = /(\w+)=(?:"([^"]*)"|([\S]*))/g;
  let m;
  while ((m = kvRe.exec(stripped)) !== null) {
    kv[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }

  if (!kv.type) return null;

  // Timestamp
  let logTimestamp = null;
  if (kv.date && kv.time) {
    try { logTimestamp = new Date(`${kv.date}T${kv.time}`); } catch (_) {}
  }

  // Severity
  const levelStr    = (kv.level || 'information').toLowerCase();
  const severity    = FORTI_SEV_MAP[levelStr] ?? 6;
  const sevLabel    = levelStr === 'information' ? 'info' : levelStr;

  // Build message
  let message = `FortiOS ${kv.type}`;
  if (kv.subtype) message += `/${kv.subtype}`;
  if (kv.srcip && kv.dstip) message += `: ${kv.srcip} -> ${kv.dstip}`;
  if (kv.service) message += ` svc=${kv.service}`;
  if (kv.action) message += ` action=${kv.action}`;
  if (kv.msg) message += ` | ${kv.msg}`;

  return {
    source_ip:       sourceIp,
    source_host:     kv.devname || null,
    facility:        23,
    facility_label:  'local7',
    severity,
    severity_label:  sevLabel,
    vendor:          'fortinet',
    program:         `FortiOS/${kv.type}`,
    message,
    raw_message:     raw,
    structured_data: {
      devname:  kv.devname,
      devid:    kv.devid,
      logid:    kv.logid,
      type:     kv.type,
      subtype:  kv.subtype,
      srcip:    kv.srcip,
      dstip:    kv.dstip,
      action:   kv.action,
      policy:   kv.policyid,
      vd:       kv.vd,
      msg:      kv.msg,
    },
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseFortinet };
