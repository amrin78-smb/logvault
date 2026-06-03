/**
 * SonicWall Parser for LogVault
 *
 * SonicWall (SonicOS) emits key=value syslog. Example:
 *   id=firewall sn=0012ABCD time="2026-05-29 10:00:00" fw=192.168.1.1 pri=5
 *   c=1024 m=537 msg="Connection Dropped" n=1234 src=10.1.1.5:1234:X0
 *   dst=8.8.8.8:443:X1 proto=TCP/HTTPS rule="LAN to WAN"
 */

'use strict';

// SonicWall pri (priority) → syslog severity number + label
function priToSeverity(pri) {
  const n = parseInt(pri);
  if (isNaN(n))      return { severity: 6, label: 'info' };
  if (n <= 2)        return { severity: 2, label: 'critical' };
  if (n <= 4)        return { severity: 3, label: 'error' };
  if (n === 5)       return { severity: 4, label: 'warning' };
  return { severity: 6, label: 'info' };
}

function detectSonicWall(raw) {
  if (!raw) return false;
  if (/id=firewall/i.test(raw)) return true;
  if (/id=sonicos/i.test(raw))  return true;
  if (/sn=[A-Z0-9]+\s+.*\bfw=/i.test(raw)) return true;
  return false;
}

// Parse key=value pairs (values may be quoted)
function parseKV(str) {
  const kv = {};
  const re = /(\w+)=(?:"([^"]*)"|(\S+))/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    kv[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }
  return kv;
}

// SonicWall src/dst use ip:port:interface — split out the parts
function splitEndpoint(val) {
  if (!val) return { ip: null, port: null, iface: null };
  const parts = val.split(':');
  return {
    ip:    parts[0] || null,
    port:  parts[1] ? parseInt(parts[1]) : null,
    iface: parts[2] || null,
  };
}

function actionFromMsg(msg) {
  if (!msg) return null;
  if (/dropp?ed|blocked|denied/i.test(msg))            return 'blocked';
  if (/allowed|connection opened|permitted/i.test(msg)) return 'allowed';
  return null;
}

function parseSonicWall(raw, sourceIp) {
  try {
    if (!detectSonicWall(raw)) return null;

    const stripped = raw.replace(/^<\d{1,3}>/, '').trim();
    const kv = parseKV(stripped);

    const sev    = priToSeverity(kv.pri);
    const action = actionFromMsg(kv.msg);
    const src    = splitEndpoint(kv.src);
    const dst    = splitEndpoint(kv.dst);

    let logTimestamp = null;
    if (kv.time) {
      const d = new Date(kv.time.replace(' ', 'T'));
      if (!isNaN(d.getTime())) logTimestamp = d;
    }

    let message = 'SonicWall';
    if (kv.msg) message += `: ${kv.msg}`;
    if (src.ip && dst.ip) message += ` ${src.ip} -> ${dst.ip}`;
    if (kv.proto) message += ` proto=${kv.proto}`;
    if (kv.rule) message += ` rule="${kv.rule}"`;

    const structured = {
      category:     'firewall',
      action,
      serial:       kv.sn || null,
      firewall_ip:  kv.fw || null,
      msg:          kv.msg || null,
      src_ip:       src.ip,
      src_port:     src.port,
      src_iface:    src.iface,
      dst_ip:       dst.ip,
      dst_port:     dst.port,
      dst_iface:    dst.iface,
      protocol:     kv.proto || null,
      rule:         kv.rule || null,
      priority:     kv.pri ? parseInt(kv.pri) : null,
      message_id:   kv.m || null,
    };
    Object.keys(structured).forEach(k => (structured[k] == null) && delete structured[k]);

    return {
      source_ip:       sourceIp,
      source_host:     kv.fw || null,
      facility:        23,
      facility_label:  'local7',
      severity:        sev.severity,
      severity_label:  sev.label,
      vendor:          'sonicwall',
      program:         'SonicWall',
      message,
      raw_message:     raw,
      structured_data: structured,
      is_parsed:       true,
      log_timestamp:   logTimestamp,
      parser_version:  'sonicwall-v1.0',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseSonicWall, detectSonicWall };
