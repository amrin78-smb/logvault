/**
 * Juniper Parser for LogVault
 *
 * Covers Juniper SRX (RT_FLOW / RT_IDP) and EX switching structured syslog.
 *
 * 1. SRX flow:
 *    <pri>timestamp host RT_FLOW: RT_FLOW_SESSION_CREATE: session created
 *    10.1.1.5/1234->8.8.8.8/443 junos-https None 10.1.1.5/1234->8.8.8.8/443
 *    inbound-zone->outbound-zone ethernet0/0
 *
 * 2. SRX IDP/IPS:
 *    <pri>timestamp host RT_IDP: IDP_ATTACK_LOG_EVENT: IDP: attack repeat=1,
 *    action=DROP, threat-severity=HIGH, attack-name=HTTP:OVERFLOW:CVE-2021-12345,
 *    src-ip=185.220.101.1, src-port=45123, dst-ip=10.1.1.5, dst-port=80,
 *    protocol-name=TCP
 *
 * 3. EX switching:
 *    <pri>timestamp host mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex=503, ifAdminStatus=up
 */

'use strict';

const SEV_LABELS = ['emergency','alert','critical','error','warning','notice','info','debug'];

// Threat severity (IDP) → syslog severity
const THREAT_SEV = {
  critical: { severity: 2, label: 'critical' },
  high:     { severity: 3, label: 'error' },
  medium:   { severity: 4, label: 'warning' },
  low:      { severity: 5, label: 'notice' },
  info:     { severity: 6, label: 'info' },
};

function detectJuniper(raw) {
  if (!raw) return false;
  if (/RT_FLOW:/.test(raw))   return true;
  if (/RT_IDP:/.test(raw))    return true;
  if (/JUNOS/i.test(raw))     return true;
  if (/\bRT_[A-Z_]+:/.test(raw)) return true;
  return false;
}

// Pull "key=value" or "key-name=value" (comma or space separated, optional trailing comma)
function parseKV(str) {
  const kv = {};
  if (!str) return kv;
  const re = /([\w-]+)=("([^"]*)"|[^\s,]+)/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    kv[m[1]] = m[3] !== undefined ? m[3] : m[2];
  }
  return kv;
}

function sevFromPri(raw) {
  const m = raw.match(/^<(\d{1,3})>/);
  if (!m) return { severity: 6, label: 'info', facility: 23, facility_label: 'local7' };
  const pri = parseInt(m[1], 10);
  const severity = pri % 8;
  return { severity, label: SEV_LABELS[severity] || 'info', facility: Math.floor(pri / 8), facility_label: 'local7' };
}

function parseJuniper(raw, sourceIp) {
  try {
    if (!detectJuniper(raw)) return null;

    const base = sevFromPri(raw);

    // Extract hostname after timestamp if present
    const hostMatch = raw.match(/^(?:<\d{1,3}>)?\w{3}\s+\d{1,2}\s+[\d:]+\s+(\S+)\s/);
    const sourceHost = hostMatch ? hostMatch[1] : null;

    let severity      = base.severity;
    let severityLabel = base.label;
    let category      = 'network';
    let message       = raw;
    const structured  = {};

    if (/RT_IDP:/.test(raw)) {
      // IDS/IPS attack event
      category = 'security';
      const kv = parseKV(raw);
      const ts = (kv['threat-severity'] || '').toLowerCase();
      if (THREAT_SEV[ts]) { severity = THREAT_SEV[ts].severity; severityLabel = THREAT_SEV[ts].label; }
      else { severity = 3; severityLabel = 'error'; }

      structured.event_type     = 'RT_IDP';
      structured.attack_name    = kv['attack-name'] || null;
      structured.threat_severity = kv['threat-severity'] || null;
      structured.action         = (kv.action || '').toLowerCase().includes('drop') ? 'blocked'
                                 : (kv.action ? kv.action.toLowerCase() : null);
      structured.src_ip         = kv['src-ip'] || null;
      structured.dst_ip         = kv['dst-ip'] || null;
      structured.src_port       = kv['src-port'] ? parseInt(kv['src-port']) : null;
      structured.dst_port       = kv['dst-port'] ? parseInt(kv['dst-port']) : null;
      structured.protocol       = kv['protocol-name'] || null;
      structured.repeat_count   = kv.repeat ? parseInt(kv.repeat) : null;

      message = `Juniper IDP attack ${structured.attack_name || ''}`.trim();
      if (structured.src_ip && structured.dst_ip) message += `: ${structured.src_ip} -> ${structured.dst_ip}`;
      if (kv.action) message += ` action=${kv.action}`;

    } else if (/RT_FLOW:/.test(raw)) {
      // Session create/close
      category = 'firewall';
      const evMatch = raw.match(/(RT_FLOW_SESSION_\w+)/);
      const event   = evMatch ? evMatch[1] : 'RT_FLOW';
      // Address tuple: 10.1.1.5/1234->8.8.8.8/443
      const tuple   = raw.match(/(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)->(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)/);
      // service name + zones: ... junos-https None ... inbound->outbound iface
      const appMatch  = raw.match(/->\d+\s+(\S+)\s+\S+/);
      const zoneMatch = raw.match(/([\w-]+)->([\w-]+)\s+(\S+)\s*$/);

      structured.event_type = event;
      if (tuple) {
        structured.src_ip   = tuple[1];
        structured.src_port = parseInt(tuple[2]);
        structured.dst_ip   = tuple[3];
        structured.dst_port = parseInt(tuple[4]);
      }
      structured.application = appMatch ? appMatch[1] : null;
      structured.src_zone    = zoneMatch ? zoneMatch[1] : null;
      structured.dst_zone    = zoneMatch ? zoneMatch[2] : null;
      structured.interface   = zoneMatch ? zoneMatch[3] : null;
      structured.action      = /CLOSE/.test(event) ? 'closed' : 'allowed';

      message = `Juniper ${event}`;
      if (structured.src_ip && structured.dst_ip) message += `: ${structured.src_ip} -> ${structured.dst_ip}`;
      if (structured.application) message += ` app=${structured.application}`;

    } else {
      // EX switching / SNMP traps
      const trapMatch = raw.match(/(SNMP_TRAP_\w+|[A-Z][A-Z0-9_]+_(?:UP|DOWN))/);
      const kv = parseKV(raw);
      const trap = trapMatch ? trapMatch[1] : null;

      if (trap && /LINK_(UP|DOWN)/.test(trap)) {
        category = 'interface';
        structured.link_state = /DOWN/.test(trap) ? 'down' : 'up';
        if (structured.link_state === 'down') { severity = 4; severityLabel = 'warning'; }
      } else if (/AUTH/i.test(raw)) {
        category = 'authentication';
      } else if (/BGP|OSPF|RIP/i.test(raw)) {
        category = 'routing';
      }

      structured.event_type    = trap || null;
      structured.interface     = kv.ifIndex || kv.interface || null;
      structured.admin_status  = kv.ifAdminStatus || null;

      const progMatch = raw.match(/\s(\w+)(?:\[\d+\])?:\s/);
      message = trap ? `Juniper ${trap}` : (progMatch ? raw.slice(raw.indexOf(progMatch[0]) + progMatch[0].length).trim() : raw);
    }

    Object.keys(structured).forEach(k => (structured[k] == null) && delete structured[k]);
    structured.category = category;

    return {
      source_ip:       sourceIp,
      source_host:     sourceHost,
      facility:        base.facility,
      facility_label:  base.facility_label,
      severity,
      severity_label:  severityLabel,
      vendor:          'juniper',
      program:         structured.event_type || 'JUNOS',
      message,
      raw_message:     raw,
      structured_data: structured,
      is_parsed:       true,
      log_timestamp:   null,
      parser_version:  'juniper-v1.0',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseJuniper, detectJuniper };
