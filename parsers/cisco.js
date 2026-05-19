/**
 * Cisco IOS / IOS-XE Syslog Parser
 * Enhanced with STP, MAC flap, storm control, and interface event classification
 * Fixes: New Year timestamp rollover edge case
 */

'use strict';

const FACILITY_LABELS = ['kern','user','mail','daemon','auth','syslog','lpr','news',
  'uucp','cron','authpriv','ftp','ntp','audit','alert2','clock',
  'local0','local1','local2','local3','local4','local5','local6','local7'];

const IOS_SEV_MAP = { 0:'emergency',1:'alert',2:'critical',3:'error',4:'warning',5:'notice',6:'info',7:'debug' };

const CISCO_MNEMONIC_RE = /%([A-Z0-9_\-]+)-(\d)-([A-Z0-9_]+):/;
const CISCO_FULL_RE     = /^<(\d{1,3})>\*?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?(?:\s+\w+)?):\s+(%[A-Z0-9_\-]+-\d-[A-Z0-9_]+:.*)/s;

const EVENT_PATTERNS = [
  { pattern: /LINK-\d-UPDOWN/,           category: 'interface', subcategory: 'link_change' },
  { pattern: /LINEPROTO-\d-UPDOWN/,      category: 'interface', subcategory: 'protocol_change' },
  { pattern: /SPANTREE.*TOPOTRAP/,       category: 'stp',       subcategory: 'topology_change' },
  { pattern: /SPANTREE.*ROOTCHANGE/,     category: 'stp',       subcategory: 'root_change' },
  { pattern: /SPANTREE.*CHNMISCFG/,      category: 'stp',       subcategory: 'loop_detected' },
  { pattern: /SPANTREE.*PORTDEL/,        category: 'stp',       subcategory: 'port_removed' },
  { pattern: /STP.*INTERFACE_ROLE/,      category: 'stp',       subcategory: 'role_change' },
  { pattern: /STP-\d-BLOCK/,            category: 'stp',       subcategory: 'port_blocked' },
  { pattern: /SW_MATM.*MACFLAP/,         category: 'loop',      subcategory: 'mac_flap' },
  { pattern: /MACFLAP_NOTIF/,            category: 'loop',      subcategory: 'mac_flap' },
  { pattern: /STORM_CONTROL.*FILTERED/,  category: 'loop',      subcategory: 'storm_control' },
  { pattern: /STORM_CONTROL.*SHUTDOWN/,  category: 'loop',      subcategory: 'storm_shutdown' },
  { pattern: /SEC_LOGIN.*LOGIN_FAILED/,  category: 'security',  subcategory: 'login_failed' },
  { pattern: /SEC_LOGIN.*QUIET_MODE/,    category: 'security',  subcategory: 'brute_force' },
  { pattern: /SEC_LOGIN.*LOGIN_SUCCESS/, category: 'security',  subcategory: 'login_success' },
  { pattern: /AAA.*AUTHEN_FAIL/,         category: 'security',  subcategory: 'auth_failed' },
  { pattern: /SYS-\d-CONFIG_I/,          category: 'config',    subcategory: 'config_change' },
  { pattern: /SYS-\d-LOGOUT/,            category: 'config',    subcategory: 'logout' },
  { pattern: /OSPF.*ADJCHG/,             category: 'routing',   subcategory: 'ospf_neighbor' },
  { pattern: /BGP.*ADJCHANGE/,           category: 'routing',   subcategory: 'bgp_neighbor' },
  { pattern: /DUAL-\d-NBRCHANGE/,        category: 'routing',   subcategory: 'eigrp_neighbor' },
];

function classifyEvent(mnemonicFull, message) {
  const s = `${mnemonicFull} ${message}`;
  for (const p of EVENT_PATTERNS) {
    if (p.pattern.test(s)) return { category: p.category, subcategory: p.subcategory };
  }
  return { category: 'general', subcategory: 'general' };
}

function extractInterface(message) {
  const m = message.match(/(?:Interface|interface|port)\s+([\w\/\.]+)/i)
         || message.match(/(GigabitEthernet[\w\/\.]+)/i)
         || message.match(/(FastEthernet[\w\/\.]+)/i)
         || message.match(/(TenGigabitEthernet[\w\/\.]+)/i)
         || message.match(/(Ethernet[\w\/\.]+)/i)
         || message.match(/(Vlan[\w\/\.]+)/i)
         || message.match(/(Po[\d]+)/i);
  return m ? m[1] : null;
}

function extractMAC(message) {
  const m = message.match(/([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/i)
         || message.match(/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i);
  return m ? m[1] : null;
}

// ── Fix: Handle New Year rollover in Cisco timestamps ─────────
// Cisco syslog doesn't include the year — we add current year,
// but if the log is from December and current month is January,
// we need to use the previous year.
function parseCiscoTimestamp(dateStr) {
  if (!dateStr) return null;
  try {
    const now   = new Date();
    const year  = now.getFullYear();
    const parsed = new Date(`${dateStr.trim()} ${year}`);
    if (isNaN(parsed.getTime())) return null;
    // If the parsed date is more than 1 day in the future, it's from last year
    if (parsed.getTime() > now.getTime() + 86400000) {
      return new Date(`${dateStr.trim()} ${year - 1}`);
    }
    return parsed;
  } catch (_) { return null; }
}

function parseCisco(raw, sourceIp) {
  if (!CISCO_MNEMONIC_RE.test(raw)) return null;

  const mnemonicMatch = CISCO_MNEMONIC_RE.exec(raw);
  if (!mnemonicMatch) return null;

  const fullMatch    = CISCO_FULL_RE.exec(raw);
  const iosFacility  = mnemonicMatch[1];
  const iosSeverity  = parseInt(mnemonicMatch[2], 10);
  const mnemonic     = mnemonicMatch[3];
  const mnemonicFull = mnemonicMatch[0];

  const msgStart = raw.indexOf(mnemonicFull) + mnemonicFull.length;
  const message  = raw.slice(msgStart).trim();

  const severity      = iosSeverity <= 7 ? iosSeverity : 6;
  const severityLabel = IOS_SEV_MAP[severity] || 'info';

  let facility      = 23;
  let facilityLabel = 'local7';
  if (fullMatch) {
    const pri = parseInt(fullMatch[1], 10);
    facility      = Math.floor(pri / 8);
    facilityLabel = FACILITY_LABELS[facility] || 'local7';
  }

  const logTimestamp = fullMatch ? parseCiscoTimestamp(fullMatch[2]) : null;
  const { category, subcategory } = classifyEvent(mnemonicFull, message);
  const iface    = extractInterface(message);
  const mac      = extractMAC(message);

  let linkState = null;
  if (subcategory === 'link_change' || subcategory === 'protocol_change') {
    if (/changed state to up|line protocol.*up/i.test(message))     linkState = 'up';
    if (/changed state to down|line protocol.*down/i.test(message)) linkState = 'down';
  }

  return {
    source_ip:       sourceIp,
    source_host:     null,
    facility,
    facility_label:  facilityLabel,
    severity,
    severity_label:  severityLabel,
    vendor:          'cisco',
    program:         iosFacility,
    message:         message || raw,
    raw_message:     raw,
    structured_data: { ios_facility: iosFacility, ios_severity: iosSeverity, mnemonic, category, subcategory, interface: iface, mac_address: mac, link_state: linkState },
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseCisco };
