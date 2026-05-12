/**
 * Cisco IOS / IOS-XE Syslog Parser
 *
 * Cisco format: <PRI>TIMESTAMP: %FACILITY-SEVERITY-MNEMONIC: message
 * Example: <189>May 12 10:23:01.456: %SYS-5-CONFIG_I: Configured from console by admin on vty0
 * Example: <189>*May 12 10:23:01.456 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
 */

'use strict';

const { parseGeneric } = require('./generic');

const SEVERITY_LABELS = ['emergency','alert','critical','error','warning','notice','info','debug'];
const FACILITY_LABELS = ['kern','user','mail','daemon','auth','syslog','lpr','news',
  'uucp','cron','authpriv','ftp','ntp','audit','alert2','clock',
  'local0','local1','local2','local3','local4','local5','local6','local7'];

// Cisco syslog mnemonic maps IOS facility severity to syslog severity
const IOS_SEV_MAP = { 0:'emergency', 1:'alert', 2:'critical', 3:'error', 4:'warning', 5:'notice', 6:'info', 7:'debug' };

// Detects Cisco IOS-style %FACILITY-SEVERITY-MNEMONIC pattern
const CISCO_MNEMONIC_RE = /%([A-Z0-9_\-]+)-(\d)-([A-Z0-9_]+):/;

// Full Cisco log line
const CISCO_FULL_RE = /^<(\d{1,3})>\*?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?(?:\s+\w+)?):\s+(%[A-Z0-9_\-]+-\d-[A-Z0-9_]+:.*)/s;

function parseCisco(raw, sourceIp) {
  // Must contain the Cisco mnemonic pattern to be treated as Cisco
  if (!CISCO_MNEMONIC_RE.test(raw)) return null;

  const fullMatch = CISCO_FULL_RE.exec(raw);
  const mnemonicMatch = CISCO_MNEMONIC_RE.exec(raw);

  if (!mnemonicMatch) return null;

  const iosFacility  = mnemonicMatch[1]; // e.g. "SYS", "LINK", "SEC_LOGIN"
  const iosSeverity  = parseInt(mnemonicMatch[2], 10);
  const mnemonic     = mnemonicMatch[3]; // e.g. "CONFIG_I", "UPDOWN"

  // Extract message after the mnemonic colon
  const msgStart = raw.indexOf(mnemonicMatch[0]) + mnemonicMatch[0].length;
  const message  = raw.slice(msgStart).trim();

  // Decode PRI if present
  let severity      = iosSeverity <= 7 ? iosSeverity : 6;
  let facility      = 23; // default local7
  let facilityLabel = 'local7';
  let severityLabel = IOS_SEV_MAP[severity] || 'info';

  if (fullMatch) {
    const pri = parseInt(fullMatch[1], 10);
    facility      = Math.floor(pri / 8);
    facilityLabel = FACILITY_LABELS[facility] || 'local7';
    // Use IOS severity (more accurate) over PRI severity
  }

  // Parse timestamp
  let logTimestamp = null;
  if (fullMatch && fullMatch[2]) {
    const year = new Date().getFullYear();
    try { logTimestamp = new Date(`${fullMatch[2].trim()} ${year}`); } catch (_) {}
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
    structured_data: {
      ios_facility: iosFacility,
      ios_severity: iosSeverity,
      mnemonic,
    },
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseCisco };
