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

  // For TRAFFIC logs: src/dst IPs are at known columns
  if (logType === 'TRAFFIC' && cols.length > 13) {
    const srcip = cols[7]?.trim(); const dstip = cols[8]?.trim();
    const app   = cols[24]?.trim(); const action = cols[30]?.trim();
    if (srcip && dstip) message += `: ${srcip} -> ${dstip}`;
    if (app) message += ` app=${app}`;
    if (action) message += ` action=${action}`;
  }

  if (logType === 'THREAT' && cols.length > 15) {
    const srcip   = cols[7]?.trim(); const dstip = cols[8]?.trim();
    const threat  = cols[26]?.trim(); const action = cols[28]?.trim();
    if (srcip && dstip) message += `: ${srcip} -> ${dstip}`;
    if (threat) message += ` threat=${threat}`;
    if (action) message += ` action=${action}`;
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
    structured_data: { log_type: logType, subtype, serial },
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parsePaloAlto };
