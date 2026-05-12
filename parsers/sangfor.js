/**
 * Sangfor Syslog Parser
 *
 * Sangfor NGFW / SSL VPN / IAM devices send logs in key=value format,
 * similar to Fortinet but with Sangfor-specific field names.
 *
 * Example: <166>May 12 10:23:01 SangforNGFW CEF:0|Sangfor|NGFW|9.0|100001|Traffic Log|5|
 *          src=192.168.1.10 dst=8.8.8.8 spt=54321 dpt=443 proto=TCP act=permit
 *
 * Sangfor also sends plain RFC3164 with program tag starting with "Sangfor"
 */

'use strict';

// Sangfor detection: CEF header with Sangfor vendor, OR program tag containing Sangfor
const SANGFOR_CEF_RE  = /CEF:0\|Sangfor\|/i;
const SANGFOR_TAG_RE  = /\bSangfor\w*/i;
const SANGFOR_KV_RE   = /(\w+)=(?:"([^"]*)"|([\S]*))/g;

const CEF_SEV_MAP = { 0:'debug',1:'debug',2:'debug',3:'info',4:'info',5:'notice',6:'warning',7:'warning',8:'error',9:'critical',10:'critical' };
const CEF_SEV_NUM = { 0:7,1:7,2:7,3:6,4:6,5:5,6:4,7:4,8:3,9:2,10:2 };

function parseSangfor(raw, sourceIp) {
  if (!SANGFOR_CEF_RE.test(raw) && !SANGFOR_TAG_RE.test(raw)) return null;

  let severity = 6; let severityLabel = 'info';
  let message  = raw; let structuredData = {};
  let sourceHost = null; let logTimestamp = null;

  if (SANGFOR_CEF_RE.test(raw)) {
    // CEF format: CEF:0|Vendor|Product|Version|EventID|EventName|Severity|extensions
    const cefParts = raw.split('CEF:0|');
    if (cefParts.length < 2) return null;

    const cefBody  = cefParts[1];
    const pipes    = cefBody.split('|');
    if (pipes.length < 7) return null;

    const eventName = pipes[4]?.trim();
    const cefSev    = parseInt(pipes[5]?.trim(), 10);

    severity      = CEF_SEV_NUM[cefSev] ?? 6;
    severityLabel = CEF_SEV_MAP[cefSev] ?? 'info';

    // Parse extensions (key=value after last pipe)
    const extensions = pipes.slice(6).join('|');
    const kv = {};
    let m;
    while ((m = SANGFOR_KV_RE.exec(extensions)) !== null) {
      kv[m[1]] = m[2] !== undefined ? m[2] : m[3];
    }

    message = eventName || 'Sangfor event';
    if (kv.src && kv.dst) message += `: ${kv.src} -> ${kv.dst}`;
    if (kv.act) message += ` action=${kv.act}`;
    if (kv.msg) message += ` | ${kv.msg}`;

    sourceHost    = kv.dhost || kv.src || null;
    structuredData = { format: 'CEF', event_name: eventName, ...kv };

    if (kv.start) {
      try { logTimestamp = new Date(parseInt(kv.start, 10)); } catch (_) {}
    }

  } else {
    // Plain RFC3164 with Sangfor in the program tag
    const rfc = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)/s.exec(raw);
    if (!rfc) return null;

    const pri = parseInt(rfc[1], 10);
    severity       = pri % 8;
    severityLabel  = ['emergency','alert','critical','error','warning','notice','info','debug'][severity] || 'info';
    sourceHost     = rfc[3];
    message        = rfc[5] || raw;
    structuredData = { format: 'RFC3164', program: rfc[4] };
    const year = new Date().getFullYear();
    try { logTimestamp = new Date(`${rfc[2]} ${year}`); } catch (_) {}
  }

  return {
    source_ip:       sourceIp,
    source_host:     sourceHost,
    facility:        20,
    facility_label:  'local4',
    severity,
    severity_label:  severityLabel,
    vendor:          'sangfor',
    program:         'Sangfor',
    message,
    raw_message:     raw,
    structured_data: structuredData,
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseSangfor };
