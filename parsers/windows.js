/**
 * Windows Event Log Parser for LogVault
 *
 * Windows logs arrive via NXLog / Winlogbeat shipped as syslog. Handles:
 *
 * 1. NXLog CEF:
 *    CEF:0|Microsoft|Windows|6.3|4625|An account failed to log on|7|src=10.1.1.5 suser=Administrator
 *
 * 2. NXLog MSWinEventLog tab/space format:
 *    <pri>timestamp host MSWinEventLog 1 Security 4625 ... An account failed to log on.
 *
 * 3. Winlogbeat JSON embedded in the message:
 *    {"winlog":{"event_id":4625,"channel":"Security","computer_name":"HOST",
 *     "event_data":{"TargetUserName":"Administrator","LogonType":"3","IpAddress":"10.1.1.5"}}}
 */

'use strict';

// EventID → { category, severity, label, summary builder }
const EVENT_MAP = {
  4624: { category: 'authentication', severity: 6, label: 'info',    desc: 'Successful logon' },
  4625: { category: 'authentication', severity: 4, label: 'warning', desc: 'Failed logon' },
  4634: { category: 'authentication', severity: 6, label: 'info',    desc: 'Account logoff' },
  4648: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Logon with explicit credentials' },
  4672: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Special privileges assigned' },
  4698: { category: 'configuration',  severity: 4, label: 'warning', desc: 'Scheduled task created' },
  4700: { category: 'configuration',  severity: 4, label: 'warning', desc: 'Scheduled task enabled' },
  4720: { category: 'authentication', severity: 5, label: 'notice',  desc: 'User account created' },
  4722: { category: 'authentication', severity: 6, label: 'info',    desc: 'User account enabled' },
  4724: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Password reset' },
  4728: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Member added to security group' },
  4732: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Member added to local group' },
  4740: { category: 'authentication', severity: 4, label: 'warning', desc: 'Account locked out' },
  4756: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Member added to universal group' },
  // Kerberos / NTLM auth events — also brute-force / credential-attack signals
  4768: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Kerberos TGT requested' },
  4771: { category: 'authentication', severity: 4, label: 'warning', desc: 'Kerberos pre-authentication failed' },
  4776: { category: 'authentication', severity: 4, label: 'warning', desc: 'NTLM credential validation' },
  7034: { category: 'system',         severity: 3, label: 'error',   desc: 'Service crashed' },
  7036: { category: 'system',         severity: 6, label: 'info',    desc: 'Service state change' },
  7045: { category: 'configuration',  severity: 4, label: 'warning', desc: 'New service installed' },
};

// Validate an IPv4/IPv6 address string. Rejects '-', empty, hostnames, ::1-as-noise.
function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const v = ip.trim();
  if (!v || v === '-' || v === '::') return false;
  // IPv4 with octet range check
  const v4 = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) return v4.slice(1).every(o => Number(o) <= 255);
  // IPv6 (loose but reasonable): hex groups + colons, optional :: compression
  if (/^[0-9a-fA-F:]+$/.test(v) && v.includes(':')) return true;
  return false;
}

// event_id → normalized-contract subcategory.
// 4776 (NTLM) resolves to success/failure at parse time based on result fields.
function subcategoryFor(eventId, fields) {
  switch (eventId) {
    case 4624: return 'login_success';
    case 4625: return 'login_failed';
    case 4740: return 'account_lockout';
    case 4768: // Kerberos TGT request (a failure here is an auth failure)
    case 4771: // Kerberos pre-auth failed
      return 'login_failed';
    case 4776: {
      // NTLM: a non-zero/non-'0x0' status means validation failed.
      const status = (fields && (fields.failure_reason || fields.status)) || '';
      const s = String(status).trim().toLowerCase();
      const success = s === '' || s === '0x0' || s === '0' || s === 'success';
      return success ? 'login_success' : 'login_failed';
    }
    default: return null;
  }
}

function detectWindows(raw) {
  if (!raw) return false;
  if (/MSWinEventLog/i.test(raw))            return true;
  if (/\bwinlog\b/i.test(raw))               return true;
  if (/CEF:\d+\|Microsoft\|Windows\|/i.test(raw)) return true;
  if (/EventID["\s:=]+\d{3,5}/i.test(raw))   return true;
  if (/EventCode=4\d{3}/.test(raw))          return true;
  return false;
}

// CEF extension key=value parser
function parseCEFExt(ext) {
  const kv = {};
  if (!ext) return kv;
  const re = /(\w+)=((?:[^=\\]|\\.)*)(?=\s+\w+=|$)/g;
  let m;
  while ((m = re.exec(ext)) !== null) kv[m[1]] = m[2].trim();
  return kv;
}

function buildSummary(eventId, fields) {
  const user  = fields.user || null;
  const ip    = fields.srcip || fields.src_ip || null;
  const type  = fields.logon_type || null;
  switch (eventId) {
    case 4625: return `Failed logon (login failed) for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}${type ? ` (Type ${type})` : ''}`;
    case 4624: return `Successful logon for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}`;
    case 4771:
    case 4768: return `Kerberos login failed for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}`;
    case 4776: return `NTLM credential validation for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}`;
    case 4740: return `Account ${user || 'unknown'} locked out`;
    case 4720: return `User account ${user || 'unknown'} created`;
    case 4724: return `Password reset for ${user || 'unknown'}`;
    case 7034: return `Service ${fields.process_name || ''} crashed`.trim();
    case 7045: return `New service installed: ${fields.process_name || 'unknown'}`;
    default: {
      const info = EVENT_MAP[eventId];
      return info ? `${info.desc}${user ? ` — ${user}` : ''}` : `Windows Event ${eventId}`;
    }
  }
}

function parseWindows(raw, sourceIp) {
  try {
    if (!detectWindows(raw)) return null;

    let eventId  = null;
    let channel  = null;
    let computer = null;
    const fields = {};

    // Winlogbeat JSON
    const jsonMatch = raw.match(/\{.*"winlog".*\}/s);
    if (jsonMatch) {
      try {
        const obj = JSON.parse(jsonMatch[0]);
        const wl  = obj.winlog || {};
        eventId   = parseInt(wl.event_id);
        channel   = wl.channel || null;
        computer  = wl.computer_name || null;
        const ed  = wl.event_data || {};
        fields.user       = ed.TargetUserName || ed.SubjectUserName || null;
        fields.logon_type = ed.LogonType || null;
        // 4768/4771 (Kerberos) carry the client IP in IpAddress too; some shippers use ClientAddress.
        {
          const ipCand = ed.IpAddress || ed.ClientAddress || ed.Workstation || null;
          fields.src_ip = isValidIp(ipCand) ? String(ipCand).trim() : null;
        }
        fields.process_name = ed.ProcessName || ed.ServiceName || null;
        fields.failure_reason = ed.FailureReason || ed.Status || ed.SubStatus || null;
      } catch (_) {}
    }

    // CEF
    if (eventId == null) {
      const cef = raw.match(/CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s);
      if (cef) {
        eventId = parseInt(cef[5]);
        const ext = parseCEFExt(cef[8]);
        fields.user       = ext.suser || ext.duser || null;
        {
          // CEF: src is the real client/source IP (attacker). Validate before use.
          const ipCand = ext.src || ext.shost || null;
          fields.src_ip = isValidIp(ipCand) ? String(ipCand).trim() : null;
        }
        fields.logon_type = ext.cs1 || null;
        fields.process_name = ext.deviceProcessName || ext.dproc || null;
        if (ext.msg) fields.failure_reason = ext.msg;
      }
    }

    // MSWinEventLog / generic EventID/EventCode text
    if (eventId == null) {
      const m = raw.match(/MSWinEventLog\s+\d+\s+(\w+)\s+(\d{3,5})/i)
             || raw.match(/EventID["\s:=]+(\d{3,5})/i)
             || raw.match(/EventCode=(\d{3,5})/i);
      if (m) {
        if (m.length === 3) { channel = m[1]; eventId = parseInt(m[2]); }
        else eventId = parseInt(m[1]);
      }
      const userM = raw.match(/(?:TargetUserName|Account Name|suser)["\s:=]+([^\s,"]+)/i);
      const ipM   = raw.match(/(?:IpAddress|Source Network Address|Client Address|ClientAddress|src)["\s:=]+(\d{1,3}(?:\.\d{1,3}){3})/i);
      const ltM   = raw.match(/Logon Type["\s:=]+(\d+)/i);
      if (userM && !fields.user)                       fields.user = userM[1];
      if (ipM && !fields.src_ip && isValidIp(ipM[1]))  fields.src_ip = ipM[1];
      if (ltM && !fields.logon_type)                   fields.logon_type = ltM[1];
    }

    if (eventId == null || isNaN(eventId)) return null;

    const info = EVENT_MAP[eventId] || { category: 'system', severity: 6, label: 'info', desc: `Windows Event ${eventId}` };

    const subcategory = subcategoryFor(eventId, fields);

    const structured = {
      category:       info.category,
      event_id:       eventId,
      // Normalized contract: subcategory drives auth correlation (login_failed/success/account_lockout).
      subcategory:    subcategory || null,
      channel:        channel || null,
      computer_name:  computer || null,
      user:           fields.user || null,
      logon_type:     fields.logon_type || null,
      // Normalized contract: `srcip` = real client/source IP (attacker), spelled per contract.
      srcip:          fields.src_ip || null,
      src_ip:         fields.src_ip || null,  // kept for back-compat
      failure_reason: fields.failure_reason || null,
      process_name:   fields.process_name || null,
    };
    Object.keys(structured).forEach(k => (structured[k] == null) && delete structured[k]);

    return {
      source_ip:       sourceIp,
      source_host:     computer || null,
      facility:        4,
      facility_label:  'auth',
      severity:        info.severity,
      severity_label:  info.label,
      vendor:          'windows',
      program:         channel ? `Windows/${channel}` : 'Windows',
      message:         buildSummary(eventId, structured),
      raw_message:     raw,
      structured_data: structured,
      is_parsed:       true,
      log_timestamp:   null,
      parser_version:  'windows-v1.0',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseWindows, detectWindows };
