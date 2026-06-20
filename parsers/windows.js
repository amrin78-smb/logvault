/**
 * Windows Event Log Parser for LogVault
 *
 * Windows logs arrive via NXLog / Winlogbeat / Snare shipped as syslog. Handles
 * three ingest paths:
 *
 * 1. NXLog / generic CEF:
 *    CEF:0|Microsoft|Windows|6.3|4625|An account failed to log on|7|src=10.1.1.5 suser=Administrator
 *
 * 2. Snare / NXLog MSWinEventLog tab/space text format:
 *    <pri>timestamp host MSWinEventLog 1 Security 4625 ... An account failed to log on.
 *
 * 3. Winlogbeat / NXLog JSON embedded in the message:
 *    {"winlog":{"event_id":4625,"channel":"Security","computer_name":"HOST",
 *     "event_data":{"TargetUserName":"Administrator","LogonType":"3","IpAddress":"10.1.1.5"}}}
 *
 * NORMALIZED CONTRACT (emitted in structured_data, only-when-present):
 *   srcip       — the REAL client/source IP (the remote user/attacker). For Windows
 *                 Security logon events this is the event's IpAddress /
 *                 "Source Network Address" — NEVER the Windows host that relayed the
 *                 syslog (that is source_ip / source_host).
 *   dstip       — destination IP where the event carries one.
 *   user        — the account the event is about (TargetUserName / "Account Name").
 *   subcategory — 'login_failed' | 'login_success' | 'auth_failed' | 'account_lockout'
 *   action      — coarse action verb (logon/logoff/lockout/account_created/...).
 *   category    — 'authentication' for logon/credential events (resolved first by
 *                 collector/taxonomy.js), 'system'/'security'/'configuration' otherwise.
 */

'use strict';

// EventID → { category, severity, label, desc }
// Severity follows the syslog numeric scale (lower = more severe): 3 error,
// 4 warning, 5 notice, 6 info. Mapped faithfully from the event's nature.
const EVENT_MAP = {
  // ── Logon / logoff (Security channel) ──
  4624: { category: 'authentication', severity: 6, label: 'info',    desc: 'Successful logon' },
  4625: { category: 'authentication', severity: 4, label: 'warning', desc: 'Failed logon' },
  4634: { category: 'authentication', severity: 6, label: 'info',    desc: 'Account logoff' },
  4647: { category: 'authentication', severity: 6, label: 'info',    desc: 'User-initiated logoff' },
  4648: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Logon with explicit credentials' },
  4672: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Special privileges assigned to new logon' },
  // ── Account / group management ──
  4720: { category: 'authentication', severity: 5, label: 'notice',  desc: 'User account created' },
  4722: { category: 'authentication', severity: 6, label: 'info',    desc: 'User account enabled' },
  4723: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Password change attempted' },
  4724: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Password reset' },
  4725: { category: 'authentication', severity: 5, label: 'notice',  desc: 'User account disabled' },
  4726: { category: 'authentication', severity: 4, label: 'warning', desc: 'User account deleted' },
  4728: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Member added to security group' },
  4732: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Member added to local group' },
  4756: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Member added to universal group' },
  4740: { category: 'authentication', severity: 4, label: 'warning', desc: 'Account locked out' },
  4767: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Account unlocked' },
  // ── Kerberos / NTLM auth — brute-force / credential-attack signals ──
  4768: { category: 'authentication', severity: 5, label: 'notice',  desc: 'Kerberos TGT requested' },
  4769: { category: 'authentication', severity: 6, label: 'info',    desc: 'Kerberos service ticket requested' },
  4771: { category: 'authentication', severity: 4, label: 'warning', desc: 'Kerberos pre-authentication failed' },
  4776: { category: 'authentication', severity: 4, label: 'warning', desc: 'NTLM credential validation' },
  // ── Process / system / service / policy ──
  4688: { category: 'security',       severity: 6, label: 'info',    desc: 'A new process has been created' },
  4689: { category: 'system',         severity: 6, label: 'info',    desc: 'A process has exited' },
  4697: { category: 'configuration',  severity: 4, label: 'warning', desc: 'A service was installed' },
  4698: { category: 'configuration',  severity: 4, label: 'warning', desc: 'Scheduled task created' },
  4699: { category: 'configuration',  severity: 4, label: 'warning', desc: 'Scheduled task deleted' },
  4700: { category: 'configuration',  severity: 4, label: 'warning', desc: 'Scheduled task enabled' },
  4719: { category: 'configuration',  severity: 4, label: 'warning', desc: 'System audit policy changed' },
  4946: { category: 'configuration',  severity: 5, label: 'notice',  desc: 'Firewall rule added' },
  4947: { category: 'configuration',  severity: 5, label: 'notice',  desc: 'Firewall rule modified' },
  1102: { category: 'security',       severity: 3, label: 'error',   desc: 'Audit log was cleared' },
  7034: { category: 'system',         severity: 3, label: 'error',   desc: 'Service crashed' },
  7036: { category: 'system',         severity: 6, label: 'info',    desc: 'Service state change' },
  7040: { category: 'configuration',  severity: 5, label: 'notice',  desc: 'Service start type changed' },
  7045: { category: 'configuration',  severity: 4, label: 'warning', desc: 'New service installed' },
};

// Validate an IPv4/IPv6 address string. Rejects '-', empty, hostnames, ::-as-noise.
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
// 4776 (NTLM) / 4768 / 4769 resolve to success/failure at parse time from result fields.
function subcategoryFor(eventId, fields) {
  switch (eventId) {
    case 4624: return 'login_success';
    case 4625: return 'login_failed';
    case 4740: return 'account_lockout';
    case 4771: // Kerberos pre-auth failed — always a failure
      return 'login_failed';
    case 4768: // Kerberos TGT request: failure carries a non-0x0 result/status
    case 4769: // Kerberos service ticket request: same
    case 4776: { // NTLM: a non-zero/non-'0x0' status means validation failed
      const status = (fields && (fields.failure_reason || fields.status_code || fields.status)) || '';
      const s = String(status).trim().toLowerCase();
      const success = s === '' || s === '0x0' || s === '0' || s === 'success' || s === '0x00000000';
      return success ? 'login_success' : 'login_failed';
    }
    default: return null;
  }
}

// event_id → coarse action verb (contract field `action`).
function actionFor(eventId) {
  switch (eventId) {
    case 4624: case 4648: case 4768: case 4769: case 4776: return 'logon';
    case 4625: case 4771:                                  return 'logon_failed';
    case 4634: case 4647:                                  return 'logoff';
    case 4672:                                             return 'privilege_assigned';
    case 4720:                                             return 'account_created';
    case 4722:                                             return 'account_enabled';
    case 4725:                                             return 'account_disabled';
    case 4726:                                             return 'account_deleted';
    case 4723: case 4724:                                  return 'password_change';
    case 4728: case 4732: case 4756:                       return 'group_member_added';
    case 4740:                                             return 'account_lockout';
    case 4767:                                             return 'account_unlocked';
    case 4688:                                             return 'process_created';
    case 4689:                                             return 'process_exited';
    case 4697: case 7045:                                  return 'service_installed';
    case 1102:                                             return 'log_cleared';
    default:                                               return null;
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

// Best-effort event-time extraction. Prefers the event's own timestamp (with its
// timezone) over the collector OS locale. Returns an ISO string or null.
function extractTimestamp(raw, jsonObj) {
  // Winlogbeat / NXLog JSON: top-level @timestamp or winlog event time
  if (jsonObj) {
    const cand = jsonObj['@timestamp']
      || (jsonObj.winlog && (jsonObj.winlog.time_created || jsonObj.winlog.event_time))
      || jsonObj.EventTime || jsonObj.event_time || null;
    if (cand) {
      const d = new Date(cand);
      if (!isNaN(d.getTime())) return d.toISOString();
    }
  }
  // CEF/text: NXLog often emits "EventTime=2026-06-20 14:03:11" (local) or rt= (CEF, epoch ms)
  const rt = raw.match(/(?:^|\s)rt=(\d{10,13})/);
  if (rt) {
    const n = Number(rt[1]);
    const d = new Date(rt[1].length === 13 ? n : n * 1000);
    if (!isNaN(d.getTime())) return d.toISOString();
  }
  const et = raw.match(/EventTime["\s:=]+["']?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/i);
  if (et) {
    const d = new Date(et[1].replace(' ', 'T'));
    if (!isNaN(d.getTime())) return d.toISOString();
  }
  return null;
}

function buildSummary(eventId, fields) {
  const user  = fields.user || null;
  const ip    = fields.srcip || fields.src_ip || null;
  const type  = fields.logon_type || null;
  switch (eventId) {
    case 4625: return `Failed logon (login failed) for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}${type ? ` (Type ${type})` : ''}`;
    case 4624: return `Successful logon for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}${type ? ` (Type ${type})` : ''}`;
    case 4648: return `Logon using explicit credentials${user ? ` for ${user}` : ''}${ip ? ` from ${ip}` : ''}`;
    case 4634:
    case 4647: return `Logoff for ${user || 'unknown'}`;
    case 4672: return `Special privileges assigned${user ? ` to ${user}` : ''}`;
    case 4771:
    case 4768:
    case 4769: return `Kerberos ${fields.subcategory === 'login_failed' ? 'login failed' : 'ticket request'} for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}`;
    case 4776: return `NTLM credential validation${fields.subcategory === 'login_failed' ? ' failed' : ''} for ${user || 'unknown'}${ip ? ` from ${ip}` : ''}`;
    case 4740: return `Account ${user || 'unknown'} locked out${fields.caller_computer ? ` (source ${fields.caller_computer})` : ''}`;
    case 4767: return `Account ${user || 'unknown'} unlocked`;
    case 4720: return `User account ${user || 'unknown'} created`;
    case 4726: return `User account ${user || 'unknown'} deleted`;
    case 4724: return `Password reset for ${user || 'unknown'}`;
    case 4723: return `Password change attempted for ${user || 'unknown'}`;
    case 4688: return `New process created: ${fields.new_process_name || 'unknown'}${fields.user ? ` (by ${fields.user})` : ''}`;
    case 4689: return `Process exited: ${fields.process_name || fields.new_process_name || 'unknown'}`;
    case 4697:
    case 7045: return `New service installed: ${fields.service_name || fields.process_name || 'unknown'}`;
    case 1102: return `Audit log was cleared${fields.user ? ` by ${fields.user}` : ''}`;
    case 7034: return `Service ${fields.process_name || ''} crashed`.trim();
    default: {
      const info = EVENT_MAP[eventId];
      return info ? `${info.desc}${user ? ` — ${user}` : ''}` : `Windows Event ${eventId}`;
    }
  }
}

// "DOMAIN\\user" / "user@domain" → bare username; '-' / empty → null.
function cleanUser(u) {
  if (!u) return null;
  let v = String(u).trim();
  if (!v || v === '-') return null;
  return v;
}

function parseWindows(raw, sourceIp) {
  try {
    if (!detectWindows(raw)) return null;

    let eventId  = null;
    let channel  = null;
    let computer = null;
    let jsonObj  = null;
    const fields = {};

    // ── Path 1: Winlogbeat / NXLog JSON ──
    const jsonMatch = raw.match(/\{.*"winlog".*\}/s);
    if (jsonMatch) {
      try {
        const obj = JSON.parse(jsonMatch[0]);
        jsonObj   = obj;
        const wl  = obj.winlog || {};
        eventId   = parseInt(wl.event_id);
        channel   = wl.channel || null;
        computer  = wl.computer_name || (obj.host && obj.host.name) || null;
        const ed  = wl.event_data || {};

        fields.user            = cleanUser(ed.TargetUserName || ed.SubjectUserName || ed.MemberName);
        fields.subject_user    = cleanUser(ed.SubjectUserName);
        fields.target_domain   = ed.TargetDomainName || ed.SubjectDomainName || null;
        fields.logon_type      = ed.LogonType || null;
        // srcip = the REAL remote client. IpAddress / Source Network Address.
        // 4768/4771 (Kerberos) sometimes carry it as ClientAddress.
        {
          const ipCand = ed.IpAddress || ed.ClientAddress || null;
          fields.src_ip = isValidIp(ipCand) ? String(ipCand).trim() : null;
        }
        if (isValidIp(ed.DestinationIp || ed.DestAddress)) {
          fields.dst_ip = String(ed.DestinationIp || ed.DestAddress).trim();
        }
        fields.src_port        = ed.IpPort || ed.SourcePort || null;
        fields.workstation     = ed.WorkstationName || ed.Workstation || null;
        fields.process_name    = ed.ProcessName || ed.ServiceName || null;
        fields.new_process_name = ed.NewProcessName || null;
        fields.parent_process  = ed.ParentProcessName || null;
        fields.command_line    = ed.CommandLine || null;
        fields.service_name    = ed.ServiceName || null;
        fields.logon_process   = ed.LogonProcessName || null;
        fields.auth_package    = ed.AuthenticationPackageName || null;
        fields.status_code     = ed.Status || null;
        fields.sub_status      = ed.SubStatus || null;
        fields.failure_reason  = ed.FailureReason || ed.Status || ed.SubStatus || null;
        fields.caller_computer = ed.CallerComputerName || null; // 4740 source workstation
      } catch (_) {}
    }

    // ── Path 2: CEF ──
    if (eventId == null) {
      const cef = raw.match(/CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s);
      if (cef) {
        eventId = parseInt(cef[5]);
        const ext = parseCEFExt(cef[8]);
        // CEF: src is the real client/source IP (attacker). suser = target account.
        fields.user        = cleanUser(ext.suser || ext.duser);
        {
          const ipCand = ext.src || ext.shost || null;
          fields.src_ip = isValidIp(ipCand) ? String(ipCand).trim() : null;
        }
        if (isValidIp(ext.dst)) fields.dst_ip = String(ext.dst).trim();
        fields.src_port     = ext.spt || null;
        fields.logon_type   = ext.cs1 || null;
        fields.workstation  = ext.shost || ext.sntdom || null;
        fields.process_name = ext.deviceProcessName || ext.dproc || null;
        fields.new_process_name = ext.deviceProcessName || null;
        fields.command_line = ext.cs2 || null;
        fields.target_domain = ext.duser ? null : (ext.sntdom || null);
        if (ext.msg) fields.failure_reason = ext.msg;
      }
    }

    // ── Path 3: MSWinEventLog / generic EventID/EventCode text (Snare etc.) ──
    if (eventId == null) {
      const m = raw.match(/MSWinEventLog\s+\d+\s+(\w+)\s+\d+\s+[^\t]*\s+(\d{3,5})/i)
             || raw.match(/MSWinEventLog\s+\d+\s+(\w+)\s+(\d{3,5})/i)
             || raw.match(/EventID["\s:=]+(\d{3,5})/i)
             || raw.match(/EventCode=(\d{3,5})/i);
      if (m) {
        if (m.length === 3) { channel = m[1]; eventId = parseInt(m[2]); }
        else eventId = parseInt(m[1]);
      }
    }

    // ── Field backfill from free text for ALL paths (only-when-present, never overwrite) ──
    if (eventId != null && !isNaN(eventId)) {
      if (!fields.user) {
        const userM = raw.match(/(?:Target User Name|TargetUserName|Account Name|Account Name:|suser)["\s:=]+([^\s,"\t]+)/i);
        if (userM) fields.user = cleanUser(userM[1]);
      }
      if (!fields.src_ip) {
        // Source Network Address / IpAddress = the REAL client, NOT the reporting host.
        const ipM = raw.match(/(?:Source Network Address|IpAddress|Client Address|ClientAddress|Source Address|\bsrc)["\s:=]+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,})/i);
        if (ipM && isValidIp(ipM[1])) fields.src_ip = ipM[1].trim();
      }
      if (!fields.logon_type) {
        const ltM = raw.match(/Logon Type["\s:=]+(\d+)/i);
        if (ltM) fields.logon_type = ltM[1];
      }
      if (!fields.workstation) {
        const wsM = raw.match(/(?:Workstation Name|WorkstationName)["\s:=]+([^\s,"\t]+)/i);
        if (wsM && wsM[1] !== '-') fields.workstation = wsM[1];
      }
      if (!fields.new_process_name) {
        const npM = raw.match(/(?:New Process Name|NewProcessName)["\s:=]+([^\t"]+?)(?=\s{2,}|\t|$)/i);
        if (npM) fields.new_process_name = npM[1].trim();
      }
      if (!fields.command_line) {
        const clM = raw.match(/(?:Process Command Line|CommandLine)["\s:=]+([^\t"]+?)(?=\s{2,}|\t|$)/i);
        if (clM) fields.command_line = clM[1].trim();
      }
      if (!fields.service_name) {
        const svM = raw.match(/(?:Service Name|ServiceName)["\s:=]+([^\t"]+?)(?=\s{2,}|\t|$)/i);
        if (svM && svM[1] !== '-') fields.service_name = svM[1].trim();
      }
    }

    if (eventId == null || isNaN(eventId)) return null;

    const info = EVENT_MAP[eventId] || { category: 'system', severity: 6, label: 'info', desc: `Windows Event ${eventId}` };

    const subcategory = subcategoryFor(eventId, fields);
    const action      = actionFor(eventId);

    const structured = {
      category:          info.category,
      event_id:          eventId,
      // Normalized contract: subcategory drives auth correlation.
      subcategory:       subcategory || null,
      action:            action || null,
      channel:           channel || null,
      computer_name:     computer || null,
      // Account fields
      user:              fields.user || null,
      subject_user:      fields.subject_user || null,
      target_domain:     fields.target_domain || null,
      logon_type:        fields.logon_type || null,
      // Normalized contract: `srcip` = real client/source IP (attacker), spelled per contract.
      srcip:             fields.src_ip || null,
      src_ip:            fields.src_ip || null,  // kept for back-compat
      dstip:             fields.dst_ip || null,
      src_port:          fields.src_port || null,
      workstation:       fields.workstation || null,
      caller_computer:   fields.caller_computer || null,
      // Auth result detail
      status_code:       fields.status_code || null,
      sub_status:        fields.sub_status || null,
      failure_reason:    fields.failure_reason || null,
      logon_process:     fields.logon_process || null,
      auth_package:      fields.auth_package || null,
      // Process / service
      process_name:      fields.process_name || null,
      new_process_name:  fields.new_process_name || null,
      parent_process:    fields.parent_process || null,
      command_line:      fields.command_line || null,
      service_name:      fields.service_name || null,
    };
    // subcategory is referenced by buildSummary for 4768/4769/4776 wording
    if (subcategory) structured.subcategory = subcategory;
    Object.keys(structured).forEach(k => (structured[k] == null) && delete structured[k]);

    const logTimestamp = extractTimestamp(raw, jsonObj);

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
      log_timestamp:   logTimestamp,
      parser_version:  'windows-v2.0',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseWindows, detectWindows };
