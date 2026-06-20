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

  // Timestamp — use the device's own timezone offset (kv.tz, e.g. "+0700").
  // FortiOS sends the real offset in kv.tz; without it the parser depended on the
  // collector OS locale (worked only by accident). JS Date needs "+07:00" (with a
  // colon), so normalize "+0700" -> "+07:00"; fall back to UTC ('Z') if tz is
  // missing or malformed.
  let logTimestamp = null;
  if (kv.date && kv.time) {
    let offset = 'Z';
    if (typeof kv.tz === 'string' && /^[+-]\d{4}$/.test(kv.tz)) {
      offset = `${kv.tz.slice(0, 3)}:${kv.tz.slice(3)}`;
    }
    try { logTimestamp = new Date(`${kv.date}T${kv.time}${offset}`); } catch (_) {}
    if (logTimestamp && isNaN(logTimestamp.getTime())) logTimestamp = null;
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

  // FortiOS uses `srcip` for traffic logs but `remip` for VPN/auth logs.
  // The correlation engine + UI key off structured_data.srcip, so when the log
  // carries the remote-client IP as `remip` (and has no srcip of its own), surface
  // it as srcip too — without overwriting an existing srcip. Keep the original remip.
  const srcip = kv.srcip || kv.remip;

  // Auth outcome for VPN / login events. FortiOS encodes it in action/logdesc/msg
  // (e.g. action=ssl-login-fail, logdesc="SSL VPN login fail", reason=..._permission_denied).
  // Downstream security widgets + the correlation engine detect failures via
  // structured_data.subcategory, so derive it here. Only classify genuine auth events
  // (vpn subtype or a login/auth blob) so traffic/UTM logs are never mislabeled.
  let subcategory;
  const authBlob = `${kv.action || ''} ${kv.logdesc || ''} ${kv.msg || ''} ${kv.reason || ''}`.toLowerCase();
  const isAuthEvent = kv.subtype === 'vpn' || /\b(?:login|logon|auth)/.test(authBlob);
  if (isAuthEvent) {
    // Failures FIRST — note "ssl-login-fail" contains the substring "ssl-login",
    // so a failure must never fall through to the success branch.
    if (/fail|denied|reject|invalid|incorrect|permission_den/.test(authBlob)) {
      subcategory = 'login_failed';
    } else if (
      /success|logged in|tunnel.?up|established/.test(authBlob) ||
      // FortiOS SSL-VPN *successful* login carries no "success" word —
      // action="ssl-login" / logdesc="SSL VPN login" (logid 0101039424). The fail
      // branch above already consumed "ssl-login-fail", so any remaining ssl-login
      // / "vpn login" here is a genuine success.
      /ssl-login\b/.test(authBlob) ||
      /vpn login/.test(authBlob)
    ) {
      subcategory = 'login_success';
    }
  }

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
      subcategory: subcategory,
      srcip:    srcip,
      dstip:    kv.dstip,
      srcport:  kv.srcport,
      dstport:  kv.dstport,
      action:   kv.action,
      policy:   kv.policyid,
      vd:       kv.vd,
      msg:      kv.msg,
      // Device timezone offset as sent by FortiOS (e.g. "+0700"); also used above
      // to build an offset-correct log_timestamp.
      tz:       kv.tz,
      // Security-relevant identity / source fields (VPN / auth-failure logs).
      // remip is the real remote client/attacker IP; user is the targeted account.
      remip:    kv.remip,
      user:     kv.user,
      group:    kv.group,
      srccountry: kv.srccountry,
      reason:   kv.reason,
      logdesc:  kv.logdesc,
      dst_host: kv.dst_host,
      // --- Traffic / general ---
      // `service` MUST be captured: /api/stats/top-services and
      // /api/security/firewall-denies read structured_data->>'service'.
      service:      kv.service,
      dstcountry:   kv.dstcountry,
      proto:        kv.proto,
      srcintf:      kv.srcintf,
      dstintf:      kv.dstintf,
      srcintfrole:  kv.srcintfrole,
      dstintfrole:  kv.dstintfrole,
      sessionid:    kv.sessionid,
      policyname:   kv.policyname,
      sentbyte:     kv.sentbyte,
      rcvdbyte:     kv.rcvdbyte,
      sentpkt:      kv.sentpkt,
      rcvdpkt:      kv.rcvdpkt,
      duration:     kv.duration,
      app:          kv.app,
      appcat:       kv.appcat,
      srcmac:       kv.srcmac,
      devtype:      kv.devtype,
      // --- VPN ---
      locip:        kv.locip,
      locport:      kv.locport,
      remport:      kv.remport,
      tunneltype:   kv.tunneltype,
      tunnelid:     kv.tunnelid,
      status:       kv.status,
      xauthuser:    kv.xauthuser,
      xauthgroup:   kv.xauthgroup,
      error_num:    kv.error_num,
      vpntunnel:    kv.vpntunnel,
      assignip:     kv.assignip,
      outintf:      kv.outintf,
      // --- UTM / IPS (utm / ssl) ---
      eventtype:    kv.eventtype,
      eventsubtype: kv.eventsubtype,
      certdesc:     kv.certdesc,
      certhash:     kv.certhash,
      hostname:     kv.hostname,
      profile:      kv.profile,
      ref:          kv.ref,
      attack:       kv.attack,
      attackid:     kv.attackid,
      virus:        kv.virus,
      filename:     kv.filename,
      threattype:   kv.threattype,
      count:        kv.count,
      // FortiOS UTM severity field — kept separate so it never overwrites the
      // top-level numeric `severity`.
      fgt_severity: kv.severity,
      // --- Webfilter ---
      url:          kv.url,
      cat:          kv.cat,
      catdesc:      kv.catdesc,
      crscore:      kv.crscore,
      crlevel:      kv.crlevel,
      craction:     kv.craction,
      direction:    kv.direction,
      // --- System ---
      ui:           kv.ui,
    },
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseFortinet };
