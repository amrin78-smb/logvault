/**
 * Juniper Parser for LogVault
 *
 * Covers:
 *   - Juniper SRX security gateway: RT_FLOW (traffic), RT_IDP (IDP/IPS),
 *     FWAUTH_* (firewall user auth) — modern SRX emits structured key=value.
 *   - Pulse Secure / Ivanti Connect Secure SSL-VPN (ic_session, AUT2xxxx).
 *   - Junos host auth: sshd "Failed/Accepted password", login "Login failed/succeeded".
 *   - Junos EX/MX switching + routing: SNMP traps, LINK_UP/DOWN, BGP/OSPF.
 *
 * 1. SRX flow (legacy tuple form):
 *    <pri>timestamp host RT_FLOW: RT_FLOW_SESSION_CREATE: session created
 *    10.1.1.5/1234->8.8.8.8/443 junos-https None 10.1.1.5/1234->8.8.8.8/443
 *    inbound-zone->outbound-zone ethernet0/0
 *
 * 1b. SRX flow (structured key=value form):
 *    <pri>timestamp host RT_FLOW: RT_FLOW_SESSION_CLOSE [junos@... reason="TCP RST"
 *    source-address="10.1.1.5" source-port="1234" destination-address="8.8.8.8"
 *    destination-port="443" service-name="junos-https" application="HTTP"
 *    protocol-id="6" policy-name="trust-to-untrust" source-zone-name="trust"
 *    destination-zone-name="untrust" bytes-from-client="840" bytes-from-server="1320"]
 *
 * 2. SRX IDP/IPS:
 *    <pri>timestamp host RT_IDP: IDP_ATTACK_LOG_EVENT: IDP: attack repeat=1,
 *    action=DROP, threat-severity=HIGH, attack-name=HTTP:OVERFLOW:CVE-2021-12345,
 *    source-address=185.220.101.1, source-port=45123, destination-address=10.1.1.5,
 *    destination-port=80, protocol-name=TCP
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

// Month name → 0-based index (RFC3164 / Junos syslog timestamp)
const MONTHS = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

function detectJuniper(raw) {
  if (!raw) return false;
  if (/RT_FLOW:/.test(raw))   return true;
  if (/RT_IDP:/.test(raw))    return true;
  if (/RT_UTM:/.test(raw))    return true;
  if (/JUNOS/i.test(raw))     return true;
  if (/\bRT_[A-Z_]+:/.test(raw)) return true;
  if (/junos@/i.test(raw))    return true;       // structured-data SD-ID (junos@2636...)
  if (/\bSNMP_TRAP_[A-Z_]+/.test(raw)) return true;          // EX/MX SNMP traps (LINK_UP/DOWN, ...)
  // Junos system daemons (EX/MX switching, mgmt, routing) — process[pid]: TAG
  if (/\b(?:mib2d|mgd|rpd|chassisd|dcd|eventd|kmd|l2cpd|cosd|fpc\d+)(?:\[\d+\])?:/i.test(raw)) return true;
  // Common Junos message tags (UI_*, RPD_*, SNMPD_*, CHASSISD_*, LACPD_*, L2ALD_*)
  if (/\b(?:UI|RPD|SNMPD|CHASSISD|LACPD|L2ALD|LIBJNX|PFE|DFWD|MIB2D)_[A-Z0-9_]+/.test(raw)) return true;
  if (isAuthEvent(raw))       return true;
  return false;
}

// Pull "key=value", "key-name=value", or 'key="value"' (comma or space separated).
function parseKV(str) {
  const kv = {};
  if (!str) return kv;
  const re = /([\w-]+)=("([^"]*)"|[^\s,\]]+)/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    kv[m[1]] = m[3] !== undefined ? m[3] : m[2];
  }
  return kv;
}

// Defensive IPv4 validation (0-255 per octet). Rejects syslog noise / partial matches.
function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((o) => {
    const n = parseInt(o, 10);
    return n >= 0 && n <= 255;
  });
}

// Parse an int from a string only when present; otherwise null (never NaN).
function intOrNull(v) {
  if (v == null || v === '') return null;
  const n = parseInt(v, 10);
  return isNaN(n) ? null : n;
}

// Detect auth / SSL-VPN / sshd / login events that need the normalized auth contract.
function isAuthEvent(raw) {
  if (!raw) return false;
  if (/RT_FLOW:\s*FWAUTH_/i.test(raw)) return true;          // SRX firewall user auth
  if (/\bFWAUTH_[A-Z_]+\b/.test(raw)) return true;           // FWAUTH in structured form
  if (/sshd(?:\[\d+\])?:/i.test(raw)) return true;            // Junos sshd
  if (/\blogin:\s*Login\s+(?:failed|succeeded)/i.test(raw)) return true; // Junos login
  if (/ic_session:/i.test(raw) || /\bAUT2\d{4}\b/.test(raw)) return true; // Pulse/Ivanti Connect Secure
  if (/\bUI_AUTH(?:ENTICATION)?_(?:FAILED|EVENT)\b/i.test(raw)) return true; // Junos mgmt auth
  return false;
}

// Severity + facility from the syslog PRI (<134> etc). Faithful to RFC 5424.
function sevFromPri(raw) {
  const m = raw.match(/^<(\d{1,3})>/);
  if (!m) return { severity: 6, label: 'info', facility: 23, facility_label: 'local7' };
  const pri = parseInt(m[1], 10);
  const severity = pri % 8;
  const facility = Math.floor(pri / 8);
  return { severity, label: SEV_LABELS[severity] || 'info', facility, facility_label: `local${facility - 16 >= 0 ? facility - 16 : facility}` };
}

/**
 * Derive log_timestamp from the log line itself (never the collector OS clock/locale).
 * Junos can emit two timestamp styles:
 *   - RFC3164:  "May 12 10:23:01"  (no year, no offset — assume current year, treat as local→leave naive)
 *   - RFC5424:  "2026-05-12T10:23:01.123+07:00"  (preferred — carries the real offset)
 * We honor an explicit offset when present; for the year-less RFC3164 form we build a
 * UTC date with the current year so the value is stable regardless of collector locale.
 */
function parseTimestamp(raw) {
  // RFC5424 ISO form with optional fractional seconds + offset/Z
  const iso = raw.match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/);
  if (iso) {
    let s = iso[1];
    // Normalize "+0700" (no colon) → "+07:00" for the JS Date parser
    s = s.replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
    const d = new Date(s);
    if (!isNaN(d.getTime())) return d;
  }

  // RFC3164 "Mon DD HH:MM:SS" (year-less). Build a UTC date with the current year so the
  // parsed value never depends on the collector OS timezone/locale.
  const m = raw.match(/^(?:<\d{1,3}>)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    const mon = MONTHS[m[1].toLowerCase()];
    if (mon !== undefined) {
      const now = new Date();
      let year = now.getUTCFullYear();
      const d = new Date(Date.UTC(year, mon, parseInt(m[2], 10),
        parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10)));
      // If that lands more than ~24h in the future, the log is from last December.
      if (d.getTime() - now.getTime() > 24 * 3600 * 1000) {
        d.setUTCFullYear(year - 1);
      }
      if (!isNaN(d.getTime())) return d;
    }
  }
  return null;
}

function parseJuniper(raw, sourceIp) {
  try {
    if (!detectJuniper(raw)) return null;

    const base = sevFromPri(raw);

    // Extract hostname after timestamp if present (RFC3164 or ISO form)
    let sourceHost = null;
    const hostMatch3164 = raw.match(/^(?:<\d{1,3}>)?[A-Za-z]{3}\s+\d{1,2}\s+[\d:]+\s+(\S+)\s/);
    const hostMatchIso  = raw.match(/^(?:<\d{1,3}>)?\d{4}-\d{2}-\d{2}T[\d:.+-Z]+\s+(\S+)\s/);
    if (hostMatch3164) sourceHost = hostMatch3164[1];
    else if (hostMatchIso) sourceHost = hostMatchIso[1];

    const logTimestamp = parseTimestamp(raw);

    let severity      = base.severity;
    let severityLabel = base.label;
    let category      = 'network';
    let message       = raw;
    const structured  = {};

    if (isAuthEvent(raw)) {
      // Auth / SSL-VPN / sshd / login — emit normalized contract keys
      const kvAll = parseKV(raw);

      let subcategory = 'login_failed';   // safe default for auth-fail logs

      let srcip = null;
      let dstip = null;
      let user  = null;

      if (/RT_FLOW:\s*FWAUTH_/i.test(raw) || /\bFWAUTH_[A-Z_]+\b/.test(raw)) {
        // SRX FWAUTH: ... username=bob source-address=203.0.113.55 (success/fail in event name)
        category = 'authentication';
        structured.event_type = 'FWAUTH';
        const fwm = raw.match(/\b(FWAUTH_[A-Z_]+)\b/);
        if (fwm) structured.fwauth_event = fwm[1];
        user = kvAll.username || kvAll['user-name'] || kvAll.user || null;
        const sa = kvAll['source-address'] || kvAll['src-ip'] || kvAll.srcip || null;
        if (isValidIp(sa)) srcip = sa;
        const da = kvAll['destination-address'] || kvAll['dst-ip'] || kvAll.dstip || null;
        if (isValidIp(da)) dstip = da;
        if (kvAll['source-port']) structured.srcport = intOrNull(kvAll['source-port']);
        if (kvAll['destination-port']) structured.dstport = intOrNull(kvAll['destination-port']);
        // Outcome: FWAUTH_FTP_USER_AUTH_OK / _FAIL, or explicit ACCEPT/FAIL tokens
        const ok = /(_OK\b|SUCCESS|ACCEPT|_PASS\b)/i.test(raw) && !/(FAIL|DENY|REJECT|INVALID)/i.test(raw);
        subcategory = ok ? 'login_success' : 'auth_failed';

      } else if (/ic_session:/i.test(raw) || /\bAUT2\d{4}\b/.test(raw)) {
        // Pulse / Ivanti Connect Secure SSL-VPN
        category = 'vpn';
        structured.event_type = 'IC_SESSION';
        const codeM = raw.match(/\b(AUT2\d{4})\b/);
        if (codeM) structured.message_code = codeM[1];
        const um = raw.match(/user(?:\s+with\s+username)?\s+'([^']+)'/i) || raw.match(/\buser\s+([^\s,]+)/i);
        if (um) user = um[1];
        const realmM = raw.match(/realm\s+'([^']+)'/i);
        if (realmM) structured.realm = realmM[1];
        const roleM = raw.match(/roles?\s+'([^']+)'/i);
        if (roleM) structured.role = roleM[1];
        const im = raw.match(/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/i);
        if (im && isValidIp(im[1])) srcip = im[1];
        subcategory = /login\s+succeeded|login\s+success|session\s+started|primary\s+authentication\s+successful/i.test(raw)
          ? 'login_success' : 'auth_failed';

      } else if (/sshd(?:\[\d+\])?:/i.test(raw)) {
        // Junos sshd: Failed/Accepted password for [invalid user ]<user> from <ip> port .. ssh2
        category = 'authentication';
        structured.event_type = 'SSHD';
        const um = raw.match(/(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})/i);
        if (um) {
          user = um[1];
          if (isValidIp(um[2])) srcip = um[2];
        } else {
          const im = raw.match(/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/i);
          if (im && isValidIp(im[1])) srcip = im[1];
          const u2 = raw.match(/for\s+(?:invalid\s+user\s+)?(\S+)/i);
          if (u2) user = u2[1];
        }
        if (/invalid\s+user/i.test(raw)) structured.invalid_user = true;
        const portM = raw.match(/\bport\s+(\d+)/i);
        if (portM) structured.srcport = intOrNull(portM[1]);
        subcategory = /\bAccepted\b/i.test(raw) ? 'login_success' : 'login_failed';

      } else if (/\blogin:\s*Login\s+(?:failed|succeeded)/i.test(raw)) {
        // Junos login: Login failed for user admin from host 203.0.113.55
        category = 'authentication';
        structured.event_type = 'LOGIN';
        const um = raw.match(/for\s+user\s+(\S+)/i);
        if (um) user = um[1];
        const im = raw.match(/\bfrom\s+(?:host\s+)?(\d{1,3}(?:\.\d{1,3}){3})/i);
        if (im && isValidIp(im[1])) srcip = im[1];
        subcategory = /Login\s+succeeded/i.test(raw) ? 'login_success' : 'login_failed';

      } else if (/\bUI_AUTH(?:ENTICATION)?_(?:FAILED|EVENT)\b/i.test(raw)) {
        // Junos management-plane auth (UI_AUTHENTICATION_FAILED)
        category = 'authentication';
        structured.event_type = 'UI_AUTH';
        const um = raw.match(/user\s+'([^']+)'/i) || raw.match(/for\s+user\s+(\S+)/i);
        if (um) user = um[1];
        const im = raw.match(/\bfrom\s+(?:host\s+)?(\d{1,3}(?:\.\d{1,3}){3})/i);
        if (im && isValidIp(im[1])) srcip = im[1];
        subcategory = /FAILED|denied|invalid/i.test(raw) ? 'auth_failed' : 'login_success';
      }

      if (srcip) structured.srcip = srcip;
      if (dstip) structured.dstip = dstip;
      if (user)  structured.user  = user;
      structured.subcategory = subcategory;
      structured.action = subcategory === 'login_success' ? 'success' : 'failed';

      // severity: failed auth = warning, success = notice (keep pri-derived if more severe)
      if ((subcategory === 'login_failed' || subcategory === 'auth_failed') && severity > 4) {
        severity = 4; severityLabel = 'warning';
      }

      message = `Juniper auth ${structured.event_type || ''} ${subcategory}`.trim();
      if (user)  message += ` user=${user}`;
      if (srcip) message += ` from ${srcip}`;

    } else if (/RT_IDP:/.test(raw)) {
      // IDS/IPS attack event
      category = 'security';
      const kv = parseKV(raw);
      const ts = (kv['threat-severity'] || '').toLowerCase();
      if (THREAT_SEV[ts]) { severity = THREAT_SEV[ts].severity; severityLabel = THREAT_SEV[ts].label; }
      else { severity = 3; severityLabel = 'error'; }

      structured.event_type      = 'RT_IDP';
      structured.type            = 'ips';
      const idpEv = raw.match(/(IDP_ATTACK_LOG_EVENT\w*|RT_IDP_[A-Z_]+)/);
      if (idpEv) structured.idp_event = idpEv[1];
      structured.attack_name     = kv['attack-name'] || null;
      structured.threat_severity = kv['threat-severity'] || null;
      // Accept both src-ip/dst-ip and source-address/destination-address spellings
      const sa = kv['source-address'] || kv['src-ip'] || null;
      const da = kv['destination-address'] || kv['dst-ip'] || null;
      const sp = kv['source-port'] || kv['src-port'] || null;
      const dp = kv['destination-port'] || kv['dst-port'] || null;
      const rawAction = (kv.action || '').toLowerCase();
      structured.action = rawAction.includes('drop') || rawAction.includes('close') || rawAction.includes('block')
        ? 'blocked'
        : (rawAction || null);
      // Legacy underscore keys retained for any old consumers
      structured.src_ip   = sa || null;
      structured.dst_ip   = da || null;
      structured.src_port = intOrNull(sp);
      structured.dst_port = intOrNull(dp);
      // Normalized contract keys (correlation engine + UI rely on these exact keys)
      if (isValidIp(sa)) structured.srcip = sa;
      if (isValidIp(da)) structured.dstip = da;
      structured.srcport      = intOrNull(sp);
      structured.dstport      = intOrNull(dp);
      structured.protocol     = kv['protocol-name'] || kv['protocol-id'] || null;
      structured.service      = kv['service-name'] || kv.service || null;
      structured.application  = kv.application || kv['application-name'] || null;
      structured.policy       = kv['policy-name'] || kv.policy || null;
      structured.rule         = kv['rule-name'] || kv.rulebase || null;
      structured.repeat_count = intOrNull(kv.repeat);
      structured.elapsed_time = kv['elapsed-time'] || null;

      message = `Juniper IDP attack ${structured.attack_name || ''}`.trim();
      if (structured.srcip && structured.dstip) message += `: ${structured.srcip} -> ${structured.dstip}`;
      else if (structured.src_ip && structured.dst_ip) message += `: ${structured.src_ip} -> ${structured.dst_ip}`;
      if (kv.action) message += ` action=${kv.action}`;

    } else if (/RT_FLOW:/.test(raw)) {
      // Session create/close — supports legacy tuple form AND structured key=value form
      category = 'firewall';
      const evMatch = raw.match(/(RT_FLOW_SESSION_\w+|APPTRACK_SESSION_\w+)/);
      const event   = evMatch ? evMatch[1] : 'RT_FLOW';
      structured.event_type = event;

      const kv = parseKV(raw);
      const hasStructured = kv['source-address'] || kv['destination-address'];

      if (hasStructured) {
        // Modern SRX structured key=value flow log
        const sa = kv['source-address'] || null;
        const da = kv['destination-address'] || null;
        structured.src_ip   = sa;
        structured.dst_ip   = da;
        structured.src_port = intOrNull(kv['source-port']);
        structured.dst_port = intOrNull(kv['destination-port']);
        if (isValidIp(sa)) structured.srcip = sa;
        if (isValidIp(da)) structured.dstip = da;
        structured.srcport     = intOrNull(kv['source-port']);
        structured.dstport     = intOrNull(kv['destination-port']);
        structured.application = kv.application || kv['application-name'] || kv['service-name'] || null;
        structured.service     = kv['service-name'] || null;
        structured.protocol    = kv['protocol-id'] || kv['protocol-name'] || null;
        structured.policy      = kv['policy-name'] || null;
        structured.src_zone    = kv['source-zone-name'] || null;
        structured.dst_zone    = kv['destination-zone-name'] || null;
        structured.interface   = kv['inbound-interface'] || kv['outbound-interface'] || null;
        structured.reason      = kv.reason || null;
        structured.session_id  = kv['session-id-32'] || kv['session-id'] || null;
        structured.nat_src_ip  = kv['nat-source-address'] || null;
        structured.nat_dst_ip  = kv['nat-destination-address'] || null;
        structured.nat_src_port = intOrNull(kv['nat-source-port']);
        structured.nat_dst_port = intOrNull(kv['nat-destination-port']);
        const bc = intOrNull(kv['bytes-from-client']);
        const bs = intOrNull(kv['bytes-from-server']);
        if (bc != null) structured.bytes_from_client = bc;
        if (bs != null) structured.bytes_from_server = bs;
        if (bc != null || bs != null) structured.bytes = (bc || 0) + (bs || 0);
        structured.packets_from_client = intOrNull(kv['packets-from-client']);
        structured.packets_from_server = intOrNull(kv['packets-from-server']);
        structured.username = kv['username'] || null;
      } else {
        // Legacy positional tuple: 10.1.1.5/1234->8.8.8.8/443 svc None ... zone->zone iface
        const tuple   = raw.match(/(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)->(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)/);
        const appMatch  = raw.match(/->\d+\s+(\S+)\s+\S+/);
        const zoneMatch = raw.match(/([\w-]+)->([\w-]+)\s+(\S+)\s*$/);
        if (tuple) {
          structured.src_ip   = tuple[1];
          structured.src_port = intOrNull(tuple[2]);
          structured.dst_ip   = tuple[3];
          structured.dst_port = intOrNull(tuple[4]);
          if (isValidIp(tuple[1])) structured.srcip = tuple[1];
          if (isValidIp(tuple[3])) structured.dstip = tuple[3];
          structured.srcport  = intOrNull(tuple[2]);
          structured.dstport  = intOrNull(tuple[4]);
        }
        structured.application = appMatch ? appMatch[1] : null;
        structured.src_zone    = zoneMatch ? zoneMatch[1] : null;
        structured.dst_zone    = zoneMatch ? zoneMatch[2] : null;
        structured.interface   = zoneMatch ? zoneMatch[3] : null;
      }

      structured.action = /CLOSE/.test(event) ? 'closed'
                        : /DENY|REJECT|DROP/i.test(event) ? 'blocked'
                        : 'allowed';

      message = `Juniper ${event}`;
      if (structured.srcip && structured.dstip) message += `: ${structured.srcip} -> ${structured.dstip}`;
      else if (structured.src_ip && structured.dst_ip) message += `: ${structured.src_ip} -> ${structured.dst_ip}`;
      if (structured.application) message += ` app=${structured.application}`;

    } else if (/RT_UTM:/.test(raw)) {
      // SRX UTM (web-filtering / antivirus / content) — treat as security
      category = 'security';
      const kv = parseKV(raw);
      structured.event_type  = (raw.match(/(WEBFILTER_\w+|AV_\w+|CONTENT_\w+|RT_UTM_\w+)/) || [])[1] || 'RT_UTM';
      structured.type        = /WEBFILTER/i.test(raw) ? 'webfilter' : 'utm';
      const sa = kv['source-address'] || kv['src-ip'] || null;
      const da = kv['destination-address'] || kv['dst-ip'] || null;
      if (isValidIp(sa)) structured.srcip = sa;
      if (isValidIp(da)) structured.dstip = da;
      structured.url       = kv.url || kv['object-name'] || null;
      structured.category_name = kv.category || null;
      structured.action    = (kv.action || '').toLowerCase() || null;
      structured.profile   = kv['profile-name'] || kv.profile || null;
      message = `Juniper ${structured.event_type}`;
      if (structured.url) message += ` url=${structured.url}`;

    } else {
      // EX/MX switching / SNMP traps / routing
      const trapMatch = raw.match(/(SNMP_TRAP_\w+|[A-Z][A-Z0-9_]+_(?:UP|DOWN))/);
      const kv = parseKV(raw);
      const trap = trapMatch ? trapMatch[1] : null;

      if (trap && /LINK_(UP|DOWN)/.test(trap)) {
        category = 'interface';
        structured.link_state = /DOWN/.test(trap) ? 'down' : 'up';
        if (structured.link_state === 'down') { severity = 4; severityLabel = 'warning'; }
      } else if (/BGP|OSPF|RIP|RPD_/i.test(raw)) {
        category = 'routing';
      } else if (/UI_(COMMIT|CFG|CONFIGURATION|LOAD)/i.test(raw) || /mgd\[/i.test(raw)) {
        category = 'configuration';
        const cfgUser = raw.match(/User\s+'([^']+)'/i);
        if (cfgUser) structured.user = cfgUser[1];
      }

      structured.event_type    = trap || (raw.match(/\b([A-Z][A-Z0-9_]{3,})\b:/) || [])[1] || null;
      structured.interface     = kv.ifIndex || kv.interface || kv['interface-name'] || null;
      structured.admin_status  = kv.ifAdminStatus || null;
      structured.oper_status   = kv.ifOperStatus || null;

      const progMatch = raw.match(/\s([\w-]+)(?:\[\d+\])?:\s/);
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
      category,
      program:         structured.event_type || 'JUNOS',
      message,
      raw_message:     raw,
      structured_data: structured,
      is_parsed:       true,
      log_timestamp:   logTimestamp,
      parser_version:  'juniper-v2.6',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseJuniper, detectJuniper };
