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

// Basic IPv4 validation so we never emit junk (e.g. a hostname) under srcip/dstip
function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every(o => Number(o) <= 255);
}

/*
 * Classify SonicWall auth / SSL-VPN events from the message ID (m=) and/or msg text.
 * NORMALIZED CONTRACT: the correlation engine + UI key off top-level `category`
 * ('vpn' | 'authentication') and structured_data.subcategory ('login_failed' |
 * 'login_success'). Non-auth events keep category 'firewall'.
 *
 * NOTE: the specific SonicOS m= message IDs below are a best-effort starting set
 * (SSL-VPN auth IDs cluster around 1080-1090, user login around 22-24/235-238) and
 * SHOULD be refined against live samples. We therefore also key off msg-text
 * keywords defensively so classification is correct even when the m= id is unknown.
 */
function classifyAuth(kv) {
  const msg = (kv.msg || '').toLowerCase();
  const mId = kv.m != null ? String(kv.m) : '';

  // SSL-VPN auth message IDs (best-effort; refine against live samples)
  const VPN_IDS = new Set(['1080', '1081', '1082', '1083', '1086', '1087', '1088']);
  // General user-login auth message IDs (best-effort; refine against live samples)
  const AUTH_IDS = new Set(['22', '23', '24', '235', '236', '237', '238']);

  const isVpn  = VPN_IDS.has(mId) || /ssl\s*vpn|sslvpn/.test(msg);
  const isAuth = AUTH_IDS.has(mId) || /\b(user )?login|authentication|administrator login/.test(msg);

  if (!isVpn && !isAuth) return null;

  // Determine success vs failure from msg keywords
  let subcategory = null;
  if (/denied|fail|failure|invalid|incorrect|locked|rejected|unsuccessful/.test(msg)) {
    subcategory = 'login_failed';
  } else if (/success|succeeded|granted|logged in|login successful/.test(msg)) {
    subcategory = 'login_success';
  }

  // SSL-VPN events -> 'vpn'; general user/admin login -> 'authentication'
  const category = isVpn ? 'vpn' : 'authentication';
  return { category, subcategory };
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

    // Classify auth/SSL-VPN events so they are NOT mis-categorized as 'firewall'.
    const auth = classifyAuth(kv);
    // top-level category: 'vpn'/'authentication' for auth events, else 'firewall'
    const category = auth ? auth.category : 'firewall';

    const structured = {
      // top-level category mirrored here; taxonomy.js honors a parser-set category first
      category,
      action,
      serial:       kv.sn || null,
      firewall_ip:  kv.fw || null,
      msg:          kv.msg || null,
      // NORMALIZED CONTRACT keys (correlation engine + UI rely on these exact names):
      //   srcip = REAL client/source IP (attacker), dstip = destination IP, user = account.
      srcip:        isValidIp(src.ip) ? src.ip : null,
      dstip:        isValidIp(dst.ip) ? dst.ip : null,
      user:         kv.usr || null,
      subcategory:  auth ? auth.subcategory : null,
      // legacy keys kept for backwards compatibility
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
