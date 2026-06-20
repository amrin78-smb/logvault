/**
 * SonicWall Parser for LogVault
 *
 * SonicWall (SonicOS) emits key=value syslog. Example:
 *   id=firewall sn=0012ABCD time="2026-05-29 10:00:00" fw=192.168.1.1 pri=5
 *   c=1024 m=537 msg="Connection Dropped" n=1234 src=10.1.1.5:1234:X0
 *   dst=8.8.8.8:443:X1 proto=TCP/HTTPS rule="LAN to WAN"
 *
 * Completeness pass (parity with the Fortinet deep pass):
 *   - NORMALIZED CONTRACT keys: srcip (REAL client, never the fw/sender), dstip,
 *     srcport, dstport, user, subcategory ('login_failed'|'login_success'|'auth_failed'),
 *     action; top-level `category` (vpn/authentication/security/web/firewall).
 *   - Generous field capture (only-when-present): proto, service, sess, rule, fw, sn,
 *     message id (m=), category-id (c=), note (n=), threat/signature name, app, url,
 *     web-filter category, and the priority.
 *   - TIMESTAMP uses the log's own time (with tz offset when SonicOS sends one), not
 *     the collector OS locale.
 *   - SEVERITY from pri= (SonicOS priority) mapped faithfully to syslog 0-7.
 */

'use strict';

// SonicWall pri (priority) → syslog severity number + label.
// SonicOS priorities: 0=Emergency 1=Alert 2=Critical 3=Error 4=Warning
// 5=Notice 6=Informational 7=Debug — i.e. they already line up with syslog
// severities, so map faithfully 1:1 (clamped) rather than bucketing.
const PRI_LABELS = {
  0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
  4: 'warning', 5: 'notice', 6: 'info', 7: 'debug',
};
function priToSeverity(pri) {
  const n = parseInt(pri, 10);
  if (isNaN(n)) return { severity: 6, label: 'info' };
  const sev = Math.max(0, Math.min(7, n));
  return { severity: sev, label: PRI_LABELS[sev] || 'info' };
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

// SonicWall src/dst use ip:port:interface — split out the parts.
// The port can be absent (ip::iface) and the interface can be absent (ip:port).
function splitEndpoint(val) {
  if (!val) return { ip: null, port: null, iface: null };
  const parts = val.split(':');
  const portNum = parts[1] ? parseInt(parts[1], 10) : null;
  return {
    ip:    parts[0] || null,
    port:  Number.isNaN(portNum) ? null : portNum,
    iface: parts[2] || null,
  };
}

// Derive a normalized action. Prefer the native SonicOS action= field, then
// fall back to the message text. Returns 'blocked' | 'allowed' | the raw native
// action | null.
function deriveAction(kv) {
  const native = (kv.action || '').toLowerCase();
  if (native) {
    if (/drop|deny|block|reset|reject|prevent/.test(native)) return 'blocked';
    if (/allow|accept|permit|forward|pass/.test(native))     return 'allowed';
    return native;
  }
  const msg = (kv.msg || '').toLowerCase();
  if (!msg) return null;
  if (/dropp?ed|blocked|denied|prevented|reset|rejected/.test(msg)) return 'blocked';
  if (/allowed|connection opened|permitted|accepted/.test(msg))     return 'allowed';
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
 * Classify a SonicWall event into a top-level `category` (and, for auth/VPN, a
 * `subcategory`) from the message ID (m=), the SonicOS category-id (c=), and the
 * msg text. NORMALIZED CONTRACT: the correlation engine + UI key off top-level
 * `category` and structured_data.subcategory.
 *
 *   category: 'vpn' | 'authentication' | 'security' | 'web' | 'firewall'
 *   subcategory: 'login_failed' | 'login_success' | 'auth_failed' (auth/vpn only)
 *
 * NOTE: the specific SonicOS m= message IDs below are a best-effort set and SHOULD
 * be refined against live samples. We also key off msg-text keywords defensively so
 * classification stays correct even when the m= id is unknown. Resolution order:
 * VPN/auth → security (threats) → web (content filter) → firewall (default).
 */
function classify(kv) {
  const msg = (kv.msg || '').toLowerCase();
  const mId = kv.m != null ? String(kv.m) : '';

  // --- SSL-VPN / user-login auth ---
  // SSL-VPN auth message IDs (best-effort; refine against live samples)
  const VPN_IDS = new Set(['1080', '1081', '1082', '1083', '1086', '1087', '1088']);
  // General user/admin-login auth message IDs (best-effort; refine against live samples)
  const AUTH_IDS = new Set(['22', '23', '24', '235', '236', '237', '238']);

  const isVpn  = VPN_IDS.has(mId) || /ssl\s*vpn|sslvpn|ssl-vpn/.test(msg);
  const isAuth = AUTH_IDS.has(mId)
    || /\b(user )?log\s?in|log\s?on|authentication|administrator login|admin login/.test(msg);

  if (isVpn || isAuth) {
    let subcategory = null;
    if (/denied|deny|fail|failure|invalid|incorrect|locked|rejected|unsuccessful|bad credential/.test(msg)) {
      // SSL-VPN / general login failures are login_failed; a non-login auth
      // failure (e.g. RADIUS/LDAP backend rejecting) is auth_failed.
      subcategory = (isVpn || /log\s?in|log\s?on/.test(msg)) ? 'login_failed' : 'auth_failed';
    } else if (/success|succeeded|granted|logged in|login successful|authenticated/.test(msg)) {
      subcategory = 'login_success';
    }
    return { category: isVpn ? 'vpn' : 'authentication', subcategory };
  }

  // --- Security: IPS / GAV / Anti-Spyware / Botnet / Geo-IP / anomaly ---
  // SonicOS groups these under category-id (c=) families and distinct msg text.
  const isSecurity =
    /intrusion|\bips\b|\bidp\b|signature|exploit|attack|prevention/.test(msg) ||
    /gateway anti.?virus|\bgav\b|virus|malware|trojan|ransomware|worm/.test(msg) ||
    /anti.?spyware|spyware/.test(msg) ||
    /botnet|command.?and.?control|\bc2\b|c&c/.test(msg) ||
    /geo.?ip|blocked country/.test(msg) ||
    /capture atp|threat detected|cloud anti.?virus/.test(msg);
  if (isSecurity) return { category: 'security', subcategory: null };

  // --- Web: Content Filter Service (CFS) / URL filtering ---
  // App Control web categories surface a url/category; treat URL/content blocks as 'web'.
  const isWeb =
    /content filter|cfs|web (site )?(access|filter)|url (category|filter|rating)|website blocked|blocked web/.test(msg) ||
    (kv.url != null && /\b(filter|block|rating|category)\b/.test(msg));
  if (isWeb) return { category: 'web', subcategory: null };

  // --- App Control ---
  // App Control can be policy/firewall- or security-flavored. When the event names
  // a threat-ish action keep it security, otherwise leave it as firewall (app field
  // is still captured). Default below handles the firewall case.
  if (/application control|app control|app.?ctrl/.test(msg)) {
    if (/block|deny|drop|detect/.test(msg)) return { category: 'security', subcategory: null };
  }

  // --- Default: normal connection traffic stays firewall ---
  return { category: 'firewall', subcategory: null };
}

// Extract a human-readable threat / signature name for security events. SonicOS
// puts the signature/threat name either in dedicated keys or inline in msg, e.g.
//   msg="IPS Detection Alert: WEB-ATTACKS SQL injection attempt, SID: 1234"
//   msg="Gateway Anti-Virus Alert: Trojan.Generic blocked"
function extractThreat(kv) {
  // Prefer explicit keys if a given firmware emits them.
  if (kv.threat)    return kv.threat;
  if (kv.signature) return kv.signature;
  if (kv.virus)     return kv.virus;
  if (kv.spyware)   return kv.spyware;
  const msg = kv.msg || '';
  // "<Family> Alert: <name>[, ...]" — capture the descriptive name after the colon.
  let m = msg.match(/(?:Alert|Detection|Detected|Prevention)\s*:\s*([^,;]+)/i);
  if (m && m[1]) return m[1].trim();
  return null;
}

function parseSonicWall(raw, sourceIp) {
  try {
    if (!detectSonicWall(raw)) return null;

    const stripped = raw.replace(/^<\d{1,3}>/, '').trim();
    const kv = parseKV(stripped);

    const sev    = priToSeverity(kv.pri);
    const action = deriveAction(kv);
    const src    = splitEndpoint(kv.src);
    const dst    = splitEndpoint(kv.dst);

    // Timestamp — use the LOG's own time, not the collector OS locale.
    // SonicOS sends time="YYYY-MM-DD HH:MM:SS" (local to the appliance). When a
    // tz offset is present (e.g. tz="GMT+07:00" / tz=+0700) honor it; otherwise
    // fall back to parsing the bare local time. Prefer gmtime= (UTC) when present.
    let logTimestamp = null;
    if (kv.gmtime) {
      const d = new Date(`${kv.gmtime.replace(' ', 'T')}Z`);
      if (!isNaN(d.getTime())) logTimestamp = d;
    }
    if (!logTimestamp && kv.time) {
      let offset = '';
      // tz forms seen in the wild: "+0700", "GMT+07:00", "GMT +7", "UTC+7"
      const tzRaw = (kv.tz || '').toString();
      let tzm = tzRaw.match(/([+-])(\d{2}):?(\d{2})/);          // +0700 / +07:00
      if (tzm) {
        offset = `${tzm[1]}${tzm[2]}:${tzm[3]}`;
      } else {
        tzm = tzRaw.match(/([+-])\s?(\d{1,2})\b/);              // GMT+7
        if (tzm) offset = `${tzm[1]}${String(tzm[2]).padStart(2, '0')}:00`;
      }
      const d = new Date(`${kv.time.replace(' ', 'T')}${offset}`);
      if (!isNaN(d.getTime())) logTimestamp = d;
    }

    const { category, subcategory } = classify(kv);
    const threat = (category === 'security') ? extractThreat(kv) : null;

    // Build a readable message.
    let message = 'SonicWall';
    if (kv.msg) message += `: ${kv.msg}`;
    if (threat) message += ` [${threat}]`;
    if (src.ip && dst.ip) message += ` ${src.ip} -> ${dst.ip}`;
    if (kv.proto) message += ` proto=${kv.proto}`;
    if (kv.service) message += ` svc=${kv.service}`;
    if (kv.rule) message += ` rule="${kv.rule}"`;

    // Username can arrive as usr= or user=.
    const user = kv.usr || kv.user || null;

    const structured = {
      // top-level category mirrored here; taxonomy.js honors a parser-set category first
      category,
      action,
      serial:       kv.sn || null,
      firewall_ip:  kv.fw || null,
      msg:          kv.msg || null,

      // ── NORMALIZED CONTRACT keys (correlation engine + UI rely on these exact
      // names): srcip = REAL client/source IP (attacker), never the fw/sender. ──
      srcip:        isValidIp(src.ip) ? src.ip : null,
      dstip:        isValidIp(dst.ip) ? dst.ip : null,
      srcport:      src.port,
      dstport:      dst.port,
      user,
      subcategory,

      // ── Generous capture (only-when-present) ──
      proto:        kv.proto || null,
      // `service` is read by /api/stats/top-services & /api/security/firewall-denies
      service:      kv.service || null,
      rule:         kv.rule || null,
      session:      kv.sess != null ? kv.sess : null,
      message_id:   kv.m != null ? kv.m : null,
      sonic_cat_id: kv.c != null ? kv.c : null,
      note_id:      kv.n != null ? kv.n : null,
      priority:     kv.pri != null && kv.pri !== '' ? parseInt(kv.pri, 10) : null,
      // Security / threat fields
      threat,
      signature:    kv.signature || null,
      virus:        kv.virus || null,
      spyware:      kv.spyware || null,
      // Web / content-filter & App Control fields
      url:          kv.url || null,
      web_category: kv.catname || kv.category || null,   // CFS category name (when present)
      app:          kv.app || kv.appName || null,

      // ── legacy keys kept for backwards compatibility ──
      src_ip:       src.ip,
      src_port:     src.port,
      src_iface:    src.iface,
      dst_ip:       dst.ip,
      dst_port:     dst.port,
      dst_iface:    dst.iface,
      protocol:     kv.proto || null,
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
      parser_version:  'sonicwall-v1.1',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseSonicWall, detectSonicWall };
