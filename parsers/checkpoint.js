/**
 * Check Point Parser for LogVault
 *
 * Covers the three log shapes Check Point gateways emit:
 *
 * 1. LEA (Log Export API) / key=value syslog:
 *    <priority>date=2026-05-29 time=10:00:00 action=Drop src=10.1.1.5 dst=8.8.8.8
 *    proto=TCP sport=1234 dport=443 fw_message=Connection dropped product=FireWall-1
 *
 * 2. CEF:
 *    CEF:0|Check Point|VPN-1 & FireWall-1|R81|Drop|Connection|4|src=10.1.1.5 dst=8.8.8.8 act=Drop
 *
 * 3. Syslog with Check Point kernel header (semicolon separated):
 *    host kernel: [fw4_0]product=Firewall; src=10.1.1.5; dst=8.8.8.8; proto=6; action=drop;
 */

'use strict';

// Action → syslog severity number + label
const CP_ACTION_SEV = {
  accept:    { severity: 6, label: 'info' },
  encrypt:   { severity: 6, label: 'info' },
  decrypt:   { severity: 6, label: 'info' },
  allow:     { severity: 6, label: 'info' },
  drop:      { severity: 4, label: 'warning' },
  block:     { severity: 4, label: 'warning' },
  reject:    { severity: 3, label: 'error' },
  alert:     { severity: 2, label: 'critical' },
  malicious: { severity: 2, label: 'critical' },
  prevent:   { severity: 2, label: 'critical' },
};

// Normalize Check Point action → blocked/allowed for downstream taxonomy + risk
function normalizeAction(act) {
  if (!act) return null;
  const lower = act.toLowerCase();
  if (['accept', 'allow', 'encrypt', 'decrypt'].includes(lower)) return 'allowed';
  if (['drop', 'block', 'reject', 'prevent'].includes(lower))    return 'blocked';
  if (['alert', 'malicious'].includes(lower))                    return 'alert';
  return lower;
}

// Map Check Point product → standard category.
// Order matters: most specific blades first so e.g. "Anti-Virus" doesn't fall
// through to the generic firewall bucket. URL Filtering / Application Control →
// 'application' (taxonomy.js normalizes that to 'web'). Threat Prevention blades
// (IPS / Anti-Bot / Anti-Virus / Threat Emulation/Extraction / SmartDefense) →
// 'security'. Identity Awareness → 'authentication'. Mobile Access / VPN → 'vpn'.
function productToCategory(product) {
  const p = (product || '').toLowerCase();
  // Threat Prevention family (security) — check BEFORE 'vpn'/'firewall' so a
  // product string like "Anti Malware" isn't mis-bucketed.
  if (p.includes('ips') || p.includes('smartdefense') ||
      p.includes('anti-bot') || p.includes('anti bot') || p.includes('antibot') ||
      p.includes('anti-virus') || p.includes('anti virus') || p.includes('antivirus') ||
      p.includes('anti-malware') || p.includes('anti malware') ||
      p.includes('threat emulation') || p.includes('threat extraction') ||
      p.includes('threat prevention') || p.includes('sandblast') ||
      p.includes('dlp')) {
    return p.includes('dlp') ? 'dlp' : 'security';
  }
  // URL Filtering / Application Control (web)
  if (p.includes('url filtering') || p.includes('urlf') ||
      p.includes('application control') || p.includes('app control') ||
      p.includes('application') || p.includes('app')) return 'application';
  // Identity Awareness (authentication)
  if (p.includes('identity awareness') || p.includes('identity')) return 'authentication';
  // Mobile Access / VPN (vpn)
  if (p.includes('mobile access') || p.includes('mobile')) return 'vpn';
  if (p.includes('vpn-1') || p.includes('vpn'))            return 'vpn';
  // Firewall
  if (p.includes('firewall-1') || p.includes('firewall'))  return 'firewall';
  return 'firewall';
}

// Threat Prevention severity (Check Point uses textual severity for threat blades:
// Critical / High / Medium / Low / Informational) → syslog severity number + label.
const CP_THREAT_SEV = {
  critical:      { severity: 2, label: 'critical' },
  high:          { severity: 3, label: 'error' },
  medium:        { severity: 4, label: 'warning' },
  low:           { severity: 5, label: 'notice' },
  informational: { severity: 6, label: 'info' },
  info:          { severity: 6, label: 'info' },
};

function severityForAction(act) {
  const lower = (act || '').toLowerCase();
  return CP_ACTION_SEV[lower] || { severity: 5, label: 'notice' };
}

// Validate an IPv4 address (4 octets, 0-255). Returns the IP or null.
function validIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  for (let i = 1; i <= 4; i++) { if (parseInt(m[i], 10) > 255) return null; }
  return ip.trim();
}

// Derive auth subcategory for Mobile Access / VPN / Identity Awareness events.
// Returns 'login_failed', 'login_success', or null (non-auth / unknown).
function authSubcategory(category, rawAction, kv, eventName) {
  if (category !== 'vpn' && category !== 'authentication') return null;
  const action = (rawAction || '').toLowerCase();
  const status = (kv.auth_status || kv.authentication_status || '').toLowerCase();
  const reason = `${kv.fw_message || ''} ${kv.reason || ''} ${eventName || ''}`.toLowerCase();

  const failHints = /fail|failed|reject|deny|denied|block|drop|invalid|incorrect|wrong|bad|lockout|locked/;
  const okHints   = /success|succeed|succeeded|accept|accepted|granted|logon|logged in|authenticated|established/;

  if (status.includes('fail') || /reject|block|drop/.test(action)) return 'login_failed';
  if (status.includes('success') || status.includes('accept')) return 'login_success';
  if (failHints.test(reason)) return 'login_failed';
  if (/accept|allow|encrypt|decrypt/.test(action) || okHints.test(reason)) return 'login_success';
  return null;
}

// Parse key=value (LEA / CEF extension) and key=value; (kernel header) pairs
function parseKV(str) {
  const kv = {};
  if (!str) return kv;
  // Semicolon-separated kernel header style
  if (/;\s*\w+=/.test(str)) {
    for (const part of str.split(';')) {
      const m = part.match(/\s*(\w+)=(.*)/);
      if (m) kv[m[1]] = m[2].trim();
    }
    return kv;
  }
  // Space-separated, values may be quoted
  const re = /(\w+)=(?:"([^"]*)"|(\S+))/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    kv[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }
  return kv;
}

function detectCheckPoint(raw) {
  if (!raw) return false;
  if (/product=VPN-1/i.test(raw))       return true;
  if (/product=FireWall-1/i.test(raw))  return true;
  // Check Point auth/VPN/threat/web products (Log Exporter `product=` field).
  if (/product=(?:"?\s*)?(?:Mobile Access|VPN|Identity Awareness|IPS|SmartDefense|Anti[- ]?Bot|Anti[- ]?Virus|Anti[- ]?Malware|Threat Emulation|Threat Extraction|Threat Prevention|SandBlast|URL Filtering|Application Control|DLP)\b/i.test(raw)) return true;
  if (/\bauth_status=/i.test(raw))      return true;
  // Threat Prevention / IPS signals
  if (/\bprotection_name=/i.test(raw))  return true;
  if (/\bprotection_type=/i.test(raw))  return true;
  if (/\bmalware_family=/i.test(raw))   return true;
  if (/\bmalware_action=/i.test(raw))   return true;
  if (/\bconfidence_level=/i.test(raw)) return true;
  // URL Filtering / App Control signals
  if (/\bappi_name=/i.test(raw))        return true;
  if (/\bapp_category=/i.test(raw))     return true;
  if (/\bmatched_category=/i.test(raw)) return true;
  if (/CEF:\d+\|Check Point\|/i.test(raw)) return true;
  if (/fw_message=/i.test(raw))         return true;
  if (/\[fw4_0\]/i.test(raw))           return true;
  return false;
}

function parseCheckPoint(raw, sourceIp) {
  try {
    if (!detectCheckPoint(raw)) return null;

    const cefMatch = raw.match(/CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s);

    let kv, product, eventName, logTimestamp = null;

    if (cefMatch) {
      const [, , , cefProduct, , cefAction, cefName, , extension] = cefMatch;
      kv        = parseKV(extension);
      product   = cefProduct;
      eventName = cefName;
      kv.action = kv.act || kv.action || cefAction;
    } else {
      const stripped = raw.replace(/^<\d{1,3}>/, '').trim();
      kv        = parseKV(stripped);
      product   = kv.product || null;
      eventName = kv.fw_message || kv.message || null;
    }

    // Timestamp / timezone — honor the log's own time, not the collector OS locale.
    // Check Point Log Exporter can carry either an epoch-seconds `time` field, or a
    // separate human date/time. If the device emits a UTC offset (e.g. tz="+0700"),
    // apply it; JS Date needs "+07:00" so normalize "+0700" -> "+07:00". Without a
    // tz we anchor to UTC ('Z') rather than silently inheriting the collector locale.
    if (logTimestamp == null) {
      const tzRaw = kv.tz || kv.time_zone || kv.timezone || null;
      let offset = 'Z';
      if (typeof tzRaw === 'string' && /^[+-]\d{4}$/.test(tzRaw)) {
        offset = `${tzRaw.slice(0, 3)}:${tzRaw.slice(3)}`;
      } else if (typeof tzRaw === 'string' && /^[+-]\d{2}:\d{2}$/.test(tzRaw)) {
        offset = tzRaw;
      }
      if (kv.date && kv.time && /[:]/.test(kv.time)) {
        const d = new Date(`${kv.date}T${kv.time}${offset}`);
        if (!isNaN(d.getTime())) logTimestamp = d;
      } else if (kv.time && /^\d{9,13}$/.test(kv.time)) {
        // Epoch seconds (10 digits) or milliseconds (13) — already absolute (UTC).
        const epoch = kv.time.length >= 13 ? parseInt(kv.time, 10) : parseInt(kv.time, 10) * 1000;
        const d = new Date(epoch);
        if (!isNaN(d.getTime())) logTimestamp = d;
      }
    }

    const rawAction = kv.action || kv.act || null;
    // Threat-prevention / IPS / Anti-* events: detect via threat fields regardless
    // of the parsed product string so category + the threat name are always captured.
    const protectionName = kv.protection_name || kv.malware_family || kv.attack || null;
    const isThreatEvent  = !!(protectionName || kv.protection_type || kv.malware_action ||
                              kv.confidence_level || kv.attack_info);
    // URL Filtering / App Control events
    const isWebEvent     = !!(kv.appi_name || kv.app_category || kv.matched_category ||
                              kv.resource || kv.url);

    // Category: product mapping first, then refine from event fields so a generic
    // "Firewall" product carrying threat/web fields is categorized correctly.
    let category = productToCategory(product);
    if (isThreatEvent && category !== 'dlp') category = 'security';
    else if (isWebEvent && (category === 'firewall' || category === 'network')) category = 'web';

    // Severity: Threat Prevention carries its own textual severity — map it
    // faithfully; otherwise fall back to action-based severity.
    const threatSevKey = String(kv.severity || '').toLowerCase();
    const sev = (isThreatEvent && CP_THREAT_SEV[threatSevKey])
      ? CP_THREAT_SEV[threatSevKey]
      : severityForAction(rawAction);

    const action    = normalizeAction(rawAction);
    const subcategory = authSubcategory(category, rawAction, kv, eventName);

    // Auth result/reason text — helps the message-regex fallback in correlation
    const authReason = kv.auth_status || kv.authentication_status || kv.fw_message || kv.reason || null;

    let message = 'Check Point';
    if (product)        message += ` ${product}`;
    if (rawAction)      message += `: ${rawAction}`;
    if (protectionName) message += ` [${protectionName}]`;
    if (kv.src && kv.dst) message += ` ${kv.src} -> ${kv.dst}`;
    if (kv.user)        message += ` user=${kv.user}`;
    if (kv.service || kv.dport) message += ` svc=${kv.service || kv.dport}`;
    const webResource = kv.resource || kv.url || kv.appi_name || null;
    if (webResource)    message += ` ${webResource}`;
    if (authReason)     message += ` | ${authReason}`;
    if (eventName && eventName !== authReason) message += ` | ${eventName}`;

    // Real source/destination IPs. In Check Point logs `src` is the REAL client/
    // source (never the gateway/sender), `dst` the destination. Some auth/Mobile
    // Access logs carry the client IP in `client_ip`/`endpoint_ip` instead — fall
    // back to those so srcip is the real remote user, not the gateway.
    const srcRaw = kv.src || kv.client_ip || kv.endpoint_ip || kv.xff || null;
    const dstRaw = kv.dst || null;

    // Source/destination ports. Check Point Log Exporter emits `s_port` for the
    // client port and `service` for the destination service; older/kernel logs use
    // `sport`/`dport`. Capture both the normalized `srcport`/`dstport` (contract)
    // and the legacy `src_port`/`dst_port`.
    const sPortRaw = kv.s_port || kv.sport || null;
    const dPortRaw = kv.dport || kv.d_port || null;
    const srcPort  = sPortRaw != null && /^\d+$/.test(String(sPortRaw)) ? parseInt(sPortRaw, 10) : null;
    const dstPort  = dPortRaw != null && /^\d+$/.test(String(dPortRaw)) ? parseInt(dPortRaw, 10) : null;

    const structured = {
      category,
      subcategory: subcategory || null,
      action,
      cp_action:   rawAction || null,
      product:     product || null,
      // --- Source / destination (contract) ---
      // srcip MUST be the validated REAL source IP, emitted under `srcip` (not just
      // `src_ip`) so correlation + UI key off it. Keep raw `src_ip`/`dst_ip` too.
      src_ip:      srcRaw || null,
      dst_ip:      dstRaw || null,
      srcip:       validIp(srcRaw),
      dstip:       validIp(dstRaw),
      srcport:     srcPort,
      dstport:     dstPort,
      src_port:    srcPort,                       // legacy alias
      dst_port:    dstPort,                       // legacy alias
      protocol:    kv.proto || kv.protocol || null,
      proto:       kv.proto || kv.protocol || null,
      service:     kv.service || null,
      // --- Rule / policy ---
      rule_name:   kv.rule_name || kv.rule || null,
      rule_uid:    kv.rule_uid || null,
      rule_number: kv.rule_uid || kv.rule_number || kv.rule || null,
      policy_name: kv.policy_name || null,
      // --- Identity / auth ---
      user:        kv.user || kv.src_user_name || kv.src_user || kv.endpoint_user || null,
      auth_status: kv.auth_status || kv.authentication_status || null,
      auth_method: kv.auth_method || null,
      // --- Interfaces / origin ---
      ifname:      kv.ifname || kv.interface || null,
      ifdir:       kv.ifdir || null,
      origin:      kv.origin || null,
      // --- Threat Prevention / IPS / Anti-Bot / Anti-Virus (security) ---
      // The threat NAME is the most important field — surface it generously.
      protection_name:  kv.protection_name || null,
      protection_type:  kv.protection_type || null,
      attack:           kv.attack || null,
      attack_info:      kv.attack_info || null,
      confidence_level: kv.confidence_level || null,
      malware_family:   kv.malware_family || null,
      malware_action:   kv.malware_action || null,
      threat_severity:  isThreatEvent ? (kv.severity || null) : null,  // textual CP severity (kept off numeric `severity`)
      smartdefense_profile: kv.smartdefense_profile || null,
      // --- URL Filtering / Application Control (web) ---
      resource:         kv.resource || kv.url || null,
      url:              kv.url || kv.resource || null,
      appi_name:        kv.appi_name || null,
      app_category:     kv.app_category || null,
      matched_category: kv.matched_category || null,
      app_risk:         kv.app_risk || kv.risk || null,
      web_client_type:  kv.web_client_type || null,
      reason:      kv.fw_message || kv.reason || eventName || null,
    };

    // Strip null/undefined keys
    Object.keys(structured).forEach(k => (structured[k] == null) && delete structured[k]);

    return {
      source_ip:       sourceIp,
      source_host:     kv.origin || null,
      facility:        23,
      facility_label:  'local7',
      severity:        sev.severity,
      severity_label:  sev.label,
      vendor:          'checkpoint',
      program:         product ? `CheckPoint/${product}` : 'CheckPoint',
      message,
      raw_message:     raw,
      structured_data: structured,
      is_parsed:       true,
      log_timestamp:   logTimestamp,
      parser_version:  'checkpoint-v1.1',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseCheckPoint, detectCheckPoint };
