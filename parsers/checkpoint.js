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

// Map Check Point product → standard category
function productToCategory(product) {
  const p = (product || '').toLowerCase();
  if (p.includes('vpn-1') || p.includes('vpn'))            return 'vpn';
  if (p.includes('mobile access') || p.includes('mobile')) return 'vpn';
  if (p.includes('smartdefense') || p.includes('ips'))     return 'security';
  if (p.includes('application control') || p.includes('app')) return 'application';
  if (p.includes('identity awareness') || p.includes('identity')) return 'authentication';
  if (p.includes('firewall-1') || p.includes('firewall'))  return 'firewall';
  return 'firewall';
}

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
  // Check Point auth/VPN products (Mobile Access, VPN, Identity Awareness)
  if (/product=(?:"?\s*)?(?:Mobile Access|VPN|Identity Awareness)\b/i.test(raw)) return true;
  if (/\bauth_status=/i.test(raw))      return true;
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
      if (kv.date && kv.time) {
        const d = new Date(`${kv.date}T${kv.time}`);
        if (!isNaN(d.getTime())) logTimestamp = d;
      }
    }

    const rawAction = kv.action || kv.act || null;
    const sev       = severityForAction(rawAction);
    const action    = normalizeAction(rawAction);
    const category  = productToCategory(product);
    const subcategory = authSubcategory(category, rawAction, kv, eventName);

    // Auth result/reason text — helps the message-regex fallback in correlation
    const authReason = kv.auth_status || kv.authentication_status || kv.fw_message || kv.reason || null;

    let message = 'Check Point';
    if (product)        message += ` ${product}`;
    if (rawAction)      message += `: ${rawAction}`;
    if (kv.src && kv.dst) message += ` ${kv.src} -> ${kv.dst}`;
    if (kv.user)        message += ` user=${kv.user}`;
    if (kv.service || kv.dport) message += ` svc=${kv.service || kv.dport}`;
    if (authReason)     message += ` | ${authReason}`;
    if (eventName && eventName !== authReason) message += ` | ${eventName}`;

    const structured = {
      category,
      subcategory: subcategory || null,
      action,
      cp_action:   rawAction || null,
      product:     product || null,
      src_ip:      kv.src || null,
      dst_ip:      kv.dst || null,
      srcip:       validIp(kv.src),
      dstip:       validIp(kv.dst),
      src_port:    kv.sport ? parseInt(kv.sport) : null,
      dst_port:    kv.dport ? parseInt(kv.dport) : null,
      protocol:    kv.proto || null,
      service:     kv.service || null,
      rule_name:   kv.rule_name || kv.rule || null,
      rule_number: kv.rule_uid || kv.rule_number || null,
      user:        kv.user || kv.src_user_name || null,
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
      parser_version:  'checkpoint-v1.0',
    };
  } catch (_) {
    return null;
  }
}

module.exports = { parseCheckPoint, detectCheckPoint };
