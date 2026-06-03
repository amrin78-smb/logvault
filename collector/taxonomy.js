'use strict';

/**
 * Universal Event Taxonomy — vendor-aware.
 *
 * Assigns a standard `category` to every parsed log entry so the UI, filters,
 * alerting and risk scoring can reason about events consistently across all
 * supported vendors.
 *
 * Standard categories (the ONLY values this function may return):
 *   authentication, vpn, firewall, interface, routing, configuration,
 *   security, wireless, system, dns, web, email, dlp, network
 *
 * Resolution order:
 *   1. Parser-provided category (normalized) — highest priority, EXCEPT the
 *      generic 'network' fallback, which is treated as "unknown" so it can be
 *      refined by the vendor/message logic below.
 *   2. Vendor + structured_data detection (uses the real fields each parser emits).
 *   3. Message-regex detection (fallback).
 *   4. Final fallback → 'network'.
 */

const STANDARD = new Set([
  'authentication', 'vpn', 'firewall', 'interface', 'routing', 'configuration',
  'security', 'wireless', 'system', 'dns', 'web', 'email', 'dlp', 'network',
]);

// Non-standard / parser-specific values → standard category
const NORMALIZE = {
  loop:         'interface',
  stp:          'interface',
  'stp/loop':   'interface',
  config:       'configuration',
  traffic:      'firewall',
  general:      'network',
  utm:          'security',
  'app-ctrl':   'security',
  appctrl:      'security',
  application:  'web',          // Check Point Application Control
  webfilter:    'web',
  antivirus:    'security',
  av:           'security',
  ips:          'security',
  ids:          'security',
  dlp:          'dlp',
  voip:         'network',
  anomaly:      'security',
  netscan:      'security',
  proxy:        'web',          // Forcepoint Web proxy
};

// Normalize a parser-provided category to a standard value, or null if unknown.
function normalizeCategory(cat) {
  if (!cat) return null;
  const c = String(cat).toLowerCase().trim();
  if (NORMALIZE[c]) return NORMALIZE[c];
  if (STANDARD.has(c)) return c;
  return null;
}

// ── 2. Vendor + structured_data detection ────────────────────────
function byVendor(vendor, s, msg) {
  switch (vendor) {

    case 'fortinet': {
      const type   = (s.type    || '').toLowerCase();
      const sub    = (s.subtype || '').toLowerCase();
      const action = (s.action  || '').toLowerCase();
      if (type === 'utm') {
        if (sub === 'webfilter') return 'web';
        if (sub === 'dlp')       return 'dlp';
        return 'security';                                  // ips, av, antivirus, app-ctrl, anomaly, ...
      }
      if (type === 'event') {
        if (sub === 'user')     return 'authentication';
        if (sub === 'system')   return 'system';
        if (sub === 'router')   return 'routing';
        if (sub === 'wireless') return 'wireless';
        if (sub === 'vpn')      return 'vpn';
        if (sub === 'ha')       return 'system';
        if (sub === 'config')   return 'configuration';
        return 'system';                                    // generic management event
      }
      if (type === 'traffic') return 'firewall';
      if (['ssl-new-con', 'ssl-exit-error', 'tunnel-up', 'tunnel-down'].includes(action)) return 'vpn';
      if (s.tunnel_type) return 'vpn';
      if (String(s.service || '').toLowerCase() === 'dns' || String(s.dstport) === '53') return 'dns';
      if (action) return 'firewall';
      return null;
    }

    case 'cisco': {
      const tok = `${(s.ios_facility || '').toUpperCase()} ${(s.mnemonic || '').toUpperCase()}`;
      if (/LOGIN|LOGOUT|AUTH|SEC_LOGIN|AAA|AUTHPRIV/.test(tok)) return 'authentication';
      if (/CRYPTO|ISAKMP|IPSEC|\bVPN\b/.test(tok))              return 'vpn';
      if (/IDS|IPS|INSPECT/.test(tok))                          return 'security';
      if (/DOT11|CAPWAP|WLAN/.test(tok))                        return 'wireless';
      if (/OSPF|BGP|RIP|EIGRP|DUAL/.test(tok))                  return 'routing';
      if (/STP|SPANTREE|SPANNING/.test(tok))                    return 'interface';
      if (/LINK|UPDOWN|LINEPROTO/.test(tok))                    return 'interface';
      if (/CONFIG/.test(tok))                                   return 'configuration';
      if (/SYS|RELOAD|RESTART/.test(tok))                       return 'system';
      return null;
    }

    case 'paloalto': {
      const lt = (s.log_type || '').toUpperCase();
      const st = (s.subtype  || '').toLowerCase();
      if (lt === 'TRAFFIC')       return 'firewall';
      if (lt === 'THREAT')        return st === 'url' ? 'web' : 'security';
      if (lt === 'CONFIG')        return 'configuration';
      if (lt === 'SYSTEM')        return 'system';
      if (lt === 'HIPMATCH')      return 'security';
      if (lt === 'GLOBALPROTECT') return 'vpn';
      if (lt === 'AUTHENTICATION' || lt === 'USERID') return 'authentication';
      return null;
    }

    case 'aruba': {
      const prog = (s.program || '').toLowerCase();
      if (/authmgr|certmgr|localdb|radius|eap|dot1x/.test(prog)) return 'authentication';
      if (/sapd|stm|wms|mdns|nbapi|airwave/.test(prog))         return 'wireless';
      if (/802\.1x|\beap\b|radius|authentication/i.test(msg))   return 'authentication';
      if (/\bvpn\b|ipsec/i.test(msg))                           return 'vpn';
      if (/\bids\b|wids|attack/i.test(msg))                     return 'security';
      if (/ssid|wireless|wlan|associat|deauth|station/i.test(msg)) return 'wireless';
      return null;
    }

    case 'juniper': {
      const et = (s.event_type || '').toUpperCase();
      if (et === 'RT_IDP' || /IDP|IDS|IPS|ATTACK/.test(et)) return 'security';
      if (et.startsWith('RT_FLOW') || /FLOW/.test(et))      return 'firewall';
      if (/LINK/.test(et))                                  return 'interface';
      if (/BGP|OSPF|RIP/.test(et))                          return 'routing';
      if (/AUTH|LOGIN/.test(et))                            return 'authentication';
      return null;
    }

    case 'checkpoint': {
      const p = (s.product || '').toLowerCase();
      if (/vpn/.test(p))                       return 'vpn';
      if (/identity/.test(p))                  return 'authentication';
      if (/application/.test(p))               return 'web';
      if (/smartdefense|ips|threat|anti/.test(p)) return 'security';
      if (/firewall/.test(p))                  return 'firewall';
      return null;
    }

    case 'forcepoint': {
      const p = (s.product || '').toLowerCase();
      if (/email/.test(p))        return 'email';
      if (/dlp/.test(p))          return 'dlp';
      if (/web|proxy/.test(p))    return 'web';
      if (/ngfw|firewall/.test(p)) return 'firewall';
      return null;
    }

    case 'windows': {
      const id = parseInt(s.event_id, 10);
      const ch = (s.channel || '').toLowerCase();
      const AUTH = new Set([4624, 4625, 4634, 4648, 4672, 4720, 4722, 4724, 4728, 4732, 4740, 4756]);
      const SYS  = new Set([7034, 7036, 7045]);
      const CFG  = new Set([4698, 4700]);
      if (CFG.has(id))  return 'configuration';
      if (AUTH.has(id)) return 'authentication';
      if (SYS.has(id))  return 'system';
      if (ch === 'security')    return 'authentication';
      if (ch === 'system')      return 'system';
      if (ch === 'application') return 'system';
      return null;
    }

    case 'sonicwall':
      return 'firewall';                                   // SonicWall only sends firewall logs

    case 'sangfor': {
      const tok = `${(s.event_name || '').toLowerCase()} ${msg.toLowerCase()}`;
      if (/\bvpn\b|ipsec|ssl.?vpn|tunnel/.test(tok))            return 'vpn';
      if (/auth|login|logon/.test(tok))                        return 'authentication';
      if (/attack|threat|intrusion|malware|virus|\bips\b|\bids\b/.test(tok)) return 'security';
      return 'firewall';                                       // Sangfor default
    }

    default:
      return null;
  }
}

// ── 3. Message-regex detection (most specific first) ─────────────
const MSG_RULES = [
  ['authentication', /login.fail|auth.fail|logon.fail|wrong.password|bad.password|authentication.failure|account.lock|failed.*login|login.*failed|user.*authenticated|logdesc=.*(auth|login|logout)|action=(login|logout)|tunnel-up.*user|vpn.*user.*connect/i],
  ['vpn',            /\bvpn\b|ssl-vpn|ipsec|ikev[12]|phase[- ]?[12]|tunnel.?(up|down|establish)|dialup|l2tp|pptp|ssl.new.con|ssl.exit/i],
  ['security',       /\bips\b|\bids\b|intrusion|threat|malware|exploit|attack|signature|anomaly|\butm\b|\bav\b|antivirus|ransomware|trojan|botnet|webfilter.*block|app.ctrl|netscan/i],
  ['interface',      /link.?(up|down)|interface.?(up|down)|port.?(up|down)|line.protocol|flap|stp|spanning.tree|lag|lacp|\bRT_LINK\b|\bLINK_DOWN\b|\bLINK_UP\b/i],
  ['routing',        /\bbgp\b|\bospf\b|\brip\b|\beigrp\b|neighbor.?(up|down)|adjacency|route.?(add|delete|change)|prefix|redistribute/i],
  ['configuration',  /config.*change|configured.*from|admin.*login|logdesc=.*config|policy.*change|firmware|upgrade|backup|restore|system.*event.*admin/i],
  ['dns',            /\bdns\b|domain.name|nxdomain|\bptr\b|dns.query|dns.fail|resolve.*fail|svc=dns|dstport=53|service=DNS/i],
  ['web',            /\bhttp\b|\bhttps\b|\burl\b|web.*filter|proxy|browse|get.request|post.request|response.code/i],
  ['wireless',       /wifi|wireless|\bssid\b|802\.1[x1]|\bwpa\b|\beap\b|ap.client|associate|deassociate|station/i],
  ['system',         /reboot|restart|shutdown|high.cpu|memory.full|disk.full|temperature|power|service.crash|daemon|process.exit|kernel/i],
  ['email',          /\bsmtp\b|\bmail\b|quarantine.*mail|email.*block|sender|recipient|subject.*mail/i],
  ['dlp',            /\bdlp\b|data.loss|data.leak|sensitive.*data|policy.violation.*data/i],
];

const FIREWALL_ACTIONS = new Set(['blocked', 'allowed', 'deny', 'accept', 'drop', 'pass']);

function byMessage(message, s) {
  for (const [cat, re] of MSG_RULES) {
    if (re.test(message)) return cat;
  }
  if (FIREWALL_ACTIONS.has(String(s.action || '').toLowerCase())) return 'firewall';
  return null;
}

// ── Public entry point ───────────────────────────────────────────
function getCategory(vendor, structured, message) {
  const s   = structured || {};
  const v   = (vendor  || '').toLowerCase();
  const msg = message || '';

  // 1. Parser-provided category (normalized). 'network' is non-authoritative.
  const norm = normalizeCategory(s.category);
  if (norm && norm !== 'network') return norm;

  // 2. Vendor + structured detection
  const vc = byVendor(v, s, msg);
  if (vc) return vc;

  // 3. Message-regex detection
  const mc = byMessage(msg, s);
  if (mc) return mc;

  // 4. Final fallback
  return 'network';
}

module.exports = { getCategory };
