/**
 * Cisco Syslog Parser (multi-product: IOS / IOS-XE, ASA, FTD/FirePOWER, ISE, AnyConnect, WLC)
 *
 * Cisco devices share the %FACILITY-SEVERITY-MNEMONIC: message shape, but the
 * payload differs sharply per product:
 *   - IOS / IOS-XE  : interface/STP/routing/config + %SEC_LOGIN auth
 *   - ASA / FTD     : %ASA-/%FTD- AAA auth (113xxx), VPN/AnyConnect (722xxx),
 *                     connection build/teardown (302xxx), ACL denies (106xxx)
 *   - ISE / RADIUS  : CISE_* / RADIUS passed/failed authentications
 *   - WLC           : DOT11 / CAPWAP wireless association events
 *
 * Normalized contract (downstream correlation / UI / CSV depend on these EXACT
 * structured_data keys): srcip (the REAL remote client/source IP — NEVER the
 * syslog sender/relay), dstip, srcport, dstport, user, subcategory
 * ('login_failed'|'login_success'|'auth_failed' on auth events), action; plus a
 * correct top-level `category` (authentication/vpn/security/firewall/system/
 * network/...). All additions are capture-when-present and null-stripped, so
 * existing IOS interface/STP/routing parsing is unchanged.
 */

'use strict';

const FACILITY_LABELS = ['kern','user','mail','daemon','auth','syslog','lpr','news',
  'uucp','cron','authpriv','ftp','ntp','audit','alert2','clock',
  'local0','local1','local2','local3','local4','local5','local6','local7'];

const IOS_SEV_MAP = { 0:'emergency',1:'alert',2:'critical',3:'error',4:'warning',5:'notice',6:'info',7:'debug' };

// Mnemonic may contain hyphens AND mixed case on some products (e.g. ISE
// "Passed-Authentication"), so the mnemonic group allows both; the facility
// (uppercase) + single-digit severity + colon anchor keep it precise.
const CISCO_MNEMONIC_RE = /%([A-Z0-9_\-]+)-(\d)-([A-Za-z0-9_\-]+):/;
const CISCO_FULL_RE     = /^<(\d{1,3})>\*?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?(?:\s+\w+)?):\s+(%[A-Z0-9_\-]+-\d-[A-Za-z0-9_\-]+:.*)/s;

const EVENT_PATTERNS = [
  // ── Auth / VPN classification (most specific first) ──────────────
  // IOS interactive login (SSH/console/telnet) — normalized to authentication
  { pattern: /SEC_LOGIN.*LOGIN_FAILED/,  category: 'authentication', subcategory: 'login_failed' },
  { pattern: /SEC_LOGIN.*QUIET_MODE/,    category: 'authentication', subcategory: 'login_failed' },
  { pattern: /SEC_LOGIN.*LOGIN_SUCCESS/, category: 'authentication', subcategory: 'login_success' },
  // ASA/FTD AnyConnect & remote-access VPN auth → vpn
  { pattern: /%(?:ASA|FTD)-\d-722037/,   category: 'vpn',            subcategory: 'login_failed' },  // SVC closing conn / terminated
  { pattern: /%(?:ASA|FTD)-\d-722023/,   category: 'vpn',            subcategory: 'login_failed' },  // SVC terminated
  { pattern: /%(?:ASA|FTD)-\d-113019/,   category: 'vpn',            subcategory: 'login_failed' },  // Group/Username disconnected (session end)
  // ASA/FTD AnyConnect successful tunnel / session establishment → vpn success
  { pattern: /%(?:ASA|FTD)-\d-722022/,   category: 'vpn',            subcategory: 'login_success' },  // SVC connection established
  { pattern: /%(?:ASA|FTD)-\d-716001/,   category: 'vpn',            subcategory: 'login_success' },  // WebVPN session started
  { pattern: /%(?:ASA|FTD)-\d-716002/,   category: 'vpn',            subcategory: 'login_failed'  },  // WebVPN session terminated
  // ASA/FTD AAA auth (113004 success, 113005/113015 rejected, 113021 restricted)
  { pattern: /%(?:ASA|FTD)-\d-113004/,   category: 'authentication', subcategory: 'login_success' },
  { pattern: /%(?:ASA|FTD)-\d-113005/,   category: 'authentication', subcategory: 'login_failed' },
  { pattern: /%(?:ASA|FTD)-\d-113015/,   category: 'authentication', subcategory: 'login_failed' },
  { pattern: /%(?:ASA|FTD)-\d-113021/,   category: 'authentication', subcategory: 'login_failed' },
  // ── ASA/FTD threat / IPS / FirePOWER (before generic firewall) ───
  { pattern: /%(?:ASA|FTD)-\d-4000\d\d/, category: 'security',  subcategory: 'ips_signature' }, // 4000xx IPS signature
  { pattern: /%FTD-\d-430\d\d\d/,        category: 'security',  subcategory: 'intrusion' },     // FTD 430xxx Snort/IPS/file events
  { pattern: /%(?:ASA|FTD)-\d-733100/,   category: 'security',  subcategory: 'threat_detection' }, // threat-detection rate exceeded
  // ── ASA/FTD connection build/teardown (traffic) → firewall ───────
  { pattern: /%(?:ASA|FTD)-\d-302013/,   category: 'firewall',  subcategory: 'connection_built' },     // TCP built
  { pattern: /%(?:ASA|FTD)-\d-302015/,   category: 'firewall',  subcategory: 'connection_built' },     // UDP built
  { pattern: /%(?:ASA|FTD)-\d-302020/,   category: 'firewall',  subcategory: 'connection_built' },     // ICMP built
  { pattern: /%(?:ASA|FTD)-\d-302014/,   category: 'firewall',  subcategory: 'connection_teardown' },  // TCP teardown
  { pattern: /%(?:ASA|FTD)-\d-302016/,   category: 'firewall',  subcategory: 'connection_teardown' },  // UDP teardown
  { pattern: /%(?:ASA|FTD)-\d-302021/,   category: 'firewall',  subcategory: 'connection_teardown' },  // ICMP teardown
  // ── ASA/FTD deny (106xxx) → firewall deny ────────────────────────
  { pattern: /%(?:ASA|FTD)-\d-106023/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // denied by ACL
  { pattern: /%(?:ASA|FTD)-\d-106001/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // inbound TCP denied
  { pattern: /%(?:ASA|FTD)-\d-106006/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // inbound UDP denied (no rule)
  { pattern: /%(?:ASA|FTD)-\d-106007/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // inbound UDP denied (DNS)
  { pattern: /%(?:ASA|FTD)-\d-106010/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // inbound denied
  { pattern: /%(?:ASA|FTD)-\d-106014/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // denied ICMP
  { pattern: /%(?:ASA|FTD)-\d-106015/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // denied TCP (no conn)
  { pattern: /%(?:ASA|FTD)-\d-106021/,   category: 'firewall',  subcategory: 'denied', action: 'deny' }, // reverse-path denied
  { pattern: /%(?:ASA|FTD)-\d-1060\d\d/, category: 'firewall',  subcategory: 'denied', action: 'deny' }, // any other 106xxx deny
  // ── ISE / RADIUS auth (CISE prefix or explicit RADIUS auth mnemonics) ──
  { pattern: /(?:CISE|RADIUS).*(?:Authentication failed|Auth failed|RADIUS-Reject|5400|5440|24408|22056)/i, category: 'authentication', subcategory: 'login_failed' },
  { pattern: /(?:CISE|RADIUS).*(?:Authentication succeeded|Auth succeeded|Passed-Authentication|5200|5205)/i, category: 'authentication', subcategory: 'login_success' },
  // ── Non-auth events (unchanged) ──────────────────────────────────
  { pattern: /LINK-\d-UPDOWN/,           category: 'interface', subcategory: 'link_change' },
  { pattern: /LINEPROTO-\d-UPDOWN/,      category: 'interface', subcategory: 'protocol_change' },
  { pattern: /SPANTREE.*TOPOTRAP/,       category: 'stp',       subcategory: 'topology_change' },
  { pattern: /SPANTREE.*ROOTCHANGE/,     category: 'stp',       subcategory: 'root_change' },
  { pattern: /SPANTREE.*CHNMISCFG/,      category: 'stp',       subcategory: 'loop_detected' },
  { pattern: /SPANTREE.*PORTDEL/,        category: 'stp',       subcategory: 'port_removed' },
  { pattern: /STP.*INTERFACE_ROLE/,      category: 'stp',       subcategory: 'role_change' },
  { pattern: /STP-\d-BLOCK/,            category: 'stp',       subcategory: 'port_blocked' },
  { pattern: /SW_MATM.*MACFLAP/,         category: 'loop',      subcategory: 'mac_flap' },
  { pattern: /MACFLAP_NOTIF/,            category: 'loop',      subcategory: 'mac_flap' },
  { pattern: /STORM_CONTROL.*FILTERED/,  category: 'loop',      subcategory: 'storm_control' },
  { pattern: /STORM_CONTROL.*SHUTDOWN/,  category: 'loop',      subcategory: 'storm_shutdown' },
  // ── Wireless (WLC / autonomous AP) ───────────────────────────────
  { pattern: /DOT11-\d-(?:ASSOC|DISASSOC|DEAUTH)/, category: 'wireless', subcategory: 'station_event' },
  { pattern: /DOT11-\d-MAXRETRIES/,      category: 'wireless', subcategory: 'station_event' },
  { pattern: /CAPWAP-\d-/,               category: 'wireless', subcategory: 'ap_event' },
  { pattern: /LWAPP-\d-/,                category: 'wireless', subcategory: 'ap_event' },
  { pattern: /AAA.*AUTHEN_FAIL/,         category: 'authentication', subcategory: 'login_failed' },
  { pattern: /SYS-\d-CONFIG_I/,          category: 'config',    subcategory: 'config_change' },
  { pattern: /SYS-\d-LOGOUT/,            category: 'config',    subcategory: 'logout' },
  { pattern: /OSPF.*ADJCHG/,             category: 'routing',   subcategory: 'ospf_neighbor' },
  { pattern: /BGP.*ADJCHANGE/,           category: 'routing',   subcategory: 'bgp_neighbor' },
  { pattern: /DUAL-\d-NBRCHANGE/,        category: 'routing',   subcategory: 'eigrp_neighbor' },
];

function classifyEvent(mnemonicFull, message) {
  const s = `${mnemonicFull} ${message}`;
  for (const p of EVENT_PATTERNS) {
    if (p.pattern.test(s)) return { category: p.category, subcategory: p.subcategory, action: p.action || null };
  }
  return { category: 'general', subcategory: 'general', action: null };
}

function extractInterface(message) {
  const m = message.match(/(?:Interface|interface|port)\s+([\w\/\.]+)/i)
         || message.match(/(GigabitEthernet[\w\/\.]+)/i)
         || message.match(/(FastEthernet[\w\/\.]+)/i)
         || message.match(/(TenGigabitEthernet[\w\/\.]+)/i)
         || message.match(/(Ethernet[\w\/\.]+)/i)
         || message.match(/(Vlan[\w\/\.]+)/i)
         || message.match(/(Po[\d]+)/i);
  return m ? m[1] : null;
}

function extractMAC(message) {
  const m = message.match(/([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/i)
         || message.match(/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i);
  return m ? m[1] : null;
}

// ── Auth / VPN field extraction ──────────────────────────────────
// Validate a dotted-quad IPv4 (each octet 0-255). Defensive: rejects
// things like 999.1.1.1 or version strings.
function isValidIPv4(ip) {
  if (!ip) return false;
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function firstValidIP(message, regexes) {
  for (const re of regexes) {
    const m = message.match(re);
    if (m && m[1] && isValidIPv4(m[1])) return m[1];
  }
  return null;
}

// Extract the REAL client/source IP from Cisco auth/VPN logs.
// NOT the syslog sender — the remote user/attacker IP.
function extractSrcIp(message) {
  return firstValidIP(message, [
    /\[Source:\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\]/i,   // IOS %SEC_LOGIN [Source: x]
    /\buser\s*IP\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/i,   // ASA 113015 "user IP ="
    /\bClient\s*(?:outside\s*)?IP\s*=?\s*(\d{1,3}(?:\.\d{1,3}){3})/i, // AnyConnect "Client IP ="
    /\bIP\s*<(\d{1,3}(?:\.\d{1,3}){3})>/i,            // ASA 722xxx "IP <x>"
    /\bIP\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/i,          // ASA VPN 113019 "IP ="
    /\bCalling-Station-ID[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i, // ISE/RADIUS
    /\bEndpoint\s*IP[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i,      // ISE
    /\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/i,            // generic "from <ip>" auth blobs
  ]);
}

// Extract a destination IP when present (e.g. ASA AAA "server = x").
function extractDstIp(message) {
  return firstValidIP(message, [
    /\bserver\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/i,      // ASA AAA "server ="
    /\bDestination\s*IP[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i,
    /\bNAS-IP-Address[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i, // ISE/RADIUS
  ]);
}

// Extract the username/account from Cisco auth/VPN logs.
function extractUser(message) {
  const res = [
    /\[user:\s*([^\]]+?)\s*\]/i,                  // IOS %SEC_LOGIN [user: x]
    /\bUser\s*<([^>]+)>/i,                         // ASA 722xxx "User <x>"
    /\bUsername\s*=\s*"?([^",\s]+)"?/i,           // ASA VPN 113019 "Username ="
    /\buser\s*=\s*"?([^",\s]+)"?/i,               // ASA AAA "user ="
    /\bUser-Name[=:\s]+"?([^",\s]+)"?/i,          // ISE/RADIUS "User-Name"
  ];
  for (const re of res) {
    const m = message.match(re);
    if (m && m[1]) {
      const u = m[1].trim();
      // Guard against placeholder/empty values
      if (u && u !== '*****' && u.toLowerCase() !== 'unknown') return u;
    }
  }
  return null;
}

// Extract the VPN/RADIUS group/tunnel-group when present (security-relevant).
function extractGroup(message) {
  const m = message.match(/\bGroup\s*<([^>]+)>/i)                          // ASA 722xxx "Group <x>"
         || message.match(/\bGroup\s*=\s*"?([^",\]]+?)"?(?:\s*[,\]]|\s{2,}|$)/i)
         || message.match(/\bGroup-Name\s*=\s*"?([^",\]]+?)"?(?:\s*[,\]]|$)/i)
         || message.match(/\btunnel-group\s*[=:]\s*"?([^",\s]+)"?/i);
  if (m && m[1]) { const g = m[1].trim(); if (g) return g; }
  return null;
}

// ── ASA connection / deny traffic extraction ─────────────────────
// ASA 302013/302014: "Built/Teardown {inbound|outbound} TCP connection 12345
//   for outside:203.0.113.5/443 (203.0.113.5/443) to inside:10.0.0.10/52345 ..."
// ASA 106023:        "Deny tcp src outside:203.0.113.9/40213 dst inside:10.0.0.5/3389 by access-group ..."
// Returns { srcip, srcport, dstip, dstport, proto } (each null when absent).
function extractTraffic(message) {
  const out = { srcip: null, srcport: null, dstip: null, dstport: null, proto: null };

  // Protocol (tcp/udp/icmp) — appears right after Built/Teardown/Deny.
  const protoM = message.match(/\b(?:Built|Teardown|Deny|Denied)\s+(?:inbound\s+|outbound\s+)?(tcp|udp|icmp|gre|esp|ah|sctp|ip)\b/i)
              || message.match(/\bprotocol\s+(tcp|udp|icmp)\b/i);
  if (protoM) out.proto = protoM[1].toLowerCase();

  // 106xxx deny form: "src <zone>:<ip>/<port> dst <zone>:<ip>/<port>"
  const denySrc = message.match(/\bsrc\s+[\w\-]+:(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,5}))?/i);
  const denyDst = message.match(/\bdst\s+[\w\-]+:(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,5}))?/i);
  if (denySrc && isValidIPv4(denySrc[1])) { out.srcip = denySrc[1]; if (denySrc[2]) out.srcport = denySrc[2]; }
  if (denyDst && isValidIPv4(denyDst[1])) { out.dstip = denyDst[1]; if (denyDst[2]) out.dstport = denyDst[2]; }

  // 302xxx build/teardown form: "for <zone>:<ip>/<port> ... to <zone>:<ip>/<port>"
  // In ASA, "for <faddr>" is the foreign/source side and "to <laddr>" the local/dest side.
  if (!out.srcip || !out.dstip) {
    const forM = message.match(/\bfor\s+[\w\-]+:(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,5})/i);
    const toM  = message.match(/\bto\s+[\w\-]+:(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,5})/i);
    if (forM && isValidIPv4(forM[1]) && !out.srcip) { out.srcip = forM[1]; out.srcport = forM[2]; }
    if (toM  && isValidIPv4(toM[1])  && !out.dstip) { out.dstip = toM[1];  out.dstport = toM[2]; }
  }

  return out;
}

// ── Threat / IPS signature extraction (FTD/FirePOWER/ASA IPS) ─────
function extractThreat(message) {
  const out = { signature: null, signature_id: null, threat: null };
  // ASA IPS 4000xx: "IPS:2000 ICMP Echo Request from 1.2.3.4 to 5.6.7.8 ..."
  const sigId = message.match(/\bSigID[:\s=]+(\d+)/i)
             || message.match(/\bIPS:(\d+)\b/i)
             || message.match(/\b(?:signature|sig)\s*id[:\s=]+(\d+)/i)
             || message.match(/\[\s*\d+:(\d+):\d+\s*\]/);  // Snort GID:SID:rev
  if (sigId) out.signature_id = sigId[1];
  // Signature / rule name — FTD Snort messages: "[**] [1:2010935:3] ET POLICY ... [**]"
  const sigName = message.match(/\]\s*([^\[]+?)\s*\[\*\*\]/)        // Snort "[**] ... msg ... [**]"
               || message.match(/\bSignature[:\s=]+"?([^",\]]+?)"?(?:\s*[,\]]|$)/i);
  if (sigName && sigName[1]) { const n = sigName[1].trim(); if (n) out.signature = n; }
  // Threat / malware name (file/malware events)
  const threat = message.match(/\b(?:ThreatName|Threat|Malware)[:\s=]+"?([^",\]]+?)"?(?:\s*[,\]]|$)/i);
  if (threat && threat[1]) { const t = threat[1].trim(); if (t) out.threat = t; }
  return out;
}

// ── Fix: Handle New Year rollover in Cisco timestamps ─────────
// Cisco IOS/ASA syslog timestamps (e.g. "Jun 20 10:23:01") carry NO year and
// usually no timezone. We assume the COLLECTOR's wall-clock year and treat the
// time as the collector's local time (Cisco can be configured for `service
// timestamps log datetime` with a zone, but the common case has none). If a
// trailing zone token is present in fullMatch[2] (e.g. "Jun 20 10:23:01.123 UTC")
// JS Date will honor it; otherwise local time is used. The only correction made
// is the New-Year rollover below — a Dec log seen in early Jan belongs to the
// previous year.
function parseCiscoTimestamp(dateStr) {
  if (!dateStr) return null;
  try {
    const now   = new Date();
    const year  = now.getFullYear();
    const parsed = new Date(`${dateStr.trim()} ${year}`);
    if (isNaN(parsed.getTime())) return null;
    // If the parsed date is more than 1 day in the future, it's from last year
    if (parsed.getTime() > now.getTime() + 86400000) {
      return new Date(`${dateStr.trim()} ${year - 1}`);
    }
    return parsed;
  } catch (_) { return null; }
}

function parseCisco(raw, sourceIp) {
  if (!CISCO_MNEMONIC_RE.test(raw)) return null;

  const mnemonicMatch = CISCO_MNEMONIC_RE.exec(raw);
  if (!mnemonicMatch) return null;

  const fullMatch    = CISCO_FULL_RE.exec(raw);
  const iosFacility  = mnemonicMatch[1];
  const iosSeverity  = parseInt(mnemonicMatch[2], 10);
  const mnemonic     = mnemonicMatch[3];
  const mnemonicFull = mnemonicMatch[0];

  const msgStart = raw.indexOf(mnemonicFull) + mnemonicFull.length;
  const message  = raw.slice(msgStart).trim();

  // Cisco's %FACILITY-SEVERITY-MNEMONIC severity digit (0-7) is authoritative.
  const severity      = iosSeverity <= 7 ? iosSeverity : 6;
  const severityLabel = IOS_SEV_MAP[severity] || 'info';

  let facility      = 23;
  let facilityLabel = 'local7';
  if (fullMatch) {
    const pri = parseInt(fullMatch[1], 10);
    facility      = Math.floor(pri / 8);
    facilityLabel = FACILITY_LABELS[facility] || 'local7';
  }

  const logTimestamp = fullMatch ? parseCiscoTimestamp(fullMatch[2]) : null;
  const cls = classifyEvent(mnemonicFull, message);
  const category = cls.category;
  const subcategory = cls.subcategory;
  // Interface/MAC only matter for L2/L3 device events — skip on auth/vpn/firewall/
  // security logs so phrases like "connection: Transport closing" don't yield a
  // bogus interface. (Additive: IOS interface/STP/routing parsing is unchanged.)
  const isL2L3 = !(category === 'authentication' || category === 'vpn' ||
                   category === 'firewall' || category === 'security');
  const iface    = isL2L3 ? extractInterface(message) : null;
  const mac      = isL2L3 ? extractMAC(message) : null;

  let linkState = null;
  if (subcategory === 'link_change' || subcategory === 'protocol_change') {
    if (/changed state to up|line protocol.*up/i.test(message))     linkState = 'up';
    if (/changed state to down|line protocol.*down/i.test(message)) linkState = 'down';
  }

  // ── Contract field extraction, scoped by classified category ─────
  // (so non-auth/non-traffic logs never pick up stray IPs/users).
  let srcip = null, dstip = null, srcport = null, dstport = null;
  let user = null, group = null, action = cls.action;
  let proto = null, signature = null, signature_id = null, threat = null;

  if (category === 'authentication' || category === 'vpn') {
    srcip = extractSrcIp(message);
    dstip = extractDstIp(message);
    user  = extractUser(message);
    group = extractGroup(message);
  } else if (category === 'firewall') {
    const t = extractTraffic(message);
    srcip = t.srcip; dstip = t.dstip; srcport = t.srcport; dstport = t.dstport; proto = t.proto;
    // Build/teardown have no deny action; only the deny patterns set action='deny'.
  } else if (category === 'security') {
    const th = extractThreat(message);
    signature = th.signature; signature_id = th.signature_id; threat = th.threat;
    // Security events frequently carry attacker/source + victim IPs ("from x to y").
    srcip = firstValidIP(message, [/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})/i, /\bsrc\s+[\w\-]*:?(\d{1,3}(?:\.\d{1,3}){3})/i]);
    dstip = firstValidIP(message, [/\bto\s+(\d{1,3}(?:\.\d{1,3}){3})/i,   /\bdst\s+[\w\-]*:?(\d{1,3}(?:\.\d{1,3}){3})/i]);
  }

  // Hand-picked literal, then strip null/undefined values so the stored
  // structured_data stays lean (additive: all existing keys preserved).
  const structured_data = {
    ios_facility: iosFacility,
    ios_severity: iosSeverity,
    mnemonic,
    category,
    subcategory,
    interface: iface,
    mac_address: mac,
    link_state: linkState,
    // Normalized contract fields (correlation / UI / CSV)
    srcip,
    dstip,
    srcport,
    dstport,
    user,
    action,
    // Security-relevant extras (capture-when-present)
    group,
    proto,
    signature,
    signature_id,
    threat,
  };
  for (const k of Object.keys(structured_data)) {
    if (structured_data[k] === null || structured_data[k] === undefined) delete structured_data[k];
  }

  return {
    source_ip:       sourceIp,
    source_host:     null,
    facility,
    facility_label:  facilityLabel,
    severity,
    severity_label:  severityLabel,
    vendor:          'cisco',
    program:         iosFacility,
    message:         message || raw,
    raw_message:     raw,
    structured_data,
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseCisco };
