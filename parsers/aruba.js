/**
 * Aruba / HP ProCurve Syslog Parser
 *
 * Aruba APs and controllers send RFC 3164 with Aruba-specific program tags.
 * Controller example: <30>May 12 10:23:01 aruba-ctrl authmgr[1234]: <522007> <WARN> ...
 * AP example:         <30>May 12 10:23:01 AP-LobbyFloor sapd[678]: <305074> <INFO> ...
 *
 * Aruba Mobility Controller logs often contain <MSGID> and <LEVEL> inline.
 */

'use strict';

const ARUBA_PROGRAMS  = /^(authmgr|sapd|stm|mdns|fpapps|nanny|aruba-airwave|localdb|nbapi|profmgr|certmgr|datapath|wms|cppm|clearpass)/i;
// Detection: the RFC3164 header followed by a recognizable Aruba program tag, OR
// a clear ClearPass/CPPM RADIUS / ArubaOS signature anywhere in the line (CPPM
// often relays through different program tags, e.g. "Radius" or process names).
const ARUBA_DETECT_RE = /<\d+>\s*\w{3}\s+\d+\s+[\d:]+\s+\S+\s+(authmgr|sapd|stm|fpapps|nanny|aruba|localdb|profmgr|certmgr|wms|cppm|clearpass|radius|dot1x|eap)/i;
const ARUBA_CPPM_RE   = /\b(ClearPass|CPPM|Policy Manager|RADIUS\b.*(Accept|Reject)|Login Status:\s*(Accept|Reject))\b/i;
const ARUBA_OS_RE     = /\bArubaOS|Aruba(OS-CX|OS-Switch)?\b|\baruba-(ctrl|controller|instant)\b/i;
const ARUBA_LEVEL_RE  = /<(EMERG|ALERT|CRIT|ERR|WARN|NOTICE|INFO|DBG)>/i;

const ARUBA_SEV_MAP = {
  'EMERG': 0, 'ALERT': 1, 'CRIT': 2, 'ERR': 3,
  'WARN': 4, 'NOTICE': 5, 'INFO': 6, 'DBG': 7,
};
const ARUBA_SEV_LABELS = {
  'EMERG': 'emergency', 'ALERT': 'alert', 'CRIT': 'critical', 'ERR': 'error',
  'WARN': 'warning', 'NOTICE': 'notice', 'INFO': 'info', 'DBG': 'debug',
};

const RFC3164_ARUBA = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)/s;

// --- Opportunistic auth/body extraction (ClearPass RADIUS, controller 802.1X, captive portal) ---
// All defensive: only return a value when a confident match is found.

const IP_OCTETS_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function isValidIp(ip) {
  const m = IP_OCTETS_RE.exec(ip);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    if (parseInt(m[i], 10) > 255) return false;
  }
  return true;
}

// A "loopback-ish" sender IP we should never surface as the real client srcip.
function isUsableClientIp(ip) {
  if (!isValidIp(ip)) return false;
  if (ip === '0.0.0.0' || ip === '255.255.255.255') return false;
  return true;
}

// srcip: the REAL client/endpoint IP. Prefer the most explicit "client" labels
// first (Client-IP / Framed-IP / endpoint), then captive-portal / station IP, then
// a generic labeled IP. Deliberately ordered so a controller/NAS/sender IP label
// (NAS-IP-Address, switchIP, src of the syslog relay) is NOT picked as the client.
const SRCIP_RES = [
  /\bClient-?IP(?:-Address)?\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bFramed-?IP(?:-Address)?\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bendpoint(?:-ip)?\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bstation(?:-ip)?\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\buser(?:-ip)?\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bsrc-?ip\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bclient\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i,
  // Generic IP= last — common but ambiguous; only used if nothing better matched.
  /\bIP\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
];
function extractSrcIp(msg) {
  for (const re of SRCIP_RES) {
    const m = re.exec(msg);
    if (m && isUsableClientIp(m[1])) return m[1];
  }
  return null;
}

// NAS / controller / switch IP — captured separately, NEVER used as srcip.
const NASIP_RES = [
  /\bNAS-?IP(?:-Address)?\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bswitch-?IP\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bcontroller-?IP\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
];
function extractNasIp(msg) {
  for (const re of NASIP_RES) {
    const m = re.exec(msg);
    if (m && isValidIp(m[1])) return m[1];
  }
  return null;
}

// mac: mac=, station <mac>, Calling-Station-Id, MAC-Address, or a bare aa:bb:.. /
// aabb.ccdd.eeff token after an identity word. Normalize to colon-lowercase.
const MAC_TOKEN     = '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})';
const MAC_DOT_TOKEN = '([0-9a-fA-F]{4}(?:\\.[0-9a-fA-F]{4}){2})';   // Cisco/Aruba dotted form
const MAC_DASH_TOKEN = '([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})';     // RADIUS dashed form
function normalizeMac(raw) {
  if (!raw) return null;
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':');
}
const MAC_RES = [
  new RegExp('\\b(?:Calling-Station-Id|MAC-?Address|mac|MAC)\\s*[=:]\\s*' + MAC_TOKEN, 'i'),
  new RegExp('\\b(?:Calling-Station-Id|MAC-?Address|mac|MAC)\\s*[=:]\\s*' + MAC_DASH_TOKEN, 'i'),
  new RegExp('\\b(?:Calling-Station-Id|MAC-?Address|mac|MAC)\\s*[=:]\\s*' + MAC_DOT_TOKEN, 'i'),
  new RegExp('\\bstation\\s+' + MAC_TOKEN, 'i'),
  new RegExp('\\bstation\\s+' + MAC_DOT_TOKEN, 'i'),
  new RegExp('\\b(?:client|user|endpoint)\\s+' + MAC_TOKEN, 'i'),
];
function extractMac(msg) {
  for (const re of MAC_RES) {
    const m = re.exec(msg);
    if (m && m[1]) {
      const norm = normalizeMac(m[1]);
      if (norm) return norm;
    }
  }
  return null;
}

// user: User-Name=, user=, for user '<name>', username <name>, or '<name>' after
// "user". Skip MAC-as-username (MAC-auth) so it doesn't pollute the user field.
const USER_RES = [
  /\bUser-?Name\s*[=:]\s*'?"?([^\s,'"]+)"?'?/i,
  /\busername\s*[=:]?\s*'?"?([^\s,'"]+)"?'?/i,
  /\bfor user\s+'([^']+)'/i,
  /\buser\s*[=:]\s*'?"?([^\s,'"]+)"?'?/i,
  /\buser\s+'([^']+)'/i,
];
const LOOKS_LIKE_MAC = /^[0-9a-fA-F]{2}([:\-.][0-9a-fA-F]{2,4}){2,5}$|^[0-9a-fA-F]{12}$/;
function extractUser(msg) {
  for (const re of USER_RES) {
    const m = re.exec(msg);
    if (m && m[1] && !LOOKS_LIKE_MAC.test(m[1])) return m[1];
  }
  return null;
}

// ESSID / SSID, AP name, RADIUS service, auth source — generous, only-when-present.
function firstMatch(msg, re) {
  const m = re.exec(msg);
  return m && m[1] ? m[1].trim() : null;
}
function extractEssid(msg)     { return firstMatch(msg, /\b(?:ESSID|SSID)\s*[=:]?\s*'?"?([^\s,'"]+)"?'?/i); }
function extractAp(msg)        { return firstMatch(msg, /\b(?:AP(?:-Name)?|access point)\s*[=:]?\s*'?"?([A-Za-z0-9_\-.]+)"?'?/i); }
function extractService(msg)   { return firstMatch(msg, /\bservice\s*[=:]\s*'?"?([^,'"]+?)"?'?(?:\s*,|\s*$|\s{2,})/i); }
function extractAuthSource(msg){ return firstMatch(msg, /\b(?:auth-?source|Authentication Source|auth source)\s*[=:]\s*'?"?([^,'"]+?)"?'?(?:\s*,|\s*$|\s{2,})/i); }
function extractAuthMethod(msg){ return firstMatch(msg, /\b(?:auth-?method|Authentication Method|EAP-?Type)\s*[=:]\s*'?"?([^,'"]+?)"?'?(?:\s*,|\s*$|\s{2,})/i); }
function extractRole(msg)      { return firstMatch(msg, /\b(?:role|Enforcement Profile)\s*[=:]\s*'?"?([^,'"]+?)"?'?(?:\s*,|\s*$|\s{2,})/i); }
function extractReason(msg)    { return firstMatch(msg, /\b(?:reason|Error Code|Alerts)\s*[=:]\s*'?"?([^,'"]+?)"?'?(?:\s*,|\s*$|\s{2,})/i); }

// subcategory: login_failed / login_success for auth events.
// Failures FIRST so "Reject"/"failure" never falls through to a success word.
const FAIL_RE = /Auth(?:entication)?\s+fail|authentication\s+failed|\bauth\s+failure\b|\bReject\b|Login\s+Status:\s*Reject|server\s+reject|access[- ]reject|deauth.*(fail|reject)|denied|invalid\s+(?:user|password|credential)|MAC\s+auth\s+fail/i;
const SUCCESS_RE = /Auth(?:entication)?\s+success|\bauthenticated\b|\bAccept\b|Login\s+Status:\s*Accept|access[- ]accept|successfully\s+authenticated/i;
function extractAuthSubcategory(msg) {
  if (FAIL_RE.test(msg))    return 'login_failed';
  if (SUCCESS_RE.test(msg)) return 'login_success';
  return null;
}

// Is this line an authentication event at all? Used to (a) set category and (b)
// gate subcategory so operational logs (port/link/stp) are never mislabeled.
const AUTH_CONTEXT_RE = /802\.1[xX]|\bdot1x\b|\bEAP\b|\bRADIUS\b|\bMAC[- ]?auth\b|captive\s*portal|\bauthmgr\b|Login\s+Status|User-?Name|Calling-Station-Id|ClearPass|CPPM|access-(accept|reject)|authenticat/i;
function looksLikeAuth(prog, msg) {
  const p = (prog || '').toLowerCase();
  if (/authmgr|certmgr|localdb|cppm|clearpass|radius|dot1x|eap/.test(p)) return true;
  return AUTH_CONTEXT_RE.test(msg);
}

// Operational (port/link/stp/system) detection — capture interface/port, keep as
// network. Never set an auth subcategory on these.
const OPER_RE = /\b(?:port|interface)\s+[\w/]+|link\s*(?:up|down)|STP|spanning[- ]?tree|MSTP|RSTP|PoE|transceiver|fan|power\s*supply|temperature|reboot|cold\s*start/i;
function extractPort(msg) {
  return firstMatch(msg, /\b(?:port|interface)\s+([\w./]+)/i);
}

function parseAruba(raw, sourceIp) {
  // Accept either the program-tag signature OR an unmistakable ClearPass/CPPM /
  // ArubaOS signature (CPPM relays may not use a known program tag).
  if (!ARUBA_DETECT_RE.test(raw) && !ARUBA_CPPM_RE.test(raw) && !ARUBA_OS_RE.test(raw)) return null;

  const m = RFC3164_ARUBA.exec(raw);
  if (!m) return null;

  const pri     = parseInt(m[1], 10);
  const facility = Math.floor(pri / 8);
  let severity   = pri % 8;
  let sevLabel   = ['emergency','alert','critical','error','warning','notice','info','debug'][severity] || 'info';

  const msgBody = m[6] || '';

  // Aruba may embed <WARN>, <INFO> etc. in the message body - use that if present
  const levelMatch = ARUBA_LEVEL_RE.exec(msgBody);
  if (levelMatch) {
    const lvl = levelMatch[1].toUpperCase();
    severity  = ARUBA_SEV_MAP[lvl] ?? severity;
    sevLabel  = ARUBA_SEV_LABELS[lvl] ?? sevLabel;
  }

  // Extract Aruba message ID if present: <522007>
  const msgIdMatch = /<(\d{6})>/.exec(msgBody);
  const msgId      = msgIdMatch ? msgIdMatch[1] : null;
  const cleanMsg   = msgBody.replace(/<[^>]+>/g, '').trim();

  const year = new Date().getFullYear();

  // Opportunistic body extraction (real client IP/MAC/user + auth outcome).
  // Use cleanMsg (Aruba <...> tokens stripped) so the angle-bracket noise
  // doesn't interfere with the labeled-field regexes.
  const program    = m[4] || null;
  const structured = { msg_id: msgId, program: program, pid: m[5] };

  // --- Identity / source (generous, only-when-present) ---
  const srcip      = extractSrcIp(cleanMsg);   // REAL client/endpoint IP, never the NAS/sender
  const nasip      = extractNasIp(cleanMsg);   // controller/switch IP — captured, never srcip
  const mac        = extractMac(cleanMsg);     // endpoint MAC (802.1X / MAC-auth may be MAC-only)
  const user       = extractUser(cleanMsg);
  const essid      = extractEssid(cleanMsg);
  const ap         = extractAp(cleanMsg);
  const service    = extractService(cleanMsg);
  const authSource = extractAuthSource(cleanMsg);
  const authMethod = extractAuthMethod(cleanMsg);
  const role       = extractRole(cleanMsg);
  const reason     = extractReason(cleanMsg);
  const port       = extractPort(cleanMsg);

  // --- Auth classification ---
  // Only treat as an auth event (and only then derive subcategory + category) when
  // the line is genuinely an authentication context. Operational logs (port/link/
  // stp/system) must NOT be tagged with an auth subcategory or category.
  const isAuth     = looksLikeAuth(program, cleanMsg);
  const isOper     = OPER_RE.test(cleanMsg);
  const subcategory = isAuth ? extractAuthSubcategory(cleanMsg) : null;

  if (srcip)       structured.srcip       = srcip;
  if (nasip)       structured.nas_ip      = nasip;
  if (mac)         structured.mac         = mac;
  if (user)        structured.user        = user;
  if (essid)       structured.essid       = essid;
  if (ap)          structured.ap          = ap;
  if (service)     structured.service     = service;
  if (authSource)  structured.auth_source = authSource;
  if (authMethod)  structured.auth_method = authMethod;
  if (role)        structured.role        = role;
  if (reason)      structured.reason      = reason;
  // Only attach interface/port on operational (non-auth) logs so an auth line that
  // happens to mention a port doesn't get a misleading interface field.
  if (port && isOper && !isAuth) structured.interface = port;
  if (subcategory) structured.subcategory = subcategory;

  // Set category for confirmed authentication events. taxonomy.js honors a
  // parser-provided `category` (when not the generic 'network') as highest
  // priority, so this guarantees auth events land in 'authentication' even if the
  // program tag is an unusual CPPM relay name. Operational logs are left WITHOUT a
  // category so taxonomy classifies them (interface/wireless/system/network).
  if (isAuth && (subcategory || mac || user)) structured.category = 'authentication';

  return {
    source_ip:       sourceIp,
    source_host:     m[3] || null,
    facility,
    facility_label:  ['kern','user','mail','daemon','auth','syslog','lpr','news','uucp','cron','authpriv','ftp','ntp','audit','alert2','clock','local0','local1','local2','local3','local4','local5','local6','local7'][facility] || 'local7',
    severity,
    severity_label:  sevLabel,
    vendor:          'aruba',
    program:         m[4] || null,
    message:         cleanMsg || msgBody,
    raw_message:     raw,
    structured_data: structured,
    is_parsed:       true,
    log_timestamp:   new Date(`${m[2]} ${year}`),
  };
}

module.exports = { parseAruba };
