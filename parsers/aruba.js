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
const ARUBA_DETECT_RE = /<\d+>\s*\w{3}\s+\d+\s+[\d:]+\s+\S+\s+(authmgr|sapd|stm|fpapps|nanny|aruba|localdb|profmgr|certmgr|wms|cppm|clearpass)/i;
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

// srcip: first of Client-IP=, IP=, src-ip=, or a labeled IP token. Validate 4 octets.
const SRCIP_RES = [
  /\bClient-IP\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bsrc-?ip\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
  /\bIP\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
];
function extractSrcIp(msg) {
  for (const re of SRCIP_RES) {
    const m = re.exec(msg);
    if (m && isValidIp(m[1])) return m[1];
  }
  return null;
}

// mac: mac=, station <mac>, or Calling-Station-Id. Accept aa:bb:cc:dd:ee:ff style.
const MAC_TOKEN = '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})';
const MAC_RES = [
  new RegExp('\\b(?:mac|MAC)\\s*[=:]\\s*' + MAC_TOKEN),
  new RegExp('\\bCalling-Station-Id\\s*[=:]\\s*' + MAC_TOKEN, 'i'),
  new RegExp('\\bstation\\s+' + MAC_TOKEN, 'i'),
];
function extractMac(msg) {
  for (const re of MAC_RES) {
    const m = re.exec(msg);
    if (m && m[1]) return m[1].toLowerCase();
  }
  return null;
}

// user: user=, User-Name=, for user '<name>', or '<name>' after "user".
const USER_RES = [
  /\bUser-Name\s*[=:]\s*'?([^\s,'"]+)'?/i,
  /\bfor user\s+'([^']+)'/i,
  /\buser\s*[=:]\s*'?([^\s,'"]+)'?/i,
  /\buser\s+'([^']+)'/i,
];
function extractUser(msg) {
  for (const re of USER_RES) {
    const m = re.exec(msg);
    if (m && m[1]) return m[1];
  }
  return null;
}

// subcategory: login_failed / login_success for auth events.
const FAIL_RE    = /Auth(?:entication)?\s+fail|authentication failed|\bReject\b|Login Status:\s*Reject|server reject/i;
const SUCCESS_RE = /Auth(?:entication)?\s+success|\bauthenticated\b|\bAccept\b/i;
function extractAuthSubcategory(msg) {
  if (FAIL_RE.test(msg))    return 'login_failed';
  if (SUCCESS_RE.test(msg)) return 'login_success';
  return null;
}

function parseAruba(raw, sourceIp) {
  if (!ARUBA_DETECT_RE.test(raw)) return null;

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
  const structured = { msg_id: msgId, program: m[4], pid: m[5] };

  const srcip       = extractSrcIp(cleanMsg);
  const mac         = extractMac(cleanMsg);
  const user        = extractUser(cleanMsg);
  const subcategory = extractAuthSubcategory(cleanMsg);

  if (srcip)       structured.srcip       = srcip;
  if (mac)         structured.mac         = mac;
  if (user)        structured.user        = user;
  if (subcategory) structured.subcategory = subcategory;

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
