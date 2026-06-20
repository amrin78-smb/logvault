/**
 * Sangfor Syslog Parser
 *
 * Sangfor NGAF (NGFW) / IAM / aTrust SSL-VPN devices send logs in two shapes:
 *   1. CEF (Common Event Format) pass-through — CEF:0|Sangfor|<product>|...|extensions
 *   2. Plain RFC3164 with a program tag starting with "Sangfor"
 *
 * Example (CEF, traffic): <166>May 12 10:23:01 SangforNGFW CEF:0|Sangfor|NGAF|9.0|100001|Traffic Log|5|
 *          src=192.168.1.10 dst=8.8.8.8 spt=54321 dpt=443 proto=TCP act=permit
 *
 * Example (CEF, SSL-VPN login fail): CEF:0|Sangfor|aTrust|2.1|VPN-2001|SSL VPN Login Failed|7|
 *          src=203.0.113.9 suser=jdoe act=deny outcome=failure msg=invalid password
 *
 * Example (CEF, IPS threat): CEF:0|Sangfor|NGAF|9.0|IPS-5500|Intrusion Detected|9|
 *          src=203.0.113.50 dst=10.0.0.20 act=drop cat=Exploit cs1Label=ThreatName cs1=SQL Injection
 *
 * Contract (structured_data keys downstream needs):
 *   srcip (REAL client/source, never the appliance/sender), dstip, srcport, dstport,
 *   user, subcategory ('login_failed'|'login_success'|'auth_failed'), action.
 * Entry category is set on structured_data.category: vpn / authentication / web /
 * security / firewall (taxonomy.js maps & refines).
 */

'use strict';

// Sangfor detection: CEF header with Sangfor vendor, OR program tag containing Sangfor
const SANGFOR_CEF_RE  = /CEF:0\|Sangfor\|/i;
const SANGFOR_TAG_RE  = /\bSangfor\w*/i;
const SANGFOR_KV_RE   = /(\w+)=(?:"([^"]*)"|([\S]*))/g;

// CEF extension parser: a value runs until the next " key=" or end-of-string, so
// multi-word values (e.g. cs1=SQL Injection Attempt, msg=invalid password,
// catdesc=Malicious Web Sites) are captured WHOLE. Backslash-escaped "=" and "\n"
// are unescaped per the CEF spec.
function parseCefExtension(ext) {
  const out = {};
  if (!ext) return out;
  const re = /(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)/g;
  let m;
  while ((m = re.exec(ext)) !== null) {
    out[m[1]] = m[2].trim().replace(/\\=/g, '=').replace(/\\n/g, '\n');
  }
  return out;
}

const CEF_SEV_MAP = { 0:'debug',1:'debug',2:'debug',3:'info',4:'info',5:'notice',6:'warning',7:'warning',8:'error',9:'critical',10:'critical' };
const CEF_SEV_NUM = { 0:7,1:7,2:7,3:6,4:6,5:5,6:4,7:4,8:3,9:2,10:2 };

// Validate an IPv4 address (4 octets, 0-255). Returns the IP or null.
function validIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  for (let i = 1; i <= 4; i++) { if (parseInt(m[i], 10) > 255) return null; }
  return ip.trim();
}

// Parse a port string into an int in range, else null.
function validPort(p) {
  if (p == null) return null;
  const n = parseInt(p, 10);
  if (isNaN(n) || n < 0 || n > 65535) return null;
  return n;
}

// Threat / IPS / attack detection. Returns true when the text describes a
// security event (intrusion, malware, attack, virus, ...).
const THREAT_RE = /attack|threat|intrusion|exploit|malware|virus|trojan|ransomware|botnet|spyware|worm|\bips\b|\bids\b|brute.?force|c2|command.?and.?control|vulnerab|0day|zero.?day|signature|anomaly/i;

// Web / URL-filtering detection.
const WEB_RE = /url.?filter|web.?filter|web.?access|http|https|\burl\b|website|web.?categor|content.?filter|proxy|browse/i;

// Decide category ('vpn' / 'authentication') from auth/VPN text, else null.
function authCategory(text) {
  const t = (text || '').toLowerCase();
  if (/vpn|ssl.?vpn|tunnel|ipsec|atrust|l2tp|pptp/.test(t)) return 'vpn';
  if (/auth|login|logon|sign.?in|credential|password/.test(t)) return 'authentication';
  return null;
}

// Decide auth subcategory ('login_failed' / 'login_success' / 'auth_failed') from
// text + an optional explicit outcome token, else null.
function authSubcategory(text, outcome) {
  const t = (text || '').toLowerCase();
  const o = (outcome || '').toLowerCase();
  const isAuth = /auth|login|logon|sign.?in|credential|password|vpn|ssl.?vpn|tunnel|ipsec|atrust|l2tp|pptp/.test(t);
  if (!isAuth) return null;
  const failBlob = `${t} ${o}`;
  if (/fail|failed|failure|denied|deny|reject|invalid|incorrect|wrong|error|lockout|locked|unauthor/.test(failBlob)) {
    // Distinguish a generic auth failure (no login verb) from a login failure.
    if (/login|logon|sign.?in|vpn|ssl.?vpn|tunnel|ipsec|atrust/.test(t)) return 'login_failed';
    return 'auth_failed';
  }
  if (/success|succeed|succeeded|granted|accept|established|logged in|connect|online/.test(failBlob)) return 'login_success';
  return null;
}

// Decide the entry category from the full CEF event context.
//   vpn  > authentication > security (threat) > web > firewall
// We check VPN/auth first (so an SSL-VPN login-fail is 'vpn'/'authentication',
// not mislabeled), then threat/IPS, then web/url-filter, else firewall.
function cefCategory(eventName, kv) {
  const cat     = `${kv.cat || ''} ${kv.catdesc || ''}`;
  const threatName = kv.cs1Label && /threat|attack|signature|rule|ips/i.test(kv.cs1Label) ? kv.cs1 : '';
  const blob    = `${eventName || ''} ${kv.msg || ''} ${kv.act || ''} ${cat} ${threatName} ${kv.request || kv.url || ''}`;
  const ac = authCategory(blob);
  if (ac) return ac;
  if (THREAT_RE.test(blob)) return 'security';
  if (WEB_RE.test(blob) || kv.request || kv.url) return 'web';
  return 'firewall';
}

function parseSangfor(raw, sourceIp) {
  if (!SANGFOR_CEF_RE.test(raw) && !SANGFOR_TAG_RE.test(raw)) return null;

  let severity = 6; let severityLabel = 'info';
  let message  = raw; let structuredData = {};
  let sourceHost = null; let logTimestamp = null;

  if (SANGFOR_CEF_RE.test(raw)) {
    // CEF format: CEF:0|Vendor|Product|Version|EventID|EventName|Severity|extensions
    const cefParts = raw.split('CEF:0|');
    if (cefParts.length < 2) return null;

    const cefBody  = cefParts[1];
    const pipes    = cefBody.split('|');
    if (pipes.length < 7) return null;

    const product   = pipes[1]?.trim();
    const version   = pipes[2]?.trim();
    const eventId   = pipes[3]?.trim();
    const eventName = pipes[4]?.trim();
    const cefSev    = parseInt(pipes[5]?.trim(), 10);

    severity      = CEF_SEV_NUM[cefSev] ?? 6;
    severityLabel = CEF_SEV_MAP[cefSev] ?? 'info';

    // Parse extensions (key=value after the 7th pipe). CEF values may contain
    // spaces, so span each value to the next key (parseCefExtension).
    const extensions = pipes.slice(6).join('|');
    const kv = parseCefExtension(extensions);

    // Resolve a threat NAME (IPS/attack signature) from common CEF custom-string
    // label/value pairs, or a fallback threat field.
    let threatName = null;
    if (kv.cs1Label && /threat|attack|signature|rule|ips|malware|virus/i.test(kv.cs1Label)) threatName = kv.cs1;
    else if (kv.cs2Label && /threat|attack|signature|rule|ips|malware|virus/i.test(kv.cs2Label)) threatName = kv.cs2;
    threatName = threatName || kv.threat || kv.attack || kv.virus || kv.signature || null;

    message = eventName || 'Sangfor event';
    if (kv.src && kv.dst) message += `: ${kv.src} -> ${kv.dst}`;
    if (kv.suser || kv.user) message += ` user=${kv.suser || kv.user}`;
    if (kv.act) message += ` action=${kv.act}`;
    if (threatName) message += ` threat=${threatName}`;
    if (kv.request || kv.url) message += ` url=${(kv.request || kv.url).substring(0, 80)}`;
    if (kv.msg) message += ` | ${kv.msg}`;

    sourceHost    = kv.dvchost || kv.dhost || null;

    // Keep ALL raw CEF extension fields (generous), then layer normalized keys.
    structuredData = { format: 'CEF', event_name: eventName, product, version, event_id: eventId, ...kv };

    // --- Normalized contract keys (additive) ---
    const authText  = `${eventName || ''} ${kv.msg || ''} ${kv.act || ''}`;
    const outcome   = kv.outcome || kv.result || kv.status;
    const subcat    = authSubcategory(authText, outcome);
    const category  = cefCategory(eventName, kv);

    structuredData.srcip   = validIp(kv.src);          // REAL client/source
    structuredData.dstip   = validIp(kv.dst);
    structuredData.srcport = validPort(kv.spt);
    structuredData.dstport = validPort(kv.dpt);
    structuredData.user    = kv.suser || kv.user || kv.duser || null;
    structuredData.action  = kv.act || null;
    structuredData.proto   = kv.proto || kv.app || null;
    structuredData.url     = kv.request || kv.url || null;
    structuredData.web_category = kv.catdesc || kv.cat || null;   // url-filtering category
    if (threatName)  structuredData.threat_name = threatName;
    if (subcat)      structuredData.subcategory = subcat;
    if (category)    structuredData.category    = category;

    // Drop normalized keys that came up empty (additive/opportunistic — never
    // clobber a real raw field with null).
    ['srcip', 'dstip', 'srcport', 'dstport', 'user', 'action', 'proto', 'url', 'web_category']
      .forEach(k => (structuredData[k] == null) && delete structuredData[k]);

    // Timestamp from CEF `rt`/`start` (epoch millis) when present — uses the log's
    // own time, not the collector OS clock.
    const epoch = kv.rt || kv.start;
    if (epoch != null) {
      const n = parseInt(epoch, 10);
      if (!isNaN(n)) { const d = new Date(n); if (!isNaN(d.getTime())) logTimestamp = d; }
    }

  } else {
    // Plain RFC3164 with Sangfor in the program tag
    const rfc = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)/s.exec(raw);
    if (!rfc) return null;

    const pri = parseInt(rfc[1], 10);
    severity       = pri % 8;
    severityLabel  = ['emergency','alert','critical','error','warning','notice','info','debug'][severity] || 'info';
    sourceHost     = rfc[3];
    message        = rfc[5] || raw;
    structuredData = { format: 'RFC3164', program: rfc[4] };
    const year = new Date().getFullYear();
    try {
      const d = new Date(`${rfc[2]} ${year}`);
      if (!isNaN(d.getTime())) logTimestamp = d;
    } catch (_) {}

    // Opportunistic extraction (only set when found). Covers auth/VPN lines, plus
    // threat / web / firewall lines for category + action.
    const subcat = authSubcategory(message, null);
    const cat    = authCategory(message);

    // Labeled source IP (the REAL client, never the appliance/sender).
    const ipM   = message.match(/\b(?:src|sip|source|from|client|remote)(?:_?ip)?\s*[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
    const srcip = ipM ? validIp(ipM[1]) : null;
    // Labeled destination IP.
    const dstM  = message.match(/\b(?:dst|dip|dest(?:ination)?|to)(?:_?ip)?\s*[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
    const dstip = dstM ? validIp(dstM[1]) : null;
    // Username.
    const userM = message.match(/\b(?:user|usr|username|account)\s*[=:]\s*("[^"]+"|\S+)/i);
    const user  = userM ? userM[1].replace(/^"|"$/g, '') : null;
    // Action / outcome.
    const actM  = message.match(/\b(?:act|action|outcome|result)\s*[=:]\s*("[^"]+"|\S+)/i);
    const action = actM ? actM[1].replace(/^"|"$/g, '') : null;
    // URL.
    const urlM  = message.match(/\b(?:url|request|uri)\s*[=:]\s*("[^"]+"|\S+)/i);
    const url   = urlM ? urlM[1].replace(/^"|"$/g, '') : null;

    if (srcip)  structuredData.srcip  = srcip;
    if (dstip)  structuredData.dstip  = dstip;
    if (user)   structuredData.user   = user;
    if (action) structuredData.action = action;
    if (url)    structuredData.url    = url;
    if (subcat) structuredData.subcategory = subcat;

    // Category: auth/VPN first, then threat, then web, then (if an action present) firewall.
    if (cat) structuredData.category = cat;
    else if (THREAT_RE.test(message)) structuredData.category = 'security';
    else if (WEB_RE.test(message) || url) structuredData.category = 'web';
    else if (action) structuredData.category = 'firewall';
  }

  return {
    source_ip:       sourceIp,
    source_host:     sourceHost,
    facility:        20,
    facility_label:  'local4',
    severity,
    severity_label:  severityLabel,
    vendor:          'sangfor',
    program:         'Sangfor',
    message,
    raw_message:     raw,
    structured_data: structuredData,
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parseSangfor };
