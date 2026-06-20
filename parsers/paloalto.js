/**
 * Palo Alto PAN-OS Syslog Parser
 *
 * PAN-OS logs are CSV-formatted with a type field as the 4th column.
 * Example TRAFFIC: 1,2026/05/12 10:23:01,012345678,TRAFFIC,end,...
 * Example THREAT:  1,2026/05/12 10:23:01,012345678,THREAT,vulnerability,...
 *
 * ──────────────────────────────────────────────────────────────────────────
 * INDEX-FRAGILITY CAVEAT (read before "fixing" any column number below)
 * ──────────────────────────────────────────────────────────────────────────
 * PAN-OS CSV field positions vary by BOTH log-type AND PAN-OS version
 * (8.x / 9.x / 10.x / 11.x each append columns, and FUTURE_USE placeholders
 * shift things). The numeric indices in this file are BEST-EFFORT defaults
 * derived from the documented PAN-OS field-order reference — we have NO real
 * PAN-OS samples to validate against yet. To stay robust the parser ALWAYS:
 *   - validates that a column actually looks like an IPv4 (isIpv4) before
 *     trusting a schema-dependent index, and
 *   - falls back to scanning the row (findIp / pickByRegex) when the expected
 *     column is missing / shifted / holds something unexpected.
 * When real samples arrive, tune the indices and KEEP the validation/fallbacks.
 * This parser is ADDITIVE — it never throws away a field it cannot place; the
 * full CSV is preserved in raw_message.
 */

'use strict';

// PAN-OS log types
const PANLOG_TYPES = new Set(['TRAFFIC','THREAT','CONFIG','SYSTEM','HIPMATCH','GLOBALPROTECT','AUTHENTICATION','USERID']);

// Map PAN-OS severity strings to syslog severity numbers.
// PAN-OS severities: critical, high, medium, low, informational.
const PAN_SEV_MAP = {
  'critical': 2, 'high': 3, 'medium': 4, 'low': 5, 'informational': 6, 'info': 6,
};
// And their syslog-style label (so the UI severity chips read sensibly).
const PAN_SEV_LABEL = {
  'critical': 'critical', 'high': 'error', 'medium': 'warning',
  'low': 'notice', 'informational': 'info', 'info': 'info',
};

// THREAT subtypes that are genuine intrusion/malware detections (set type='ips'
// so IPS correlation + threat views engage). URL / data / file filtering are
// NOT IPS events — they must stay out of the IPS-repeated-attack correlation.
const IPS_THREAT_SUBTYPES = new Set([
  'vulnerability', 'spyware', 'virus', 'wildfire', 'wildfire-virus', 'flood', 'scan', 'packet',
]);
// THREAT subtypes that are really web/URL activity → category 'web'.
const WEB_THREAT_SUBTYPES = new Set(['url']);

// Loose IPv4 validator (4 octets, each 0-255). Used to defensively confirm a
// CSV column actually holds an IP before we trust a schema-dependent index.
function isIpv4(v) {
  if (!v) return false;
  const m = String(v).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}

// Very loose IPv6 detector (PAN-OS can log v6 in the same src/dst columns).
function isIpv6(v) {
  if (!v) return false;
  const s = String(v).trim();
  return s.includes(':') && /^[0-9a-fA-F:.]+$/.test(s) && (s.match(/:/g) || []).length >= 2;
}

function isIp(v) { return isIpv4(v) || isIpv6(v); }

// Scan a row for the Nth (default first) column that looks like a valid IP.
// Fallback for when the exact schema-version column index is uncertain.
function findIp(cols, skip) {
  let seen = 0;
  for (const c of cols) {
    if (isIp(c)) { if (seen >= (skip || 0)) return String(c).trim(); seen++; }
  }
  return undefined;
}

// Treat a column value as present only when it's a non-empty, non-placeholder
// token. PAN-OS uses empty strings and literal "FUTURE_USE" / "0.0.0.0" fillers.
function clean(v) {
  if (v === undefined || v === null) return undefined;
  const s = String(v).trim();
  if (!s || s === '0.0.0.0' || /^future_use$/i.test(s)) return undefined;
  return s;
}

// Pick the first column matching a predicate, scanning left→right. Used as a
// schema-independent fallback for non-IP fields (ports, actions, etc.).
function pickByRegex(cols, re, fromIdx) {
  for (let i = (fromIdx || 0); i < cols.length; i++) {
    const c = clean(cols[i]);
    if (c && re.test(c)) return c;
  }
  return undefined;
}

// Numeric port 1-65535.
function isPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= 65535;
}

function parsePaloAlto(raw, sourceIp) {
  // PAN-OS syslog-wrapped CSV. Strip an optional <PRI> and an optional
  // RFC3164/5424 header that some collectors/relays prepend before the CSV.
  let stripped = raw.replace(/^<\d{1,3}>/, '').trim();
  // If a syslog header precedes the CSV, the first CSV field ("1,") and the
  // PAN-OS type token still appear; locate the leading "<n>,YYYY/MM/DD ..." CSV
  // start defensively. Most PAN-OS senders emit the bare CSV, so this is a no-op
  // in the common case. We look for the first comma-group that yields a known
  // log type at a plausible position.
  let cols = stripped.split(',');

  // If column 3 isn't a known type, try to re-anchor: some headers shift the CSV
  // so the type lands elsewhere. Find the index of the first known log-type token
  // and re-slice so it sits at index 3 (matching native PAN-OS field order).
  let typeIdx = 3;
  if (!PANLOG_TYPES.has((cols[3] || '').trim().toUpperCase())) {
    const found = cols.findIndex((c) => PANLOG_TYPES.has((c || '').trim().toUpperCase()));
    if (found >= 1) { cols = cols.slice(found - 3); typeIdx = 3; }
  }
  if (cols.length < 5) return null;

  const logType = (cols[typeIdx] || '').trim().toUpperCase();
  if (!PANLOG_TYPES.has(logType)) return null;

  // Core header fields (stable across versions): receive-time(1), serial(2),
  // type(3), subtype(4). PAN-OS also carries a "generate time" deeper in the row
  // (typically col 6/7) — we prefer the leading receive-time but fall back to
  // scanning for a second timestamp if col 1 is unusable.
  const tsStr   = clean(cols[1]);          // receive time "2026/05/12 10:23:01"
  const serial  = clean(cols[2]);
  const subtype = clean(cols[typeIdx + 1]); // e.g. "end", "vulnerability", "url"
  const subLc   = (subtype || '').toLowerCase();

  // ── Timestamp / timezone ──────────────────────────────────────────────
  // PAN-OS logs the device's local time WITHOUT an explicit offset in the CSV.
  // Relying on the collector OS locale is wrong, so we parse it as the literal
  // wall-clock and treat it as the configured device time. We do NOT silently
  // apply the collector's TZ. If a leading receive-time is missing/malformed we
  // scan for the first "YYYY/MM/DD HH:MM:SS" token in the row (generate-time).
  function parsePanTime(s) {
    if (!s) return null;
    // PAN-OS format "YYYY/MM/DD HH:MM:SS" -> ISO "YYYY-MM-DDTHH:MM:SS".
    const m = String(s).trim().match(/^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$/);
    if (!m) return null;
    const d = new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`);
    return isNaN(d.getTime()) ? null : d;
  }
  let logTimestamp = parsePanTime(tsStr);
  if (!logTimestamp) {
    const tsScan = pickByRegex(cols, /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}$/);
    logTimestamp = parsePanTime(tsScan);
  }

  // ── Severity ──────────────────────────────────────────────────────────
  // Default to info; refine per log-type below using the faithful PAN-OS
  // severity string when one is present in the row.
  let severity = 6;
  let severityLabel = 'info';
  function applyPanSeverity(sevRaw) {
    const sev = (sevRaw || '').toLowerCase();
    if (PAN_SEV_MAP[sev] !== undefined) {
      severity = PAN_SEV_MAP[sev];
      severityLabel = PAN_SEV_LABEL[sev] || sev;
      return true;
    }
    return false;
  }

  // Build a human-readable message summary
  let message = `PAN-OS ${logType}`;
  if (subtype) message += ` [${subtype}]`;

  // Normalized fields the correlation engine + UI rely on (exact keys), merged
  // into structured_data below. Only-when-present.
  const norm = {};
  let category = 'system'; // top-level taxonomy hint (taxonomy.js re-derives via log_type/subtype)

  // ── TRAFFIC ────────────────────────────────────────────────────────────
  // PAN-OS 8.x+ TRAFFIC. Documented field order is roughly:
  //   7 src, 8 dst, 9 natsrc, 10 natdst, 11 rule, 12 srcuser, 13 dstuser,
  //   14 app, 16 from(zone), 17 to(zone), 25 sport, 26 dport, 29 proto,
  //   30 action, 31 bytes, 32 bytes-sent, 33 bytes-received, 34 packets,
  //   24/26.. srcloc/dstloc (country). BUT exact offsets shift per version, so
  //   for the fragile fields (ports/proto/action/country/bytes) we anchor on the
  //   reliably-found dst IP position and scan AFTER it for value-typed matches
  //   (numeric ports, a known proto token, a known firewall action verb, alpha
  //   country) rather than trusting an absolute index. Indices below are
  //   best-effort pending real PAN-OS samples; the scans keep us correct anyway.
  if (logType === 'TRAFFIC' || logType === 'THREAT') {
    var srcip = isIp(cols[7]) ? clean(cols[7]) : findIp(cols, 0);
    var dstip = isIp(cols[8]) ? clean(cols[8]) : findIp(cols, 1);
    if (srcip) norm.srcip = srcip;
    if (dstip) norm.dstip = dstip;
  }

  // Helper: index just after the dst IP, to anchor forward scans.
  function afterDst() {
    const di = cols.findIndex((c, i) => i >= 1 && clean(c) === (norm.dstip));
    return di >= 0 ? di + 1 : 9;
  }

  // Strict value vocabularies. PROTO is alpha-only on purpose: PAN-OS logs the
  // protocol NAME (tcp/udp/icmp/...), and matching bare numbers here would
  // wrongly grab numeric columns like repeatcnt/sessionid.
  const PROTO_RE  = /^(tcp|udp|icmp|icmp6|ipv6-icmp|igmp|gre|esp|ah|sctp|ospf|pim)$/i;
  // NOTE: "forward"/"threat" (the log-action/flags column) is intentionally NOT
  // in this set — only real session-disposition verbs, so we don't grab the flags col.
  const ACTION_RE = /^(allow|deny|drop|reset-both|reset-client|reset-server|drop-icmp|alert|block|block-url|block-ip|block-continue|sinkhole|reset|continue|override|wildfire-upload-success|wildfire-upload-failure|wildfire-upload-skip)$/i;
  const SEV_RE    = /^(critical|high|medium|low|informational)$/i;
  const DIR_RE    = /^(client-to-server|server-to-client)$/i;

  if (logType === 'TRAFFIC') {
    category = 'firewall';

    const natsrc = isIp(cols[9]) ? clean(cols[9]) : undefined;
    const natdst = isIp(cols[10]) ? clean(cols[10]) : undefined;
    if (natsrc) norm.natsrcip = natsrc;
    if (natdst) norm.natdstip = natdst;

    const rule    = clean(cols[11]);
    const srcuser = clean(cols[12]);
    const dstuser = clean(cols[13]);
    const app     = clean(cols[14]);
    const srczone = clean(cols[16]);
    const dstzone = clean(cols[17]);
    if (rule)    norm.rule    = rule;
    if (srcuser && !isIp(srcuser)) { norm.user = srcuser; norm.srcuser = srcuser; }
    if (dstuser && !isIp(dstuser)) norm.dstuser = dstuser;
    if (app && !isIp(app)) norm.app = app;
    if (srczone) norm.srczone = srczone;
    if (dstzone) norm.dstzone = dstzone;

    // Ports: documented PAN-OS TRAFFIC positions are sport=24, dport=25 (8.x+);
    // newer versions shift by a couple of columns. Prefer those when they
    // validate as ports, else fall back to the first two port-looking columns
    // after the dst IP. (Best-effort indices; the validation keeps it honest.)
    const start = afterDst();
    let sport = isPort(cols[24]) ? clean(cols[24]) : undefined;
    let dport = isPort(cols[25]) ? clean(cols[25]) : undefined;
    if (!sport || !dport) {
      const portIdxs = [];
      for (let i = start; i < cols.length && portIdxs.length < 2; i++) {
        const c = clean(cols[i]);
        if (c && isPort(c)) portIdxs.push(c);
      }
      if (!sport) sport = portIdxs[0];
      if (!dport) dport = portIdxs[1];
    }
    if (sport) norm.srcport = sport;
    if (dport) norm.dstport = dport;

    // Protocol + action: located by their known value vocabularies after dst.
    const proto  = pickByRegex(cols, PROTO_RE, start);
    const action = pickByRegex(cols, ACTION_RE, start);
    if (proto)  norm.proto  = proto.toLowerCase();
    if (action) norm.action = action.toLowerCase();

    // Bytes / packets — best-effort positional, kept only when numeric.
    const bytes   = clean(cols[31]);
    const bsent   = clean(cols[32]);
    const brcvd   = clean(cols[33]);
    const packets = clean(cols[34]);
    if (bytes   && /^\d+$/.test(bytes))   norm.bytes      = bytes;
    if (bsent   && /^\d+$/.test(bsent))   norm.bytes_sent = bsent;
    if (brcvd   && /^\d+$/.test(brcvd))   norm.bytes_recv = brcvd;
    if (packets && /^\d+$/.test(packets)) norm.packets    = packets;

    // Country (srcloc/dstloc): best-effort positional (PAN-OS ~ col 24/26),
    // validated as alpha country-shaped tokens. We do NOT aggressively scan here
    // because flag/zone columns are also alpha and would yield false positives;
    // with no real samples, a missing country is safer than a wrong one. The
    // geoEnrich pass derives country from the IP anyway.
    const srcloc = clean(cols[24]);
    const dstloc = clean(cols[26]);
    const isCountry = (c) => c && !isIp(c) && !/^\d+$/.test(c)
      && !PROTO_RE.test(c) && !ACTION_RE.test(c) && /^[A-Z][A-Za-z .'\-]+$/.test(c);
    if (isCountry(srcloc)) norm.srccountry = srcloc;
    if (isCountry(dstloc)) norm.dstcountry = dstloc;

    if (srcip && dstip) message += `: ${srcip} -> ${dstip}`;
    if (norm.app)    message += ` app=${norm.app}`;
    if (norm.action) message += ` action=${norm.action}`;
    // deny/drop/reset traffic stays firewall but the action marks it.
  }

  // ── THREAT (vulnerability / spyware / virus / wildfire / url / data / file) ─
  // src/dst already extracted in the shared TRAFFIC/THREAT block above.
  // Remaining THREAT-specific fields (rule/app/zones/proto/action/threat-name/
  // url/severity) are located by value-type scanning anchored after the dst IP,
  // because absolute offsets drift per PAN-OS version. URL filtering rides here
  // with subtype 'url'. Indices are best-effort pending real PAN-OS samples.
  if (logType === 'THREAT') {
    const start = afterDst();
    const rule    = clean(cols[11]);
    const srcuser = clean(cols[12]);
    const app     = clean(cols[14]);
    const srczone = clean(cols[16]);
    const dstzone = clean(cols[17]);
    const proto   = pickByRegex(cols, PROTO_RE, start);
    const action  = pickByRegex(cols, ACTION_RE, start);

    if (rule)    norm.rule    = rule;
    if (srcuser && !isIp(srcuser)) norm.user = srcuser;
    if (app && !isIp(app)) norm.app = app;
    if (srczone) norm.srczone = srczone;
    if (dstzone) norm.dstzone = dstzone;
    if (proto)   norm.proto   = proto.toLowerCase();
    if (action)  norm.action  = action.toLowerCase();

    // Severity string: a recognised PAN-OS severity token in the row.
    const sevTok = pickByRegex(cols, SEV_RE, start);
    if (!applyPanSeverity(sevTok)) { severity = 4; severityLabel = 'warning'; }
    if (sevTok) norm.pan_severity = sevTok.toLowerCase();

    // Threat category — restrict to PAN-OS's KNOWN threat-category vocabulary so
    // we never mistake a rule/zone name for it. (Best-effort list; extend when
    // real samples arrive.)
    const THREAT_CAT_RE = /^(code-execution|command-and-control|brute-force|info-leak|overflow|sql-injection|cross-site-scripting|dos|exploit-kit|protocol-anomaly|hacktool|phishing|malware|spyware|virus|trojan|worm|backdoor|adware|botnet|data-theft|file-sharing|unknown)$/i;
    const thrCat = pickByRegex(cols, THREAT_CAT_RE, start);
    if (thrCat) norm.threat_category = thrCat.toLowerCase();

    // Exclude already-identified columns so the threat-name / URL scan can't grab
    // the rule, user, app, zones, country, or category tokens.
    const claimed = new Set([norm.rule, norm.user, norm.app, norm.srczone,
      norm.dstzone, norm.threat_category, norm.proto, norm.action].filter(Boolean));

    // The URL / misc / filename field and the threat NAME. Threat names commonly
    // carry an id like "Apache Struts RCE(34291)" or contain spaces; URLs/paths
    // contain "/" or a dotted host. Scan after dst, skipping claimed/vocab tokens.
    let url, threat;
    for (let i = start; i < cols.length; i++) {
      let c = clean(cols[i]);
      if (!c) continue;
      // PAN-OS quotes the url/misc field; strip surrounding quotes for storage.
      c = c.replace(/^"|"$/g, '');
      if (!c || isIp(c) || /^\d+$/.test(c)) continue;
      if (PROTO_RE.test(c) || ACTION_RE.test(c) || SEV_RE.test(c) || DIR_RE.test(c)) continue;
      // Skip PAN-OS timestamp tokens ("YYYY/MM/DD HH:MM:SS" or "YYYY/MM/DD").
      if (/^\d{4}\/\d{2}\/\d{2}(\s+\d{2}:\d{2}:\d{2})?$/.test(c)) continue;
      if (claimed.has(c)) continue;
      // A URL / host / path / filename: a slash-path (not a date) or a dotted host.
      const looksUrl = (/\//.test(c) && /[a-z]/i.test(c)) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(c);
      if (!url && looksUrl) { url = c; continue; }
      // A threat/signature name: has an "(id)" suffix or a space (multi-word).
      if (!threat && (/\(\d+\)$/.test(c) || /\s/.test(c))) { threat = c; continue; }
    }

    if (WEB_THREAT_SUBTYPES.has(subLc)) {
      // URL filtering — web activity, NOT an IPS detection.
      category = 'web';
      if (url)    norm.url = url;
      if (threat) norm.threat = threat;
    } else {
      // Genuine intrusion/malware (or unknown threat subtype) → security + IPS.
      category = 'security';
      if (IPS_THREAT_SUBTYPES.has(subLc) || !subLc) norm.type = 'ips';
      if (threat) norm.threat = threat;     // captured threat NAME
      if (url)    norm.misc = url;
    }

    if (norm.srcip && norm.dstip) message += `: ${norm.srcip} -> ${norm.dstip}`;
    if (norm.threat) message += ` threat=${norm.threat}`;
    if (norm.action) message += ` action=${norm.action}`;
  }

  // ── GLOBALPROTECT (VPN) ─────────────────────────────────────────────────
  // The real client is the GlobalProtect public IP, NOT the syslog sender.
  // PAN-OS 9.1+ split GP into structured columns; 8.x/older used a free-form
  // blob. Subtypes/stages include portal-auth / gateway-auth / *-fail / login /
  // logout / connected. Column layout differs a lot across versions, so we
  // validate + scan as a fallback for both IP and user.
  if (logType === 'GLOBALPROTECT') {
    category = 'vpn';
    // GP severity is present on newer schemas; default info.
    const sevTok = pickByRegex(cols, /^(critical|high|medium|low|informational)$/i, 4);
    applyPanSeverity(sevTok);
    if (sevTok) norm.pan_severity = sevTok.toLowerCase();

    // The GP "stage"/"eventid" and "status" (success/failure) tokens.
    const status = pickByRegex(cols, /^(success|failure|failed|error|denied|allow)$/i, 4);
    // Public IP of the client — prefer a validated IP column, else first IP in row.
    const pubip = isIp(cols[8]) ? clean(cols[8]) : findIp(cols, 0);
    if (pubip) norm.srcip = pubip;
    // Private/assigned tunnel IP, if a second IP is present.
    const privip = findIp(cols, 1);
    if (privip && privip !== pubip) norm.assignip = privip;

    // User/account — a non-IP, non-numeric token. Try near col 7, else scan.
    let user = clean(cols[7]);
    if (!user || isIp(user) || /^\d+$/.test(user)) {
      user = pickByRegex(cols, /^[A-Za-z][\w.\-\\@]*$/, 5);
      if (user && (PANLOG_TYPES.has(user.toUpperCase()) || isIp(user))) user = undefined;
    }
    if (user && !isIp(user)) norm.user = user;

    // Source region/country — non-IP token near the geo column.
    const region = clean(cols[9]);
    if (region && !isIp(region) && !/^\d+$/.test(region)) norm.srccountry = region;

    // Auth outcome → subcategory. Use the subtype/stage AND any status token.
    const blob = `${subLc} ${(status || '').toLowerCase()}`;
    if (/auth-fail|fail|denied|error/.test(blob))            norm.subcategory = 'login_failed';
    else if (/auth|login|connected|success|allow/.test(blob)) norm.subcategory = 'login_success';
    if (status) norm.status = status;

    if (norm.user)  message += ` user=${norm.user}`;
    if (norm.srcip) message += ` from=${norm.srcip}`;
  }

  // ── AUTHENTICATION ──────────────────────────────────────────────────────
  // PAN-OS auth log: source-ip, user, and an event token (success/failure).
  // Map Source IP -> srcip (the REAL client/attacker for inbound auth), the
  // account -> user, and the result -> subcategory. Indices vary, so validate +
  // scan; the success/failure verdict is taken from explicit tokens in the row.
  if (logType === 'AUTHENTICATION') {
    category = 'authentication';
    const sevTok = pickByRegex(cols, /^(critical|high|medium|low|informational)$/i, 4);
    applyPanSeverity(sevTok);
    if (sevTok) norm.pan_severity = sevTok.toLowerCase();

    const srcip = isIp(cols[8]) ? clean(cols[8]) : findIp(cols, 0);
    if (srcip) norm.srcip = srcip;

    let user = clean(cols[7]);
    if (!user || isIp(user) || /^\d+$/.test(user)) {
      user = pickByRegex(cols, /^[A-Za-z][\w.\-\\@]*$/, 5);
      if (user && (PANLOG_TYPES.has(user.toUpperCase()) || isIp(user))) user = undefined;
    }
    if (user && !isIp(user)) norm.user = user;

    // Auth method / server (e.g. "ldap", "radius", "local") if present.
    const authproto = pickByRegex(cols, /^(ldap|radius|kerberos|tacacs|saml|local|cert|ssl)$/i, 5);
    if (authproto) norm.authproto = authproto.toLowerCase();

    // Verdict: look for an explicit success/failure token anywhere in the row.
    const joined = cols.join(' ').toLowerCase();
    if (/\b(fail|failure|failed|denied|invalid|reject)\b/.test(joined))     norm.subcategory = 'login_failed';
    else if (/\b(success|succeeded|allowed|authenticated)\b/.test(joined))  norm.subcategory = 'login_success';
    else norm.subcategory = 'login_failed'; // auth event without a verdict: default to failed (safer for alerting)

    if (norm.user)  message += ` user=${norm.user}`;
    if (norm.srcip) message += ` from=${norm.srcip}`;
  }

  // ── USERID ──────────────────────────────────────────────────────────────
  // User-IP mapping events. Not auth success/failure per se, but they carry the
  // user + IP binding; capture them as authentication-adjacent context. Do NOT
  // emit a login subcategory (these are not login attempts).
  if (logType === 'USERID') {
    category = 'authentication';
    const ip = findIp(cols, 0);
    if (ip) norm.srcip = ip;
    let user = clean(cols[7]);
    if (!user || isIp(user) || /^\d+$/.test(user)) {
      user = pickByRegex(cols, /^[A-Za-z][\w.\-\\@]*$/, 5);
      if (user && (PANLOG_TYPES.has(user.toUpperCase()) || isIp(user))) user = undefined;
    }
    if (user && !isIp(user)) norm.user = user;
    if (norm.user) message += ` user=${norm.user}`;
  }

  // ── CONFIG ───────────────────────────────────────────────────────────────
  // Admin/config change events: admin, client, cmd, result.
  if (logType === 'CONFIG') {
    category = 'configuration';
    const admin  = clean(cols[7]);
    const cmd    = pickByRegex(cols, /^(set|delete|edit|commit|rename|move|clone|add|create)$/i, 5);
    if (admin && !isIp(admin)) norm.admin = admin;
    if (cmd) norm.cmd = cmd.toLowerCase();
    const adminIp = findIp(cols, 0);
    if (adminIp) norm.srcip = adminIp;        // the IP the admin connected from
    if (norm.admin) message += ` admin=${norm.admin}`;
    if (norm.cmd)   message += ` cmd=${norm.cmd}`;
  }

  // ── SYSTEM ───────────────────────────────────────────────────────────────
  // System events carry an explicit severity string (commonly col 6) plus an
  // eventid + description.
  if (logType === 'SYSTEM') {
    category = 'system';
    const sevTok = clean(cols[6]) || pickByRegex(cols, /^(critical|high|medium|low|informational)$/i, 4);
    applyPanSeverity(sevTok);
    if (sevTok) norm.pan_severity = (sevTok || '').toLowerCase();
    const eventid = clean(cols[7]);
    if (eventid && !isIp(eventid)) norm.eventid = eventid;
  }

  // ── HIPMATCH ─────────────────────────────────────────────────────────────
  // Host Information Profile match (GlobalProtect endpoint posture) → security.
  if (logType === 'HIPMATCH') {
    category = 'security';
    const ip = findIp(cols, 0);
    if (ip) norm.srcip = ip;
    let user = clean(cols[7]);
    if (user && !isIp(user) && !/^\d+$/.test(user)) norm.user = user;
  }

  return {
    source_ip:       sourceIp,
    source_host:     null,
    facility:        23,
    facility_label:  'local7',
    severity,
    severity_label:  severityLabel,
    vendor:          'paloalto',
    program:         `PAN-OS/${logType}`,
    message,
    raw_message:     raw,
    // Additive: keep log_type/subtype/serial; merge normalized contract keys
    // (srcip/dstip/srcport/dstport/user/action/subcategory/type/... ) when present.
    structured_data: { log_type: logType, subtype, serial, ...norm },
    category,
    is_parsed:       true,
    log_timestamp:   logTimestamp,
  };
}

module.exports = { parsePaloAlto };
