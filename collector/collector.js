/**
 * LogVault Collector Service
 * Syslog receiver on UDP/TCP ports 514 and 1514
 * Parses, normalizes, writes to PostgreSQL
 * Evaluates alert rules AND correlation engine in real time
 */

'use strict';

const dgram    = require('dgram');
const net      = require('net');
const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const { parseGeneric }  = require('../parsers/generic');
const { parseCisco }    = require('../parsers/cisco');
const { parsePaloAlto } = require('../parsers/paloalto');
const { parseFortinet } = require('../parsers/fortinet');
const { parseAruba }    = require('../parsers/aruba');
const { parseSangfor }  = require('../parsers/sangfor');
const { parseForcepoint, detectForcepoint } = require('../parsers/forcepoint');
const { parseCheckPoint, detectCheckPoint } = require('../parsers/checkpoint');
const { parseJuniper, detectJuniper }       = require('../parsers/juniper');
const { parseWindows, detectWindows }       = require('../parsers/windows');
const { parseSonicWall, detectSonicWall }   = require('../parsers/sonicwall');
const { getCategory } = require('./taxonomy');
const { scoreLog }    = require('./riskScorer');
const { evaluateCorrelation } = require('./correlationEngine');
const { syncFromNetVault }    = require('./netvaultSync');
const { enrichIP, configureDNS } = require('./dnsLookup');
const { sendAlertEmail }         = require('./emailer');

// IPs seen this session — avoid re-enriching same IP repeatedly
const seenIPs = new Set();

// DNS settings cache — reloaded every 5 minutes
let dnsSettings = { enabled: true, server: '' };
let dnsSettingsLoadedAt = 0;
const DNS_SETTINGS_TTL = 5 * 60 * 1000; // 5 minutes

async function getDNSSettings() {
  const now = Date.now();
  if (now - dnsSettingsLoadedAt < DNS_SETTINGS_TTL) return dnsSettings;
  try {
    const { rows } = await pool.query(
      `SELECT key, value FROM app_settings WHERE key IN ('dns_server', 'dns_lookup_enabled')`
    );
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const newServer  = s.dns_server || '';
    const newEnabled = s.dns_lookup_enabled !== 'false';
    // Reconfigure DNS server if changed
    if (newServer !== dnsSettings.server) {
      configureDNS(newServer);
      console.log(`[DNS] Server updated to: ${newServer || 'system default'}`);
    }
    dnsSettings = { enabled: newEnabled, server: newServer };
    dnsSettingsLoadedAt = now;
  } catch {}
  return dnsSettings;
}

// ── Ingestion guard settings (allow-list + rate limit) ────────
// Both DEFAULT PERMISSIVE so this never drops live traffic unless an
// operator opts in. Reloaded every 5 minutes from app_settings (no restart).
let ingestSettings = {
  allowedSources: [],      // parsed allow-list rules; [] = allow ALL
  rateLimitEnabled: false, // disabled by default
  rateLimitPps: 0,         // 0 = unlimited (sentinel)
};
let ingestSettingsLoadedAt = 0;
const INGEST_SETTINGS_TTL = 5 * 60 * 1000; // 5 minutes

// Parse a comma-separated allow-list string into matcher rules.
// Supports plain IPv4 ("10.0.0.1") and CIDR ("10.0.0.0/8").
// Returns an array of rule objects; an empty array means "allow all".
function parseAllowList(raw) {
  if (!raw || !String(raw).trim()) return [];
  const rules = [];
  for (const tokenRaw of String(raw).split(',')) {
    const token = tokenRaw.trim();
    if (!token) continue;
    const slash = token.indexOf('/');
    if (slash !== -1) {
      const base = ipToInt(token.slice(0, slash));
      const bits = parseInt(token.slice(slash + 1), 10);
      if (base === null || isNaN(bits) || bits < 0 || bits > 32) continue;
      // mask of `bits` high bits set (>>> 0 to keep unsigned; bits=0 → 0)
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      rules.push({ network: (base & mask) >>> 0, mask });
    } else {
      const ip = ipToInt(token);
      if (ip === null) continue;
      rules.push({ network: ip, mask: 0xffffffff });
    }
  }
  return rules;
}

// IPv4 dotted-quad → unsigned 32-bit int, or null if not a valid IPv4.
function ipToInt(ip) {
  if (!ip) return null;
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = parseInt(p, 10);
    if (n > 255) return null;
    val = (val << 8) | n;
  }
  return val >>> 0;
}

// True if sourceIp is permitted by the current allow-list.
// Empty allow-list → always true (permissive default).
function isAllowedSource(sourceIp) {
  const rules = ingestSettings.allowedSources;
  if (!rules.length) return true;
  const ip = ipToInt(sourceIp);
  if (ip === null) return true; // non-IPv4 (e.g. IPv6) — don't drop, fail open
  for (const r of rules) {
    if (((ip & r.mask) >>> 0) === r.network) return true;
  }
  return false;
}

async function getIngestSettings() {
  const now = Date.now();
  if (now - ingestSettingsLoadedAt < INGEST_SETTINGS_TTL) return ingestSettings;
  try {
    const { rows } = await pool.query(
      `SELECT key, value FROM app_settings
       WHERE key IN ('collector_allowed_sources','collector_rate_limit_enabled','collector_rate_limit_pps')`
    );
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    ingestSettings = {
      allowedSources:   parseAllowList(s.collector_allowed_sources),
      rateLimitEnabled: s.collector_rate_limit_enabled === 'true',
      rateLimitPps:     Math.max(0, parseInt(s.collector_rate_limit_pps || '0', 10) || 0),
    };
    ingestSettingsLoadedAt = now;
  } catch {}
  return ingestSettings;
}

// ── Per-source sliding-window rate limiter (1-second buckets) ──
// Map: sourceIp → { sec: epochSecond, count: packetsThisSecond }
const rateBuckets = new Map();

// Returns true if the packet should be dropped due to rate limit.
function isRateLimited(sourceIp) {
  if (!ingestSettings.rateLimitEnabled) return false;
  const pps = ingestSettings.rateLimitPps;
  if (!pps || pps <= 0) return false; // 0 = unlimited
  const sec = Math.floor(Date.now() / 1000);
  let b = rateBuckets.get(sourceIp);
  if (!b || b.sec !== sec) {
    b = { sec, count: 0 };
    rateBuckets.set(sourceIp, b);
  }
  b.count++;
  return b.count > pps;
}

// Drop counters — logged in aggregate, never per-packet (avoids spam).
let droppedByAllowList = 0;
let droppedByRateLimit = 0;

// ── Crash resilience ──────────────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught exception:', err.message, err.stack);
  flushBuffer().catch(() => {}).finally(() => process.exit(1));
});
process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled rejection:', reason);
});

// ── DB pool ───────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME  || 'logvault',
  user:     process.env.LV_DB_USER  || 'logvault_user',
  password: process.env.LV_DB_PASS,
  max:      10,
  idleTimeoutMillis: 30000,
});

// ── Write buffer ──────────────────────────────────────────────
const BATCH_SIZE     = 100;
const BATCH_INTERVAL = 2000;
let buffer      = [];
let retryBuffer = []; // Holds failed batches for retry
let flushTimer  = null;

async function flushBuffer() {
  // Combine retry buffer with current buffer
  const toFlush = [...retryBuffer, ...buffer.splice(0, buffer.length)];
  retryBuffer = [];
  if (toFlush.length === 0) return;

  const values = [];
  const params = [];
  let p = 1;

  for (const row of toFlush) {
    values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
    params.push(
      row.received_at, row.log_timestamp, row.source_ip, row.source_host,
      row.facility, row.severity, row.severity_label, row.facility_label,
      row.vendor, row.program, row.message, row.raw_message,
      JSON.stringify(row.structured_data || {}), row.is_parsed,
      row.category || null, row.risk_score || 0
    );
  }

  try {
    await pool.query(`
      INSERT INTO syslog_entries
        (received_at, log_timestamp, source_ip, source_host, facility, severity,
         severity_label, facility_label, vendor, program, message, raw_message,
         structured_data, is_parsed, category, risk_score)
      VALUES ${values.join(',')}
    `, params);
  } catch (err) {
    console.error(`[DB] Flush error (${toFlush.length} rows): ${err.message}`);
    // Move failed batch to retry buffer — will retry on next flush
    // Cap retry buffer at 1000 rows to avoid unbounded memory growth
    retryBuffer = [...toFlush, ...retryBuffer].slice(0, 1000);
    console.error(`[DB] ${retryBuffer.length} rows queued for retry`);
  }
}

function enqueue(entry) {
  buffer.push(entry);
  if (buffer.length >= BATCH_SIZE) flushBuffer();
}

// ── Collector-side log filter ─────────────────────────────────
function shouldDrop(entry) {
  const severity = entry.severity;
  const vendor   = entry.vendor;
  const msg      = (entry.message || '') + ' ' + (entry.raw_message || '');

  // ── FORTINET ─────────────────────────────────────────────────
  if (vendor === 'fortinet') {
    // Always keep warning and above (0-4)
    if (severity <= 4) return false;

    const sd = entry.structured_data || {};

    // Always keep UTM logs (IPS, webfilter, app-ctrl, antivirus)
    if (sd.type === 'utm' || /utm\//i.test(msg) || /type=utm/i.test(msg)) return false;

    // Always keep event logs (VPN, auth, system, config)
    if (sd.type === 'event' || /event\//i.test(msg) || /type=event/i.test(msg)) return false;

    // Always keep IPS/threat logs regardless of format
    if (sd.subtype === 'ips' || /subtype=ips/i.test(msg) || /utm\/ips/i.test(msg)) return false;

    // Always keep VPN logs regardless of format
    if (sd.subtype === 'vpn' || /subtype=vpn/i.test(msg) || /ssl.vpn/i.test(msg) || /ipsec/i.test(msg)) return false;

    // Always keep denied/blocked traffic
    if (sd.action === 'deny' || /action=(deny|block|drop|reset)/i.test(msg)) return false;

    // Drop routine traffic accepts, closes, timeouts at notice/info
    if (/traffic\/(forward|local|multicast)/i.test(msg) ||
        sd.type === 'traffic') {
      if (/action=(accept|close|timeout|server-rst|client-rst|passthrough|ip-conn|dns)/i.test(msg)) {
        return true;
      }
    }

    return false;
  }

  // ── CISCO ─────────────────────────────────────────────────────
  if (vendor === 'cisco') {
    // Always keep warning and above (0-4)
    if (severity <= 4) return false;
    // Keep security-relevant mnemonics regardless of severity
    const securityPatterns = [
      /SEC_LOGIN/i, /AAA/i, /MACFLAP/i, /SPANTREE/i, /STORM_CONTROL/i,
      /OSPF/i, /BGP/i, /EIGRP/i, /CONFIG_I/i, /LINK.*UPDOWN/i,
      /LINEPROTO/i, /SYS-\d-(RESTART|RELOAD)/i, /DUAL-\d-NBRCHANGE/i,
    ];
    if (securityPatterns.some(p => p.test(msg))) return false;
    // Drop routine info/notice/debug
    if (severity >= 5) return true;
    return false;
  }

  // ── PALO ALTO ─────────────────────────────────────────────────
  if (vendor === 'paloalto') {
    if (severity <= 4) return false;
    if (/THREAT|SYSTEM|GLOBALPROTECT|AUTHENTICATION/i.test(msg)) return false;
    if (/action=(deny|block|drop|reset)/i.test(msg)) return false;
    if (/TRAFFIC/i.test(msg) && /action=(allow|accept)/i.test(msg)) return true;
    return false;
  }

  // ── ARUBA ─────────────────────────────────────────────────────
  if (vendor === 'aruba') {
    if (severity <= 4) return false;
    if (/auth|802\.1x|association|deauth|radius/i.test(msg)) return false;
    if (severity >= 5) return true;
    return false;
  }

  // ── SANGFOR ───────────────────────────────────────────────────
  if (vendor === 'sangfor') {
    if (severity <= 4) return false;
    if (severity >= 5) return true;
    return false;
  }

  // ── GENERIC / UNKNOWN ─────────────────────────────────────────
  // Drop only debug (7)
  if (severity >= 7) return true;
  return false;
}

// ── Parser chain ─────────────────────────────────────────────
// Order matters — most specific vendors first, generic last.
// Entries with a `detect` run it before `parse` (fast boolean guard);
// legacy parsers self-detect by returning null when they don't match.
const PARSERS = [
  { parse: parseFortinet },
  { parse: parseCisco },
  { parse: parsePaloAlto },
  { parse: parseAruba },
  { parse: parseSangfor },
  { detect: detectForcepoint, parse: parseForcepoint },
  { detect: detectCheckPoint, parse: parseCheckPoint },
  { detect: detectJuniper,    parse: parseJuniper },
  { detect: detectWindows,    parse: parseWindows },
  { detect: detectSonicWall,  parse: parseSonicWall },
  { parse: parseGeneric },
];

// Ensure every parsed entry has the fields the DB writer expects.
// Some parsers (e.g. Forcepoint CEF) omit transport-level fields.
function normalizeEntry(entry, raw, sourceIp) {
  if (!entry.source_ip)               entry.source_ip = sourceIp;
  if (entry.source_host === undefined) entry.source_host = null;
  if (entry.facility == null)          entry.facility = 23;
  if (entry.facility_label == null)    entry.facility_label = 'local7';
  if (entry.raw_message == null)       entry.raw_message = raw;
  if (entry.log_timestamp === undefined) entry.log_timestamp = null;
  if (!entry.structured_data)          entry.structured_data = {};
  return entry;
}

function processMessage(rawMsg, sourceIp) {
  // ── Ingestion guard (allow-list + rate limit) ──
  // Both default-permissive; settings are cached so this is cheap per packet.
  if (!isAllowedSource(sourceIp)) { droppedByAllowList++; return; }
  if (isRateLimited(sourceIp))    { droppedByRateLimit++; return; }

  const raw = rawMsg.toString('utf8').trim();
  if (!raw) return;

  let entry = null;
  for (const p of PARSERS) {
    try {
      if (p.detect && !p.detect(raw)) continue;
      entry = p.parse(raw, sourceIp);
      if (entry) break;
    } catch (_) {}
  }

  if (!entry) {
    entry = {
      source_ip: sourceIp, source_host: null, facility: 1, severity: 6,
      severity_label: 'info', facility_label: 'user', vendor: 'unknown',
      program: null, message: raw, raw_message: raw, structured_data: {},
      is_parsed: false, log_timestamp: null,
    };
  }

  normalizeEntry(entry, raw, sourceIp);

  // ── Universal taxonomy + risk scoring ──
  entry.structured_data.category = getCategory(entry.vendor, entry.structured_data, entry.message);
  entry.category   = entry.structured_data.category || 'network';
  entry.risk_score = scoreLog(entry);

  entry.received_at = new Date();

  // Drop high-volume low-value logs before writing to DB
  if (shouldDrop(entry)) return;

  enqueue(entry);

  // DNS reverse lookup for new IPs — best effort, non-blocking
  const ipKey = entry.source_ip;
  if (ipKey && !seenIPs.has(ipKey)) {
    seenIPs.add(ipKey);
    if (seenIPs.size > 10000) seenIPs.clear();
    getDNSSettings().then(s => {
      if (s.enabled) enrichIP(ipKey, pool).catch(() => {});
    });
  }

  // Run alert rules for medium+ severity
  if (entry.severity <= 4) {
    checkAlertRules(entry).catch(err => console.error('[Alert] Rule check error:', err.message));
  }

  // Run correlation engine for all events
  evaluateCorrelation(entry, pool).catch(err => console.error('[Correlation] Error:', err.message));
}

// ── Alert Rule Evaluation ─────────────────────────────────────
let alertRulesCache = [];
let lastRulesFetch  = 0;

async function getAlertRules() {
  const now = Date.now();
  if (now - lastRulesFetch > 30000) {
    try {
      const { rows } = await pool.query('SELECT * FROM alert_rules WHERE is_enabled = TRUE');
      alertRulesCache = rows;
      lastRulesFetch  = now;
    } catch (err) { console.error('[Alert] Failed to fetch rules:', err.message); }
  }
  return alertRulesCache;
}

const recentEvents = new Map();
// Suppression map — tracks last fired time per rule+source to prevent duplicate alerts
// Key: ruleId__sourceIp, Value: timestamp last fired
const suppressionMap = new Map();
const THRESHOLD_SUPPRESSION_MS = 30 * 60 * 1000; // 30 min suppression per rule+source

async function checkAlertRules(entry) {
  const rules = await getAlertRules();
  const correlationRuleNames = new Set([
    'Brute Force Login Success', 'Port Scan Detected', 'Interface Flapping Detected',
    'Network Loop Detected', 'After-Hours Configuration Change', 'STP Instability Detected',
    'Repeated IPS Triggers', 'VPN Brute Force Attempt',
  ]);

  for (const rule of rules) {
    // Skip correlation rules — handled by correlationEngine
    if (correlationRuleNames.has(rule.name)) continue;

    if (rule.match_severity?.length && !rule.match_severity.includes(entry.severity)) continue;
    if (rule.match_vendor?.length   && !rule.match_vendor.includes(entry.vendor))     continue;
    if (rule.match_host) {
      try {
        const pattern = rule.match_host.replace(/%/g, '.*');
        if (!new RegExp(pattern, 'i').test(entry.source_host || entry.source_ip || '')) continue;
      } catch (_) { continue; }
    }
    if (rule.match_pattern) {
      try { if (!new RegExp(rule.match_pattern, 'i').test(entry.message)) continue; } catch (_) { continue; }
    }

    const windowMs = parseIntervalMs(rule.threshold_window);
    const now      = Date.now();
    const key      = rule.id;

    if (!recentEvents.has(key)) recentEvents.set(key, []);
    const hits  = recentEvents.get(key);
    hits.push(now);
    const fresh = hits.filter(t => t > now - windowMs);
    recentEvents.set(key, fresh);

    if (fresh.length >= rule.threshold_count) {
      // Check suppression — don't re-fire same rule for same source within suppression window
      const sourceKey     = `${rule.id}__${entry.source_ip || 'any'}`;
      const lastFired     = suppressionMap.get(sourceKey) || 0;
      if (now - lastFired < THRESHOLD_SUPPRESSION_MS) {
        console.log(`[Alert] Rule "${rule.name}" suppressed for ${entry.source_ip} (cooldown active)`);
        continue;
      }
      suppressionMap.set(sourceKey, now);
      await fireAlert(rule, entry, fresh.length);
    }
  }
}

function parseIntervalMs(interval) {
  if (!interval) return 300000;
  if (typeof interval === 'object') {
    return ((interval.hours || 0) * 3600 + (interval.minutes || 0) * 60 + (interval.seconds || 0)) * 1000;
  }
  const str = String(interval);
  const hms = str.match(/(\d+):(\d+):(\d+)/);
  if (hms) return (parseInt(hms[1]) * 3600 + parseInt(hms[2]) * 60 + parseInt(hms[3])) * 1000;
  const mins = str.match(/(\d+)\s*min/i);
  if (mins) return parseInt(mins[1]) * 60000;
  const secs = str.match(/(\d+)\s*sec/i);
  if (secs) return parseInt(secs[1]) * 1000;
  return 300000;
}

async function fireAlert(rule, entry, matchCount) {
  try {
    // Check if there's already an open (unacknowledged) alert for this rule + source
    const existing = await pool.query(`
      SELECT id, match_count FROM alert_events
      WHERE rule_id = $1
        AND acknowledged = FALSE
        AND source_ip = $2
        AND fired_at > NOW() - INTERVAL '2 hours'
      ORDER BY fired_at DESC
      LIMIT 1
    `, [rule.id, entry.source_ip]);

    if (existing.rows.length > 0) {
      // Update existing alert — increment count, update sample message
      await pool.query(`
        UPDATE alert_events
        SET match_count   = match_count + $1,
            sample_message = $2,
            fired_at       = NOW()
        WHERE id = $3
      `, [matchCount, entry.message.substring(0, 500), existing.rows[0].id]);
      console.log(`[Alert] Rule "${rule.name}" updated existing alert — ${entry.source_host || entry.source_ip}`);
    } else {
      // Insert new alert
      await pool.query(`
        INSERT INTO alert_events (rule_id, source_host, source_ip, match_count, sample_message)
        VALUES ($1, $2, $3, $4, $5)
      `, [rule.id, entry.source_host || null, entry.source_ip, matchCount, entry.message.substring(0, 500)]);
      console.log(`[Alert] Rule "${rule.name}" fired — ${entry.source_host || entry.source_ip}`);
    }

    // Send email notification (best-effort — never blocks alert firing).
    // The emailer applies the global notification filters and resolves
    // recipients (per-rule notify_email + global recipients), so we always
    // call it and let it decide whether an email actually goes out.
    sendAlertEmail(rule, entry, matchCount, pool).catch(err =>
      console.error('[Alert] Email notify error:', err.message));
  } catch (err) { console.error('[Alert] Failed to insert/update alert event:', err.message); }
}

// ── UDP Server ────────────────────────────────────────────────
function startUDP(port) {
  const server = dgram.createSocket('udp4');
  server.on('message', (msg, rinfo) => processMessage(msg, rinfo.address));
  server.on('error',   err => console.error(`[UDP:${port}]`, err.message));
  server.bind(port,    ()  => console.log(`[UDP] Listening on port ${port}`));
  return server;
}

// ── TCP Server ────────────────────────────────────────────────
function startTCP(port) {
  const server = net.createServer(socket => {
    let leftover = '';
    socket.on('data', data => {
      const text  = leftover + data.toString('utf8');
      const lines = text.split('\n');
      leftover    = lines.pop();
      for (const line of lines) { if (line.trim()) processMessage(Buffer.from(line), socket.remoteAddress); }
    });
    socket.on('end',   () => { if (leftover.trim()) processMessage(Buffer.from(leftover), socket.remoteAddress); });
    socket.on('error', err => { if (err.code !== 'ECONNRESET') console.error(`[TCP:${port}]`, err.message); });
  });
  server.on('error', err => console.error(`[TCP:${port}]`, err.message));
  server.listen(port, () => console.log(`[TCP] Listening on port ${port}`));
  return server;
}

// ── Startup ───────────────────────────────────────────────────
async function main() {
  console.log('LogVault Collector starting...');
  try {
    await pool.query('SELECT 1');
    console.log('[DB] Connected to logvault database');
  } catch (err) {
    console.error('[DB] Connection failed:', err.message);
    process.exit(1);
  }

  startUDP(514); startUDP(1514);
  startTCP(514); startTCP(1514);

  flushTimer = setInterval(flushBuffer, BATCH_INTERVAL);
  await getAlertRules();

  // Prime ingestion-guard settings + keep the cache warm (5-min TTL).
  await getIngestSettings();
  setInterval(() => { getIngestSettings().catch(() => {}); }, INGEST_SETTINGS_TTL);

  // Aggregate drop visibility — log every 60s only when something was dropped
  // (avoids per-packet spam). Also prunes stale rate-limit buckets.
  setInterval(() => {
    if (droppedByAllowList || droppedByRateLimit) {
      console.log(`[Ingest] Dropped in last 60s — allow-list: ${droppedByAllowList}, rate-limit: ${droppedByRateLimit}`);
      droppedByAllowList = 0;
      droppedByRateLimit = 0;
    }
    // Prune rate buckets older than the current second to cap memory.
    const sec = Math.floor(Date.now() / 1000);
    for (const [ip, b] of rateBuckets) { if (b.sec < sec) rateBuckets.delete(ip); }
  }, 60 * 1000);

  // Sync NetVault assets immediately then every 15 minutes
  syncFromNetVault(pool).catch(err => console.error('[NetVaultSync] Initial sync error:', err.message));
  setInterval(() => {
    syncFromNetVault(pool).catch(err => console.error('[NetVaultSync] Sync error:', err.message));
  }, 15 * 60 * 1000);

  console.log('LogVault Collector running. Listening on ports 514 and 1514 (UDP+TCP).');
  console.log('[Correlation] Engine loaded with 8 rules');

  const shutdown = async () => {
    console.log('[Collector] Shutting down gracefully...');
    clearInterval(flushTimer);
    await flushBuffer();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT',  shutdown);
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
