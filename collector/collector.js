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
const { evaluateCorrelation } = require('./correlationEngine');
const { syncFromNetVault }    = require('./netvaultSync');
const { enrichIP, configureDNS } = require('./dnsLookup');

// IPs seen this session — avoid re-enriching same IP repeatedly
const seenIPs = new Set();

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
    values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
    params.push(
      row.received_at, row.log_timestamp, row.source_ip, row.source_host,
      row.facility, row.severity, row.severity_label, row.facility_label,
      row.vendor, row.program, row.message, row.raw_message,
      JSON.stringify(row.structured_data || {}), row.is_parsed
    );
  }

  try {
    await pool.query(`
      INSERT INTO syslog_entries
        (received_at, log_timestamp, source_ip, source_host, facility, severity,
         severity_label, facility_label, vendor, program, message, raw_message,
         structured_data, is_parsed)
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
const PARSERS = [parseCisco, parsePaloAlto, parseFortinet, parseAruba, parseSangfor, parseGeneric];

function processMessage(rawMsg, sourceIp) {
  const raw = rawMsg.toString('utf8').trim();
  if (!raw) return;

  let entry = null;
  for (const parser of PARSERS) {
    try { entry = parser(raw, sourceIp); if (entry) break; } catch (_) {}
  }

  if (!entry) {
    entry = {
      source_ip: sourceIp, source_host: null, facility: 1, severity: 6,
      severity_label: 'info', facility_label: 'user', vendor: 'unknown',
      program: null, message: raw, raw_message: raw, structured_data: {},
      is_parsed: false, log_timestamp: null,
    };
  }

  entry.received_at = new Date();

  // Drop high-volume low-value logs before writing to DB
  if (shouldDrop(entry)) return;

  enqueue(entry);

  // DNS reverse lookup for new IPs — best effort, non-blocking
  const ipKey = entry.source_ip;
  if (ipKey && !seenIPs.has(ipKey) && dnsLookupEnabled) {
    seenIPs.add(ipKey);
    // Limit seenIPs size to avoid unbounded memory
    if (seenIPs.size > 10000) seenIPs.clear();
    enrichIP(ipKey, pool).catch(() => {});
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

    if (fresh.length === rule.threshold_count) {
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

  // Load DNS settings from app_settings
  let dnsLookupEnabled = true;
  try {
    const { rows } = await pool.query(`SELECT key, value FROM app_settings WHERE key IN ('dns_server', 'dns_lookup_enabled')`);
    const settings  = Object.fromEntries(rows.map(r => [r.key, r.value]));
    dnsLookupEnabled = settings.dns_lookup_enabled !== 'false';
    if (settings.dns_server) configureDNS(settings.dns_server);
    console.log(`[DNS] Lookup ${dnsLookupEnabled ? 'enabled' : 'disabled'}${settings.dns_server ? ` — server: ${settings.dns_server}` : ' — using system DNS'}`);
  } catch (err) {
    console.error('[DNS] Failed to load settings:', err.message);
  }

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
