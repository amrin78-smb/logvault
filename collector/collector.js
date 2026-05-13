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
let buffer     = [];
let flushTimer = null;

async function flushBuffer() {
  if (buffer.length === 0) return;
  const batch = buffer.splice(0, buffer.length);
  const values = [];
  const params = [];
  let p = 1;

  for (const row of batch) {
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
    console.error('[DB] Flush error:', err.message);
  }
}

function enqueue(entry) {
  buffer.push(entry);
  if (buffer.length >= BATCH_SIZE) flushBuffer();
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
  enqueue(entry);

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
    } catch (err) {
      console.error('[Alert] Failed to fetch rules:', err.message);
    }
  }
  return alertRulesCache;
}

const recentEvents = new Map();

async function checkAlertRules(entry) {
  const rules = await getAlertRules();

  for (const rule of rules) {
    // Skip correlation rules managed by the correlation engine
    if (['Brute Force Login Success','Port Scan Detected','Interface Flapping Detected',
         'Network Loop Detected','After-Hours Configuration Change','STP Instability Detected',
         'Repeated IPS Triggers','VPN Brute Force Attempt'].includes(rule.name)) continue;

    if (rule.match_severity?.length && !rule.match_severity.includes(entry.severity)) continue;
    if (rule.match_vendor?.length   && !rule.match_vendor.includes(entry.vendor))     continue;
    if (rule.match_host) {
      const pattern = rule.match_host.replace(/%/g, '.*');
      if (!new RegExp(pattern, 'i').test(entry.source_host || entry.source_ip || '')) continue;
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
    await pool.query(`
      INSERT INTO alert_events (rule_id, source_host, source_ip, match_count, sample_message)
      VALUES ($1, $2, $3, $4, $5)
    `, [rule.id, entry.source_host || null, entry.source_ip, matchCount, entry.message.substring(0, 500)]);
    console.log(`[Alert] Rule "${rule.name}" fired — ${entry.source_host || entry.source_ip}`);
  } catch (err) {
    console.error('[Alert] Failed to insert alert event:', err.message);
  }
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

  console.log('LogVault Collector running. Listening on ports 514 and 1514 (UDP+TCP).');
  console.log('[Correlation] Engine loaded with', require('./correlationEngine').evaluateCorrelation ? 8 : 0, 'rules');

  const shutdown = async () => {
    clearInterval(flushTimer);
    await flushBuffer();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT',  shutdown);
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
