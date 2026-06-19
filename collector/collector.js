/**
 * LogVault Collector Service
 * Syslog receiver on UDP/TCP ports 514 and 1514
 * Parses, normalizes, writes to PostgreSQL
 * Evaluates alert rules AND correlation engine in real time
 */

'use strict';

const dgram    = require('dgram');
const net      = require('net');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');
const { Pool } = require('pg');
// Load .env.local by EXPLICIT path (relative to THIS file, not process.cwd()),
// so DB creds + LOG_INTEGRITY_KEY load regardless of the NSSM AppDirectory.
// override:false (the default) keeps NSSM AppEnvironmentExtra vars authoritative.
require('dotenv').config({ path: path.join(__dirname, '..', '.env.local'), override: false });

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
const { runCleanup }          = require('../scripts/cleanup');
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

// ── Tamper-evident hash chain (integrity) ─────────────────────
// HMAC-SHA256 chain over immutable fields of each entry. The chain links
// each row to the previous via prev_hash, so any insert/edit/delete of an
// in-between row is detectable by scripts/verify-integrity.js.
//
// Key from LOG_INTEGRITY_KEY. If unset, integrity is DISABLED (both columns
// stored NULL) so installs without the key keep working.
const INTEGRITY_KEY     = process.env.LOG_INTEGRITY_KEY || null;
const INTEGRITY_ENABLED = !!INTEGRITY_KEY;
let lastHash = null; // Buffer of the last entry_hash, or null at chain start

// Build the canonical string for an entry. MUST match scripts/verify-integrity.js
// EXACTLY (field order, '|' join, ISO received_at, '' for null/undefined).
function canonicalString(entry) {
  let receivedAt = entry.received_at;
  if (receivedAt instanceof Date) receivedAt = receivedAt.toISOString();
  else if (receivedAt == null)    receivedAt = '';
  else                            receivedAt = String(receivedAt);
  const fields = [
    receivedAt,
    entry.source_ip,
    entry.severity,
    entry.vendor,
    entry.message,
    entry.raw_message,
  ];
  return fields.map(f => (f == null ? '' : String(f))).join('|');
}

// Compute entry_hash (Buffer) from prevHash (Buffer|null) + canonical fields.
function computeEntryHash(prevHash, entry) {
  const prevHex = prevHash ? prevHash.toString('hex') : '';
  return crypto.createHmac('sha256', INTEGRITY_KEY)
    .update(prevHex + '|' + canonicalString(entry))
    .digest();
}

// Stamp prev_hash + entry_hash onto an entry and advance the chain.
// No-op (NULL hashes) when integrity is disabled.
function applyHashChain(entry) {
  if (!INTEGRITY_ENABLED) {
    entry.prev_hash  = null;
    entry.entry_hash = null;
    return;
  }
  const h = computeEntryHash(lastHash, entry);
  entry.prev_hash  = lastHash;
  entry.entry_hash = h;
  lastHash = h;
}

// Resume the chain across restarts from the most recent persisted hash.
async function initHashChain() {
  if (!INTEGRITY_ENABLED) {
    console.warn('[Integrity] LOG_INTEGRITY_KEY not set — hash chain disabled');
    return;
  }
  try {
    const { rows } = await pool.query(
      `SELECT entry_hash FROM syslog_entries WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`
    );
    lastHash = rows.length ? rows[0].entry_hash : null;
    console.log(`[Integrity] Hash chain enabled — ${lastHash ? 'resumed from existing chain' : 'starting fresh chain'}`);
  } catch (err) {
    console.error('[Integrity] Failed to load last hash, starting fresh:', err.message);
    lastHash = null;
  }
}

// ── Durable disk spool (write-ahead log) ──────────────────────
// Every enqueued entry is appended (NDJSON) to the active spool segment
// BEFORE it enters the in-memory buffer, so nothing is lost on crash/DB
// outage across a restart. Segments are unlinked once all their entries
// are confirmed flushed to the DB. fsync is periodic (via the flush timer),
// so a hard kill may lose at most the last sub-second of un-fsynced lines.
const SPOOL_DIR      = process.env.SPOOL_DIR || path.join(__dirname, '..', 'logs', 'spool');
const SPOOL_MAX_BYTES = 16 * 1024 * 1024; // 16 MB per segment

let spoolSegmentCounter = 0;          // monotonically increasing segment id
let spoolFd             = null;       // fd of the active segment
let spoolActivePath     = null;       // path of the active segment
let spoolActiveBytes    = 0;          // bytes written to active segment
let spoolDirty          = false;      // unsynced writes pending fsync
// Per-segment outstanding-entry counts: path → number of entries enqueued
// from that segment not yet confirmed flushed. A segment is unlinked when
// it is no longer active and its count reaches 0.
const spoolSegments = new Map();

function ensureSpoolDir() {
  try { fs.mkdirSync(SPOOL_DIR, { recursive: true }); }
  catch (err) { console.error('[Spool] Failed to create spool dir:', err.message); }
}

// Serialize an entry to a single NDJSON line. Buffers → hex; Date → ISO.
function serializeEntry(entry) {
  const o = {
    received_at:     entry.received_at instanceof Date ? entry.received_at.toISOString() : entry.received_at,
    log_timestamp:   entry.log_timestamp instanceof Date ? entry.log_timestamp.toISOString() : entry.log_timestamp,
    source_ip:       entry.source_ip,
    source_host:     entry.source_host,
    facility:        entry.facility,
    severity:        entry.severity,
    severity_label:  entry.severity_label,
    facility_label:  entry.facility_label,
    vendor:          entry.vendor,
    program:         entry.program,
    message:         entry.message,
    raw_message:     entry.raw_message,
    structured_data: entry.structured_data || {},
    is_parsed:       entry.is_parsed,
    category:        entry.category || null,
    risk_score:      entry.risk_score || 0,
    prev_hash:       entry.prev_hash  ? entry.prev_hash.toString('hex')  : null,
    entry_hash:      entry.entry_hash ? entry.entry_hash.toString('hex') : null,
  };
  return JSON.stringify(o) + '\n';
}

// Rebuild an entry from a spooled NDJSON object (hex → Buffer).
function deserializeEntry(o) {
  const e = {
    received_at:     o.received_at,
    log_timestamp:   o.log_timestamp,
    source_ip:       o.source_ip,
    source_host:     o.source_host,
    facility:        o.facility,
    severity:        o.severity,
    severity_label:  o.severity_label,
    facility_label:  o.facility_label,
    vendor:          o.vendor,
    program:         o.program,
    message:         o.message,
    raw_message:     o.raw_message,
    structured_data: o.structured_data || {},
    is_parsed:       o.is_parsed,
    category:        o.category || null,
    risk_score:      o.risk_score || 0,
    prev_hash:       o.prev_hash  ? Buffer.from(o.prev_hash,  'hex') : null,
    entry_hash:      o.entry_hash ? Buffer.from(o.entry_hash, 'hex') : null,
  };
  return e;
}

// Open a fresh active segment file.
function rollSpoolSegment() {
  if (spoolFd !== null) {
    try { fs.fsyncSync(spoolFd); } catch (_) {}
    try { fs.closeSync(spoolFd); } catch (_) {}
    spoolFd = null;
  }
  spoolSegmentCounter++;
  spoolActivePath  = path.join(SPOOL_DIR, `spool-${String(spoolSegmentCounter).padStart(10, '0')}.ndjson`);
  spoolActiveBytes = 0;
  if (!spoolSegments.has(spoolActivePath)) spoolSegments.set(spoolActivePath, 0);
  try {
    spoolFd = fs.openSync(spoolActivePath, 'a');
  } catch (err) {
    console.error('[Spool] Failed to open segment:', err.message);
    spoolFd = null;
  }
}

// Append an entry to the active spool segment and tag it with its segment.
function spoolAppend(entry) {
  if (spoolFd === null || spoolActiveBytes >= SPOOL_MAX_BYTES) rollSpoolSegment();
  if (spoolFd === null) return; // spool unavailable — fall through to in-memory only
  const line = serializeEntry(entry);
  const buf  = Buffer.from(line, 'utf8');
  try {
    fs.writeSync(spoolFd, buf);
    spoolActiveBytes += buf.length;
    spoolDirty = true;
    entry._spoolSeg = spoolActivePath;
    spoolSegments.set(spoolActivePath, (spoolSegments.get(spoolActivePath) || 0) + 1);
  } catch (err) {
    console.error('[Spool] Write error:', err.message);
  }
}

// Periodically durable-sync the active segment (called from the flush timer).
function spoolFsync() {
  if (spoolFd !== null && spoolDirty) {
    try { fs.fsyncSync(spoolFd); spoolDirty = false; } catch (_) {}
  }
}

// Called after a batch of entries is confirmed flushed to the DB: decrement
// per-segment outstanding counts and unlink any fully-flushed inactive segment.
function spoolConfirmFlushed(flushedEntries) {
  for (const e of flushedEntries) {
    const seg = e._spoolSeg;
    if (!seg) continue;
    const remaining = (spoolSegments.get(seg) || 0) - 1;
    if (remaining > 0) {
      spoolSegments.set(seg, remaining);
    } else {
      spoolSegments.set(seg, 0);
      // Only delete if this is not the active (still-being-written) segment.
      if (seg !== spoolActivePath) {
        spoolSegments.delete(seg);
        try { fs.unlinkSync(seg); } catch (_) {}
      }
    }
  }
}

// Replay any existing spool segments into the in-memory buffer on boot.
// Preserves order and stored hashes — does NOT recompute hashes.
function replaySpool() {
  ensureSpoolDir();
  let files = [];
  try {
    files = fs.readdirSync(SPOOL_DIR)
      .filter(f => /^spool-\d+\.ndjson$/.test(f))
      .sort(); // zero-padded names sort lexicographically == numerically
  } catch (_) { files = []; }

  let replayed = 0;
  for (const f of files) {
    const full = path.join(SPOOL_DIR, f);
    let content = '';
    try { content = fs.readFileSync(full, 'utf8'); }
    catch (_) { continue; }
    const lines = content.split('\n');
    let segCount = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue; // skip blank (incl. trailing newline split)
      let o;
      try { o = JSON.parse(line); }
      catch (_) {
        // Torn/partial last line after a crash — skip it rather than throw.
        if (i === lines.length - 1) continue;
        continue;
      }
      const e = deserializeEntry(o);
      e._spoolSeg = full;
      buffer.push(e);
      segCount++;
      replayed++;
    }
    if (segCount > 0) {
      spoolSegments.set(full, segCount);
    } else {
      // Empty/garbage segment — remove it.
      try { fs.unlinkSync(full); } catch (_) {}
    }
    // Track the highest counter so new segments don't collide.
    const m = f.match(/^spool-(\d+)\.ndjson$/);
    if (m) spoolSegmentCounter = Math.max(spoolSegmentCounter, parseInt(m[1], 10));
  }
  console.log(`[Spool] replayed ${replayed} entries from ${spoolSegments.size} segments`);
}

// ── Write buffer ──────────────────────────────────────────────
const BATCH_SIZE     = 100;
const BATCH_INTERVAL = 2000;
let buffer      = [];
let retryBuffer = []; // Holds failed batches for retry
let flushTimer  = null;

// Max rows per INSERT. 18 params/row → keep total params well under PostgreSQL's
// 65,535-per-query protocol limit, even when toFlush grows large under DB
// backpressure (buffer is not size-capped). Exceeding the limit surfaces as the
// wire-protocol error "bind message has N parameter formats but 0 parameters".
const MAX_INSERT_ROWS = 1000; // 1000 × 18 = 18,000 params — safe margin

async function flushBuffer() {
  // Combine retry buffer with current buffer
  const toFlush = [...retryBuffer, ...buffer.splice(0, buffer.length)];
  retryBuffer = [];
  if (toFlush.length === 0) return;

  // Insert in chunks so a single query never exceeds the parameter limit.
  for (let i = 0; i < toFlush.length; i += MAX_INSERT_ROWS) {
    const chunk = toFlush.slice(i, i + MAX_INSERT_ROWS);
    const values = [];
    const params = [];
    let p = 1;

    for (const row of chunk) {
      values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
      params.push(
        row.received_at, row.log_timestamp, row.source_ip, row.source_host,
        row.facility, row.severity, row.severity_label, row.facility_label,
        row.vendor, row.program, row.message, row.raw_message,
        JSON.stringify(row.structured_data || {}), row.is_parsed,
        row.category || null, row.risk_score || 0,
        row.prev_hash || null, row.entry_hash || null
      );
    }

    try {
      await pool.query(`
        INSERT INTO syslog_entries
          (received_at, log_timestamp, source_ip, source_host, facility, severity,
           severity_label, facility_label, vendor, program, message, raw_message,
           structured_data, is_parsed, category, risk_score, prev_hash, entry_hash)
        VALUES ${values.join(',')}
      `, params);
      // Confirm these entries are durably in the DB so their spool segments
      // can be reclaimed once fully flushed.
      spoolConfirmFlushed(chunk);
    } catch (err) {
      console.error(`[DB] Flush error (${chunk.length} rows): ${err.message}`);
      // Requeue this chunk + every not-yet-attempted row for the next flush.
      // Cap at 1000 to bound memory; un-flushed rows remain in the on-disk
      // spool and replay on restart, so they are not lost.
      retryBuffer = [...toFlush.slice(i), ...retryBuffer].slice(0, 1000);
      console.error(`[DB] ${retryBuffer.length} rows queued for retry`);
      return;
    }
  }
}

function enqueue(entry) {
  // Compute the hash at enqueue time (single-threaded, sequential) so the
  // chain order is deterministic, THEN spool with the same hash bytes, THEN
  // buffer. The identical hash bytes are used for spool + DB insert.
  applyHashChain(entry);
  spoolAppend(entry);
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

  // Resume the integrity hash chain from the last persisted hash (or warn if
  // disabled) BEFORE any new entry is hashed.
  await initHashChain();

  // Replay any durable spool segments left over from a crash/restart into the
  // in-memory buffer BEFORE opening sockets, so they drain ahead of new traffic
  // (and so a fresh active segment is opened after the highest existing counter).
  replaySpool();
  rollSpoolSegment();

  startUDP(514); startUDP(1514);
  startTCP(514); startTCP(1514);

  // Flush the DB buffer and durable-sync the spool on the same cadence.
  flushTimer = setInterval(() => { spoolFsync(); flushBuffer(); }, BATCH_INTERVAL);
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

  // Daily retention + partition maintenance, in-process — no external Windows
  // scheduled task needed. Runs ~60s after startup (let ingestion settle) then
  // every 24h. Reuses the collector's pool; never exits on error.
  const DAILY_MS = 24 * 60 * 60 * 1000;
  setTimeout(() => {
    runCleanup(pool).catch(err => console.error('[Cleanup] error:', err.message));
  }, 60 * 1000);
  setInterval(() => {
    runCleanup(pool).catch(err => console.error('[Cleanup] error:', err.message));
  }, DAILY_MS);

  console.log('LogVault Collector running. Listening on ports 514 and 1514 (UDP+TCP).');
  console.log('[Correlation] Engine loaded with 8 rules');

  const shutdown = async () => {
    console.log('[Collector] Shutting down gracefully...');
    clearInterval(flushTimer);
    spoolFsync();
    await flushBuffer();
    if (spoolFd !== null) { try { fs.fsyncSync(spoolFd); fs.closeSync(spoolFd); } catch (_) {} spoolFd = null; }
    await pool.end();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT',  shutdown);
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
