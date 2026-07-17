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
const { getCategory }    = require('./taxonomy');
const { scoreLogExplained } = require('./riskScorer');
const { mapTechniques }  = require('./mitreMapper');
const { evaluateCorrelation } = require('./correlationEngine');
const { syncFromNetVault }    = require('./netvaultSync');
const { runCleanup }          = require('../scripts/cleanup');
// Phase 2 — behavioral baselining + anomaly detection + UEBA (on-prem, pure SQL/JS).
const { buildBaselines }      = require('./analytics/baselineBuilder');
const { detectAnomalies }     = require('./analytics/anomalyDetector');
const { rollupEntityRisk }    = require('./analytics/uebaRollup');
const { enrichIP, configureDNS } = require('./dnsLookup');
const { enrichExternalIP, isPrivateIP } = require('./geoEnrich');
const { sendAlertEmail }         = require('./emailer');

// IPs seen this session — avoid re-enriching same IP repeatedly
const seenIPs = new Set();

// DNS settings cache — reloaded every 5 minutes.
// Also carries the AbuseIPDB API key for GeoIP/threat enrichment (same TTL,
// folded into one query). The key is never logged.
let dnsSettings = { enabled: true, server: '', abuseKey: '' };
let dnsSettingsLoadedAt = 0;
const DNS_SETTINGS_TTL = 5 * 60 * 1000; // 5 minutes

async function getDNSSettings() {
  const now = Date.now();
  if (now - dnsSettingsLoadedAt < DNS_SETTINGS_TTL) return dnsSettings;
  try {
    const { rows } = await pool.query(
      `SELECT key, value FROM app_settings
       WHERE key IN ('dns_server', 'dns_lookup_enabled', 'abuseipdb_api_key')`
    );
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const newServer  = s.dns_server || '';
    const newEnabled = s.dns_lookup_enabled !== 'false';
    // Reconfigure DNS server if changed
    if (newServer !== dnsSettings.server) {
      configureDNS(newServer);
      console.log(`[DNS] Server updated to: ${newServer || 'system default'}`);
    }
    dnsSettings = { enabled: newEnabled, server: newServer, abuseKey: s.abuseipdb_api_key || '' };
    dnsSettingsLoadedAt = now;
  } catch {}
  return dnsSettings;
}

// Upsert GeoIP/threat enrichment into known_hosts for an external IP.
// COALESCE keeps existing values when a future enrichment returns null, and the
// WHERE guard means a NetVault-synced row's hostname/vendor/site/brand/model are
// never touched — we only set the geo/threat columns + is_external/last_enriched.
async function upsertGeoEnrichment(ip, data) {
  if (!ip || !data) return;
  const cleanIP = String(ip).replace(/\/\d+$/, '').trim();
  try {
    await pool.query(`
      INSERT INTO known_hosts
        (ip_address, country_code, country_name, city, asn, asn_org,
         is_external, abuse_score, is_known_bad, threat_tags, last_enriched, last_seen)
      VALUES ($1::inet, $2, $3, $4, $5, $6, TRUE, $7, $8, $9, NOW(), NOW())
      ON CONFLICT (ip_address) DO UPDATE SET
        country_code  = COALESCE(EXCLUDED.country_code,  known_hosts.country_code),
        country_name  = COALESCE(EXCLUDED.country_name,  known_hosts.country_name),
        city          = COALESCE(EXCLUDED.city,          known_hosts.city),
        asn           = COALESCE(EXCLUDED.asn,           known_hosts.asn),
        asn_org       = COALESCE(EXCLUDED.asn_org,       known_hosts.asn_org),
        is_external   = TRUE,
        abuse_score   = COALESCE(EXCLUDED.abuse_score,   known_hosts.abuse_score),
        is_known_bad  = COALESCE(EXCLUDED.is_known_bad,  known_hosts.is_known_bad),
        threat_tags   = COALESCE(EXCLUDED.threat_tags,   known_hosts.threat_tags),
        last_enriched = NOW(),
        last_seen     = NOW()
    `, [
      cleanIP,
      data.country_code, data.country_name, data.city, data.asn, data.asn_org,
      (data.abuse_score === null || data.abuse_score === undefined) ? null : data.abuse_score,
      (data.abuse_score === null || data.abuse_score === undefined) ? null : data.is_known_bad,
      (data.threat_tags && data.threat_tags.length) ? data.threat_tags : null,
    ]);
  } catch (err) {
    console.error(`[GeoEnrich] Upsert error for ${cleanIP}:`, err.message);
  }
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
    srcip:           entry.srcip || null,
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
    srcip:           o.srcip || null,
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

// Max rows per INSERT. 19 params/row → keep total params well under PostgreSQL's
// 65,535-per-query protocol limit, even when toFlush grows large under DB
// backpressure (buffer is not size-capped). Exceeding the limit surfaces as the
// wire-protocol error "bind message has N parameter formats but 0 parameters".
const MAX_INSERT_ROWS = 1000; // 1000 × 19 = 19,000 params — safe margin

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
      values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
      params.push(
        row.received_at, row.log_timestamp, row.source_ip, row.source_host,
        row.facility, row.severity, row.severity_label, row.facility_label,
        row.vendor, row.program, row.message, row.raw_message,
        JSON.stringify(row.structured_data || {}), row.is_parsed,
        row.category || null, row.risk_score || 0,
        row.prev_hash || null, row.entry_hash || null, row.srcip || null
      );
    }

    try {
      await pool.query(`
        INSERT INTO syslog_entries
          (received_at, log_timestamp, source_ip, source_host, facility, severity,
           severity_label, facility_label, vendor, program, message, raw_message,
           structured_data, is_parsed, category, risk_score, prev_hash, entry_hash, srcip)
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
  // Score once, then persist the contributing factors so the UI can explain
  // "Why this score?". risk_factors rides inside structured_data (already
  // serialized into the INSERT, like the mitre field) — no new DB column.
  const riskResult = scoreLogExplained(entry);
  entry.risk_score = riskResult.score;
  if (riskResult.factors.length) entry.structured_data.risk_factors = riskResult.factors;

  // MITRE ATT&CK technique mapping (event-level). Stored inside structured_data
  // (already serialized into the INSERT, excluded from the hash chain) so no new
  // column or INSERT param-count change is needed. Empty arrays are omitted.
  const mitre = mapTechniques(entry);
  if (mitre.length) entry.structured_data.mitre = mitre;

  // Precompute srcip ONCE at insert time (perf pass, 2026-07) — same formula
  // every dashboard widget previously computed ad hoc at read time via
  // COALESCE(NULLIF(btrim(structured_data->>'srcip'), ''), host(source_ip)).
  // Prefer a non-empty parser-captured structured_data.srcip (the real
  // client/attacker IP — see the "Parser source-field contract" in
  // CLAUDE.md), falling back to the syslog sender's source_ip.
  entry.srcip = (entry.structured_data && entry.structured_data.srcip && String(entry.structured_data.srcip).trim())
    || entry.source_ip;

  entry.received_at = new Date();

  // Drop high-volume low-value logs before writing to DB
  if (shouldDrop(entry)) return;

  enqueue(entry);

  // DNS reverse lookup + GeoIP/threat enrichment for new IPs — best effort,
  // non-blocking (fire-and-forget; never awaited on the ingest hot path).
  const ipKey = entry.source_ip;
  if (ipKey && !seenIPs.has(ipKey)) {
    seenIPs.add(ipKey);
    if (seenIPs.size > 10000) seenIPs.clear();
    getDNSSettings().then(s => {
      if (s.enabled) enrichIP(ipKey, pool).catch(() => {});
      // GeoIP/threat enrichment for EXTERNAL IPs only — private IPs never leave
      // the box (isPrivateIP guard inside enrichExternalIP too, belt-and-braces).
      if (!isPrivateIP(ipKey)) {
        enrichExternalIP(ipKey, s.abuseKey)
          .then(data => { if (data) return upsertGeoEnrichment(ipKey, data); })
          .catch(() => {});
      }
    }).catch(() => {});
  }

  // In Fortinet (and similar) firewall logs the source_ip is the internal device;
  // the EXTERNAL IP appears as the destination (dstip). Enrich it too and upsert
  // it into known_hosts so the existing geo joins (source_ip → known_hosts) surface
  // country/ASN/threat data for destination IPs as well. Same fire-and-forget path.
  const sd = entry.structured_data || {};
  const dstIP = sd.dstip || sd.dst_ip || sd.destination_ip;
  if (dstIP && !isPrivateIP(dstIP) && !seenIPs.has(dstIP)) {
    seenIPs.add(dstIP);
    if (seenIPs.size > 10000) seenIPs.clear();
    getDNSSettings().then(s => {
      enrichExternalIP(dstIP, s.abuseKey)
        .then(data => { if (data) return upsertGeoEnrichment(dstIP, data); })
        .catch(() => {});
    }).catch(() => {});
  }

  // The real ATTACKER/CLIENT is structured_data.srcip (source_ip is the relay).
  // Enrich it too so country/ASN/threat data exists in known_hosts for the actor —
  // the consumers that group/score by srcip (top-talkers, known-bad hit counts,
  // UEBA known-bad factor) join known_hosts on this IP. Same fire-and-forget path.
  const srcIP = sd.srcip || sd.src_ip;
  if (srcIP && !isPrivateIP(srcIP) && !seenIPs.has(srcIP)) {
    seenIPs.add(srcIP);
    if (seenIPs.size > 10000) seenIPs.clear();
    getDNSSettings().then(s => {
      enrichExternalIP(srcIP, s.abuseKey)
        .then(data => { if (data) return upsertGeoEnrichment(srcIP, data); })
        .catch(() => {});
    }).catch(() => {});
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
      // The actor is the real attacker (structured_data.srcip) for security events,
      // falling back to the syslog sender for operational/device events that carry
      // no srcip. Suppress + record per-actor, NOT per relay — otherwise every
      // relayed event collapses to the one forwarding device and the alert is
      // attributed to the firewall itself.
      const actorIp       = entry.structured_data?.srcip || entry.source_ip;
      const sourceKey     = `${rule.id}__${actorIp || 'any'}`;
      const lastFired     = suppressionMap.get(sourceKey) || 0;
      if (now - lastFired < THRESHOLD_SUPPRESSION_MS) {
        console.log(`[Alert] Rule "${rule.name}" suppressed for ${actorIp} (cooldown active)`);
        continue;
      }
      suppressionMap.set(sourceKey, now);
      await fireAlert(rule, entry, fresh.length, actorIp);
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

async function fireAlert(rule, entry, matchCount, actorIp) {
  try {
    // actorIp = the real attacker (structured_data.srcip) or the sender fallback.
    // source_host stays the reporting device label; source_ip carries the actor so
    // the alert (and its email + log drill-down) attribute to who actually did it,
    // mirroring how the correlation engine writes alert_events.
    const alertIp = actorIp || entry.structured_data?.srcip || entry.source_ip;
    // Check if there's already an open (unacknowledged) alert for this rule + actor
    const existing = await pool.query(`
      SELECT id, match_count FROM alert_events
      WHERE rule_id = $1
        AND acknowledged = FALSE
        AND source_ip = $2
        AND fired_at > NOW() - INTERVAL '2 hours'
      ORDER BY fired_at DESC
      LIMIT 1
    `, [rule.id, alertIp]);

    if (existing.rows.length > 0) {
      // Update existing alert — increment count, update sample message
      await pool.query(`
        UPDATE alert_events
        SET match_count   = match_count + $1,
            sample_message = $2,
            fired_at       = NOW()
        WHERE id = $3
      `, [matchCount, entry.message.substring(0, 500), existing.rows[0].id]);
      console.log(`[Alert] Rule "${rule.name}" updated existing alert — ${alertIp || entry.source_host}`);
    } else {
      // Insert new alert
      await pool.query(`
        INSERT INTO alert_events (rule_id, source_host, source_ip, match_count, sample_message)
        VALUES ($1, $2, $3, $4, $5)
      `, [rule.id, entry.source_host || null, alertIp, matchCount, entry.message.substring(0, 500)]);
      console.log(`[Alert] Rule "${rule.name}" fired — ${alertIp || entry.source_host}`);
    }

    // Send email notification (best-effort — never blocks alert firing).
    // The emailer applies the global notification filters and resolves
    // recipients (per-rule notify_email + global recipients), so we always
    // call it and let it decide whether an email actually goes out.
    sendAlertEmail(rule, entry, matchCount, pool).catch(err =>
      console.error('[Alert] Email notify error:', err.message));
  } catch (err) { console.error('[Alert] Failed to insert/update alert event:', err.message); }
}

// ── Rollup maintenance (perf pass, 2026-07) ──────────────────
// Recomputes syslog_stats_rollup + syslog_talker_rollup for ONLY the current
// hour bucket and the previous hour bucket, every 5 minutes. Deliberately a
// "recompute the recent window from the raw source of truth" model, NOT
// increment-on-insert — idempotent and self-healing (a missed cycle, restart,
// or double-run can never double-count or drift). See the extensive rationale
// comment above the two CREATE TABLE statements in scripts/schema.sql.
//
// site_id in BOTH tables is resolved via known_hosts.ip_address = source_ip
// (the relay/firewall device that sent the log) — mirroring exactly how
// getStatsSiteFilter() in api/rbac.js scopes dashboard aggregates. srcip is
// stored in syslog_talker_rollup purely as the display/grouping key for
// "who's talking", never for RBAC — do not swap these.
//
// Never throws — wrapped in try/catch by every call site (matches runCleanup)
// so a rollup failure can never block or slow down log ingestion.
async function recomputeRollupBucket(pool, hourBucket) {
  await pool.query(`DELETE FROM syslog_stats_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_stats_rollup (hour_bucket, severity, severity_label, category, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at), se.severity, se.severity_label,
           COALESCE(se.category, 'uncategorized'), se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
    GROUP BY 1, 2, 3, 4, 5, 6
  `, [hourBucket]);

  await pool.query(`DELETE FROM syslog_talker_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_talker_rollup (hour_bucket, srcip, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at),
           COALESCE(se.srcip, host(se.source_ip)) AS srcip,
           se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
    GROUP BY 1, 2, 3, 4
  `, [hourBucket]);

  await recomputePhase2RollupBucket(pool, hourBucket);
  await recomputePhase3RollupBucket(pool, hourBucket);
}

// Phase 2 rollups (perf pass, 2026-07): Top Security Events / Top Blocked /
// Top Connection Failures / VPN Status. Same DELETE+INSERT-per-bucket model
// as recomputeRollupBucket above — see scripts/schema.sql's "PHASE 2 HOURLY
// ROLLUP TABLES" comment for the full rationale and table shapes. The
// classification predicates below MUST stay byte-identical to the raw-table
// versions that used to live in api/server.js's top-security-events/
// top-blocked/top-failures/vpn-summary handlers — this is a drop-in
// pre-aggregation of the exact same logic, not a redesign.
async function recomputePhase2RollupBucket(pool, hourBucket) {
  await pool.query(`DELETE FROM syslog_security_event_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_security_event_rollup (hour_bucket, event_type, site_id, log_count)
    SELECT date_trunc('hour', se.received_at),
      CASE
        WHEN se.message ILIKE '%ssl-alert%'      THEN 'SSL Alert'
        WHEN se.message ILIKE '%ssl exit error%' THEN 'SSL Exit Error'
        WHEN se.message ILIKE '%ipsec%phase 1%'  THEN 'IPSec Phase 1 Error'
        WHEN se.message ILIKE '%login failed%'   THEN 'Login Failed'
        WHEN se.message ILIKE '%action=deny%'    THEN 'Traffic Denied'
        WHEN se.message ILIKE '%utm/ips%'        THEN 'IPS Threat'
        WHEN se.message ILIKE '%negotiate%'      THEN 'VPN Negotiate'
        WHEN se.structured_data->>'subtype' IS NOT NULL THEN se.structured_data->>'subtype'
        ELSE 'Other'
      END,
      kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
      AND se.severity <= 4
    GROUP BY 1, 2, 3
  `, [hourBucket]);

  await pool.query(`DELETE FROM syslog_dest_event_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_dest_event_rollup (hour_bucket, event_class, dstip, service, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at), 'blocked',
      se.structured_data->>'dstip', COALESCE(se.structured_data->>'service', ''), se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
      AND (
        LOWER(se.structured_data->>'action') IN ('deny','denied','block','blocked','drop','dropped')
        OR se.message ILIKE '%action=deny%'
        OR se.message ILIKE '%action=block%'
        OR se.message ILIKE '%action=blocked%'
        OR se.message ILIKE '%action=drop%'
        OR se.message ILIKE '%denied%'
        OR se.message ILIKE '%ACL%deny%'
      )
      AND se.structured_data->>'dstip' IS NOT NULL
    GROUP BY 1, 3, 4, 5, 6
  `, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_dest_event_rollup (hour_bucket, event_class, dstip, service, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at), 'failure',
      se.structured_data->>'dstip', COALESCE(se.structured_data->>'service', ''), se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
      AND (
        (se.vendor = 'fortinet' AND se.message ILIKE '%Connection Failed%')
        OR (se.vendor = 'paloalto' AND se.message ILIKE '%session_end%' AND se.message ILIKE '%bytes%0%')
        OR (se.vendor = 'cisco' AND (se.message ILIKE '%unreachable%' OR se.message ILIKE '%timed out%'))
        OR (se.vendor NOT IN ('fortinet','paloalto','cisco') AND (
          se.message ILIKE '%connection failed%'
          OR se.message ILIKE '%connection refused%'
          OR se.message ILIKE '%host unreachable%'
          OR se.message ILIKE '%timed out%'
        ))
      )
      AND se.structured_data->>'dstip' IS NOT NULL
    GROUP BY 1, 3, 4, 5, 6
  `, [hourBucket]);

  await pool.query(`DELETE FROM syslog_vpn_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_vpn_rollup (hour_bucket, site_id, total, failures, successes, ssl_alerts)
    SELECT date_trunc('hour', se.received_at), kh.site_id,
      COUNT(*),
      COUNT(*) FILTER (WHERE se.message ILIKE '%fail%' OR se.message ILIKE '%error%'),
      COUNT(*) FILTER (WHERE se.message ILIKE '%success%' OR se.message ILIKE '%connected%'),
      COUNT(*) FILTER (WHERE se.message ILIKE '%ssl-alert%' OR se.message ILIKE '%ssl alert%')
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
      AND se.vendor = 'fortinet'
      AND (se.structured_data->>'subtype' = 'vpn' OR se.message ILIKE '%vpn%'
        OR se.message ILIKE '%ipsec%' OR se.message ILIKE '%ssl%')
    GROUP BY 1, 2
  `, [hourBucket]);
}

// Phase 3 rollups (perf pass, 2026-07): Top Destinations / silent-devices half
// of Capacity & Ingestion Health / What's New-Changed's 4 dimensions / Known-
// Bad Sources' hit counts. Same DELETE+INSERT-per-bucket model as Phase 1/2 —
// see scripts/schema.sql's "PHASE 3 HOURLY ROLLUP TABLES" comment for the
// full rationale, table shapes, and WHY each of these needed its own new
// table (none of the existing rollups had the right dimension).
async function recomputePhase3RollupBucket(pool, hourBucket) {
  // Top Destinations — symmetric to syslog_talker_rollup, keyed on dstip.
  await pool.query(`DELETE FROM syslog_dest_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_dest_rollup (hour_bucket, dstip, vendor, site_id, log_count)
    SELECT date_trunc('hour', se.received_at), btrim(se.structured_data->>'dstip'), se.vendor, kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
      AND se.structured_data->>'dstip' ~ '^[0-9.]+$'
    GROUP BY 1, 2, 3, 4
  `, [hourBucket]);

  // Silent devices — keyed on source_host (the relay hostname), which no
  // existing rollup carries. source_ip is a representative value (MAX, not a
  // grouping key) purely for the widget's drill-through action.
  await pool.query(`DELETE FROM syslog_source_host_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_source_host_rollup (hour_bucket, source_host, source_ip, site_id, log_count)
    SELECT date_trunc('hour', se.received_at), se.source_host, MAX(host(se.source_ip)), kh.site_id, COUNT(*)
    FROM syslog_entries se
    LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
      AND se.source_host IS NOT NULL AND se.source_host <> ''
    GROUP BY 1, 2, 4
  `, [hourBucket]);

  // What's New/Changed — 4 dimensions into one table with a discriminator.
  // Expressions are byte-identical to the ones the endpoint used to run live
  // (see api/server.js) — including new_sources' COALESCE(srcip,
  // source_ip::text) WITHOUT host(), an existing quirk (leaves the /32 mask
  // in place) preserved on purpose so behavior doesn't change.
  await pool.query(`DELETE FROM syslog_distinct_value_rollup WHERE hour_bucket = $1`, [hourBucket]);
  const DIST_VALUE_DIMS = [
    { dim: 'country', expr: `se.structured_data->>'srccountry'` },
    { dim: 'user',     expr: `se.structured_data->>'user'` },
    { dim: 'source',   expr: `COALESCE(se.structured_data->>'srcip', se.source_ip::text)` },
    { dim: 'service',  expr: `se.structured_data->>'service'` },
  ];
  for (const { dim, expr } of DIST_VALUE_DIMS) {
    await pool.query(`
      INSERT INTO syslog_distinct_value_rollup (hour_bucket, dimension, value, site_id, log_count)
      SELECT date_trunc('hour', se.received_at), $2, ${expr}, kh.site_id, COUNT(*)
      FROM syslog_entries se
      LEFT JOIN known_hosts kh ON kh.ip_address = se.source_ip
      WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
        AND ${expr} IS NOT NULL AND ${expr} NOT IN ('', 'N/A')
      GROUP BY 1, 3, 4
    `, [hourBucket, dim]);
  }

  // Known-Bad Sources — hit counts for CURRENTLY known-bad/high-abuse-score
  // IPs only (not every IP ever seen — this table is meant to stay small and
  // targeted). Replaces a per-known_hosts-row correlated subquery (measured
  // ~130s live) with one grouped pass over syslog_entries per cycle. The
  // LATERAL unnests each row's up-to-3 IP-bearing fields (srcip/dstip/relay
  // source_ip) with DISTINCT so a row where two fields coincidentally match
  // the SAME known-bad IP is still counted once for that IP — matching the
  // original query's OR-semantics exactly, not summed/double-counted.
  await pool.query(`DELETE FROM syslog_known_bad_hit_rollup WHERE hour_bucket = $1`, [hourBucket]);
  await pool.query(`
    INSERT INTO syslog_known_bad_hit_rollup (hour_bucket, ip_address, site_id, hit_count)
    SELECT date_trunc('hour', se.received_at), kb.ip_address, relay.site_id, COUNT(*)
    FROM syslog_entries se
    CROSS JOIN LATERAL (
      SELECT DISTINCT v.ip
      FROM (VALUES (se.structured_data->>'srcip'), (se.structured_data->>'dstip'), (host(se.source_ip))) AS v(ip)
      WHERE v.ip IS NOT NULL
    ) AS touched(ip)
    JOIN known_hosts kb ON host(kb.ip_address) = touched.ip AND (kb.is_known_bad = TRUE OR kb.abuse_score >= 50)
    LEFT JOIN known_hosts relay ON relay.ip_address = se.source_ip
    WHERE se.received_at >= $1 AND se.received_at < $1 + interval '1 hour'
    GROUP BY 1, 2, 3
  `, [hourBucket]);
}

// How many trailing hours get swept on every 5-minute cycle (not just the
// current+previous hour). Each individual bucket recompute is a cheap,
// idempotent DELETE+INSERT from raw syslog_entries (measured at tens of
// milliseconds per hour, per the Phase 3 validation notes in CLAUDE.md), so
// widening this costs very little relative to the 5-minute cadence, and it
// closes a real gap the original 2-bucket window had: syslog_entries.received_at
// is stamped at PARSE time and never rewritten, so an entry delayed past the
// lookback window (a DB outage, ingest backpressure, or the collector itself
// being down for a while — a routine occurrence, not an edge case, e.g. every
// deploy) inserted successfully but was silently and PERMANENTLY excluded from
// every rollup table, since nothing ever revisited that hour bucket again. A
// wider window means a bucket a late entry belongs to gets swept and corrected
// on the next few cycles automatically, with no manual intervention. This does
// NOT reintroduce increment-on-insert (still forbidden — see the header comment
// above recomputeRollupBucket) — every bucket in the window is still a full,
// idempotent re-aggregation from the raw table, just over more buckets per
// cycle. An outage longer than this window still needs the documented manual
// `node scripts/backfill-rollups.js` recovery — this only removes the need for
// that on anything shorter, which is the overwhelmingly common case (routine
// restarts/updates/brief network blips).
const ROLLUP_LOOKBACK_HOURS = parseInt(process.env.ROLLUP_LOOKBACK_HOURS, 10) || 24;

// Runs against the supplied pool. Never throws — caller (the timer callbacks
// in start()) still wraps this in .catch(), but the internal try/catch here
// means a failure on ONE bucket never skips the others, and this function
// itself never rejects the process into an unhandledRejection.
async function runRollupMaintenance(pool) {
  const now         = new Date();
  const currentHour = new Date(now); currentHour.setMinutes(0, 0, 0);

  for (let i = 0; i < ROLLUP_LOOKBACK_HOURS; i++) {
    const bucket = new Date(currentHour.getTime() - i * 60 * 60 * 1000);
    try {
      await recomputeRollupBucket(pool, bucket);
    } catch (err) {
      console.error(`[Rollup] Failed to recompute bucket ${bucket.toISOString()}:`, err.message);
    }
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

  // Rollup-table maintenance, in-process — recomputes the current + previous
  // hour bucket of syslog_stats_rollup/syslog_talker_rollup every 5 minutes so
  // dashboard widgets read small pre-aggregated tables instead of scanning raw
  // syslog_entries. Separate timer from the daily cleanup job above — do not
  // merge them. Runs ~60s after startup (let ingestion settle) then every 5m.
  // Reuses the collector's pool; never blocks ingestion, never exits on error.
  const ROLLUP_INTERVAL_MS = 5 * 60 * 1000;
  setTimeout(() => {
    runRollupMaintenance(pool).catch(err => console.error('[Rollup] error:', err.message));
  }, 60 * 1000);
  setInterval(() => {
    runRollupMaintenance(pool).catch(err => console.error('[Rollup] error:', err.message));
  }, ROLLUP_INTERVAL_MS);

  // ── Phase 2 intelligence jobs — in-process, reuse the pool, never exit on
  // error (same scheduled-job pattern as runCleanup/syncFromNetVault above).
  //  * buildBaselines    — rebuild hour×dow volume baselines every 24h
  //  * detectAnomalies   — volume/silent/new-geo/new-service checks every 30m
  //  * rollupEntityRisk  — UEBA per-entity risk rollup every 15m
  // Each call is wrapped so a failure logs and never kills the collector.
  const HALF_HOUR_MS    = 30 * 60 * 1000;
  const QUARTER_HOUR_MS = 15 * 60 * 1000;

  // Baselines: first run ~90s after startup (let ingestion settle), then every 24h.
  setTimeout(() => {
    buildBaselines(pool).catch(err => console.error('[Baseline] error:', err.message));
  }, 90 * 1000);
  setInterval(() => {
    buildBaselines(pool).catch(err => console.error('[Baseline] error:', err.message));
  }, DAILY_MS);

  // Anomaly detection: first run ~120s after startup (after a baseline pass had a
  // chance to write), then every 30m.
  setTimeout(() => {
    detectAnomalies(pool).catch(err => console.error('[Anomaly] error:', err.message));
  }, 120 * 1000);
  setInterval(() => {
    detectAnomalies(pool).catch(err => console.error('[Anomaly] error:', err.message));
  }, HALF_HOUR_MS);

  // UEBA risk rollup: first run ~150s after startup, then every 15m.
  setTimeout(() => {
    rollupEntityRisk(pool).catch(err => console.error('[UEBA] error:', err.message));
  }, 150 * 1000);
  setInterval(() => {
    rollupEntityRisk(pool).catch(err => console.error('[UEBA] error:', err.message));
  }, QUARTER_HOUR_MS);

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
