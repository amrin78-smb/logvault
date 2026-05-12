/**
 * LogVault Collector Service
 * Syslog receiver on UDP/TCP ports 514 and 1514
 * Parses, normalizes, and writes to TimescaleDB
 *
 * Run with: node collector.js
 * Managed by NSSM as a Windows service: LogVaultCollector
 */

'use strict';

const dgram   = require('dgram');
const net     = require('net');
const { Pool } = require('pg');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });

const { parseGeneric }   = require('../parsers/generic');
const { parseCisco }     = require('../parsers/cisco');
const { parsePaloAlto }  = require('../parsers/paloalto');
const { parseFortinet }  = require('../parsers/fortinet');
const { parseAruba }     = require('../parsers/aruba');
const { parseSangfor }   = require('../parsers/sangfor');

// ── Database pool ────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.LV_DB_NAME  || 'logvault',
  user:     process.env.LV_DB_USER  || 'logvault_user',
  password: process.env.LV_DB_PASS,
  max:      10,
  idleTimeoutMillis: 30000,
});

// ── Write buffer (batch inserts for high volume) ─────────────
const BATCH_SIZE     = 100;
const BATCH_INTERVAL = 2000; // ms
let buffer = [];
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
      row.received_at,
      row.log_timestamp,
      row.source_ip,
      row.source_host,
      row.facility,
      row.severity,
      row.severity_label,
      row.facility_label,
      row.vendor,
      row.program,
      row.message,
      row.raw_message,
      JSON.stringify(row.structured_data || {}),
      row.is_parsed
    );
  }

  const sql = `
    INSERT INTO syslog_entries
      (received_at, log_timestamp, source_ip, source_host, facility, severity,
       severity_label, facility_label, vendor, program, message, raw_message, structured_data, is_parsed)
    VALUES ${values.join(',')}
  `;

  try {
    await pool.query(sql, params);
    if (process.env.LOG_LEVEL === 'debug') {
      console.log(`[DB] Flushed ${batch.length} log entries`);
    }
  } catch (err) {
    console.error('[DB] Flush error:', err.message);
  }
}

function scheduleFlush() {
  if (!flushTimer) {
    flushTimer = setInterval(async () => {
      await flushBuffer();
    }, BATCH_INTERVAL);
  }
}

function enqueue(entry) {
  buffer.push(entry);
  if (buffer.length >= BATCH_SIZE) {
    flushBuffer();
  }
}

// ── Parser registry ──────────────────────────────────────────
// Each parser returns a normalized entry or null (fall through to next)
const PARSERS = [
  parseCisco,
  parsePaloAlto,
  parseFortinet,
  parseAruba,
  parseSangfor,
  parseGeneric,  // always last - catches everything else
];

function processMessage(rawMsg, sourceIp) {
  const raw = rawMsg.toString('utf8').trim();
  if (!raw) return;

  let entry = null;
  for (const parser of PARSERS) {
    try {
      entry = parser(raw, sourceIp);
      if (entry) break;
    } catch (e) {
      // parser threw, try next
    }
  }

  if (!entry) {
    // absolute fallback
    entry = {
      source_ip:      sourceIp,
      source_host:    null,
      facility:       1,
      severity:       6,
      severity_label: 'info',
      facility_label: 'user',
      vendor:         'unknown',
      program:        null,
      message:        raw,
      raw_message:    raw,
      structured_data: {},
      is_parsed:      false,
      log_timestamp:  null,
    };
  }

  entry.received_at = new Date();
  enqueue(entry);
}

// ── UDP Server ───────────────────────────────────────────────
function startUDP(port) {
  const server = dgram.createSocket('udp4');

  server.on('message', (msg, rinfo) => {
    processMessage(msg, rinfo.address);
  });

  server.on('error', (err) => {
    console.error(`[UDP:${port}] Error:`, err.message);
  });

  server.bind(port, () => {
    console.log(`[UDP] Listening on port ${port}`);
  });

  return server;
}

// ── TCP Server ───────────────────────────────────────────────
function startTCP(port) {
  const server = net.createServer((socket) => {
    let leftover = '';

    socket.on('data', (data) => {
      const text = leftover + data.toString('utf8');
      const lines = text.split('\n');
      leftover = lines.pop(); // last incomplete line saved for next chunk

      for (const line of lines) {
        if (line.trim()) {
          processMessage(Buffer.from(line), socket.remoteAddress);
        }
      }
    });

    socket.on('end', () => {
      if (leftover.trim()) {
        processMessage(Buffer.from(leftover), socket.remoteAddress);
      }
    });

    socket.on('error', (err) => {
      if (err.code !== 'ECONNRESET') {
        console.error(`[TCP:${port}] Socket error:`, err.message);
      }
    });
  });

  server.on('error', (err) => {
    console.error(`[TCP:${port}] Server error:`, err.message);
  });

  server.listen(port, () => {
    console.log(`[TCP] Listening on port ${port}`);
  });

  return server;
}

// ── Startup ──────────────────────────────────────────────────
async function main() {
  console.log('LogVault Collector starting...');

  // Test DB connection
  try {
    await pool.query('SELECT 1');
    console.log('[DB] Connected to logvault database');
  } catch (err) {
    console.error('[DB] Connection failed:', err.message);
    process.exit(1);
  }

  // Start syslog listeners
  startUDP(514);
  startUDP(1514);
  startTCP(514);
  startTCP(1514);

  // Start batch flush timer
  scheduleFlush();

  console.log('LogVault Collector running. Listening on ports 514 and 1514 (UDP+TCP).');

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('Shutting down...');
    clearInterval(flushTimer);
    await flushBuffer();
    await pool.end();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    clearInterval(flushTimer);
    await flushBuffer();
    await pool.end();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
