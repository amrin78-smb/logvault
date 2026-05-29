'use strict';

/**
 * Reverse DNS lookup utility
 * Used by collector to auto-enrich unknown IPs with hostnames
 */

const dns = require('dns');
const { promisify } = require('util');

const reverse = promisify(dns.reverse);

// Cache to avoid repeated lookups — key: ip, value: { hostname, resolved_at }
const lookupCache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// IPs currently being looked up — prevent duplicate concurrent lookups
const pendingLookups = new Set();

// Configure custom DNS server if provided
function configureDNS(dnsServer) {
  if (dnsServer && dnsServer.trim()) {
    dns.setServers([dnsServer.trim()]);
    console.log(`[DNS] Using DNS server: ${dnsServer.trim()}`);
  }
}

async function reverseLookup(ip) {
  if (!ip) return null;

  // Clean IP — remove CIDR notation
  const cleanIP = ip.replace(/\/\d+$/, '').trim();

  // Check cache
  const cached = lookupCache.get(cleanIP);
  if (cached && Date.now() - cached.resolved_at < CACHE_TTL_MS) {
    return cached.hostname;
  }

  // Skip if already looking up
  if (pendingLookups.has(cleanIP)) return null;

  pendingLookups.add(cleanIP);

  try {
    const hostnames = await reverse(cleanIP);
    const hostname  = hostnames?.[0] || null;

    // Cache result (even null = no PTR record)
    lookupCache.set(cleanIP, { hostname, resolved_at: Date.now() });
    return hostname;
  } catch {
    // No PTR record — cache null to avoid retrying
    lookupCache.set(cleanIP, { hostname: null, resolved_at: Date.now() });
    return null;
  } finally {
    pendingLookups.delete(cleanIP);
  }
}

// Enrich an IP against known_hosts — lookup and store if not already known
async function enrichIP(ip, pool) {
  if (!ip) return;
  const cleanIP = ip.replace(/\/\d+$/, '').trim();

  try {
    // Check if already in known_hosts with a hostname
    const existing = await pool.query(
      `SELECT hostname, synced_from_nv FROM known_hosts WHERE ip_address = $1::inet`,
      [cleanIP]
    );

    // If NetVault synced — don't overwrite
    if (existing.rows.length > 0 && existing.rows[0].synced_from_nv) return;

    // If already has a hostname from DNS — skip unless cache expired
    if (existing.rows.length > 0 && existing.rows[0].hostname) {
      const cached = lookupCache.get(cleanIP);
      if (cached && Date.now() - cached.resolved_at < CACHE_TTL_MS) return;
    }

    // Do reverse lookup
    const hostname = await reverseLookup(cleanIP);

    if (hostname) {
      // Upsert into known_hosts
      await pool.query(`
        INSERT INTO known_hosts (ip_address, hostname, last_seen)
        VALUES ($1::inet, $2, NOW())
        ON CONFLICT (ip_address) DO UPDATE
          SET hostname  = EXCLUDED.hostname,
              last_seen = NOW()
          WHERE known_hosts.synced_from_nv IS NOT TRUE
      `, [cleanIP, hostname]);
    } else {
      // Still upsert last_seen even without hostname
      await pool.query(`
        INSERT INTO known_hosts (ip_address, last_seen)
        VALUES ($1::inet, NOW())
        ON CONFLICT (ip_address) DO UPDATE SET last_seen = NOW()
      `, [cleanIP]);
    }
  } catch (err) {
    // Non-fatal — DNS enrichment is best-effort
    if (!err.message.includes('ENOTFOUND') && !err.message.includes('ENODATA')) {
      console.error(`[DNS] Enrichment error for ${cleanIP}:`, err.message);
    }
  }
}

module.exports = { reverseLookup, enrichIP, configureDNS };
