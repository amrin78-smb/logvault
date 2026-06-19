'use strict';

/**
 * GeoIP + threat-intel enrichment for external IPs.
 *
 * Uses FREE APIs, no extra npm deps (built-in http/https only):
 *   - GeoIP  : ip-api.com   (free tier is HTTP-only, 45 req/min)
 *   - Threat : AbuseIPDB    (only when an API key is configured)
 *
 * Hard rules:
 *   - Private/internal IPs and ANY IPv6 are NEVER sent to external APIs.
 *   - enrichExternalIP NEVER throws — returns null on any failure.
 *   - The AbuseIPDB API key is never logged.
 */

const http  = require('http');
const https = require('https');

const USER_AGENT = 'LogVault/2.0 (NocVault)';

// In-memory cache: ip → { data, cachedAt }. TTL 7 days.
const cache = new Map();
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// IPs currently being enriched — dedupe concurrent lookups.
const pendingEnrich = new Set();

// ip-api free tier is 45 req/min. Keep a tiny non-blocking min-interval guard
// so a sudden burst of brand-new IPs doesn't trip the limit. ~1.4s spacing.
const MIN_INTERVAL_MS = 1400;
let lastFetchAt = 0;

/**
 * True for IPs that must NOT be sent to external APIs:
 *   RFC1918 (10/8, 172.16-31, 192.168/16), 127/8 loopback,
 *   169.254/16 link-local, 0.0.0.0, and ANY IPv6 (contains ':').
 */
function isPrivateIP(ip) {
  if (!ip) return true;
  const clean = String(ip).replace(/\/\d+$/, '').trim();
  if (!clean) return true;
  if (clean.indexOf(':') !== -1) return true; // any IPv6 — skip
  const parts = clean.split('.');
  if (parts.length !== 4) return true; // not a clean IPv4 — skip to be safe
  const o = parts.map(p => parseInt(p, 10));
  if (o.some(n => isNaN(n) || n < 0 || n > 255)) return true;
  if (o[0] === 10) return true;                              // 10.0.0.0/8
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16.0.0/12
  if (o[0] === 192 && o[1] === 168) return true;             // 192.168.0.0/16
  if (o[0] === 127) return true;                             // 127.0.0.0/8
  if (o[0] === 169 && o[1] === 254) return true;             // 169.254.0.0/16
  if (o[0] === 0) return true;                               // 0.0.0.0/8
  return false;
}

/**
 * Fetch + parse JSON with a hard timeout. Picks http/https by URL scheme.
 * Destroys the socket on timeout. Resolves parsed JSON; rejects on any error.
 */
function fetchJSON(url, opts, timeoutMs) {
  const t = timeoutMs || 8000;
  const mod = url.startsWith('https:') ? https : http;
  const reqOpts = Object.assign({}, opts);
  reqOpts.headers = Object.assign({ 'User-Agent': USER_AGENT }, (opts && opts.headers) || {});

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, arg) => { if (!settled) { settled = true; fn(arg); } };

    const req = mod.get(url, reqOpts, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try { done(resolve, JSON.parse(body)); }
        catch (err) { done(reject, err); }
      });
    });

    req.setTimeout(t, () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', err => done(reject, err));
  });
}

// Parse the leading AS number out of ip-api's `as` string, e.g. "AS15169 Google LLC".
function parseAsn(asStr) {
  if (!asStr) return null;
  const m = String(asStr).match(/AS(\d+)/i);
  return m ? `AS${m[1]}` : null;
}

// Build a small string[] of threat tags from AbuseIPDB data.
function buildThreatTags(d) {
  const tags = [];
  if (!d) return tags;
  if (d.usageType) tags.push(String(d.usageType));
  if (d.isTor) tags.push('tor');
  if (d.isWhitelisted === false && d.abuseConfidenceScore >= 50) tags.push('reported-abuse');
  if (d.totalReports && d.totalReports > 0) tags.push(`${d.totalReports} reports`);
  return tags;
}

/**
 * Enrich an external IP. Returns the enrichment object or null.
 * NEVER throws.
 */
async function enrichExternalIP(ip, apiKey) {
  try {
    if (!ip) return null;
    const cleanIP = String(ip).replace(/\/\d+$/, '').trim();
    if (isPrivateIP(cleanIP)) return null;

    // Fresh cache hit?
    const cached = cache.get(cleanIP);
    if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) return cached.data;

    // Already in flight — skip (the in-flight one will populate the cache).
    if (pendingEnrich.has(cleanIP)) return null;
    pendingEnrich.add(cleanIP);

    try {
      // Tiny non-blocking spacing guard for ip-api's 45 req/min limit.
      const since = Date.now() - lastFetchAt;
      if (since < MIN_INTERVAL_MS) {
        await new Promise(r => setTimeout(r, MIN_INTERVAL_MS - since));
      }
      lastFetchAt = Date.now();

      // ── GeoIP via ip-api.com (HTTP only on the free tier) ──
      let geo = null;
      try {
        const url = `http://ip-api.com/json/${encodeURIComponent(cleanIP)}` +
          `?fields=status,message,country,countryCode,city,as,asname`;
        const r = await fetchJSON(url, {}, 8000);
        if (r && r.status === 'success') geo = r;
      } catch (_) { /* geo best-effort */ }

      // ── Threat via AbuseIPDB (only if a key is configured) ──
      let abuseScore = null;
      let threatTags = [];
      if (apiKey && String(apiKey).trim()) {
        try {
          const url = `https://api.abuseipdb.com/api/v2/check` +
            `?ipAddress=${encodeURIComponent(cleanIP)}&maxAgeInDays=90`;
          const r = await fetchJSON(url, {
            headers: { Key: String(apiKey).trim(), Accept: 'application/json' },
          }, 8000);
          const d = r && r.data;
          if (d) {
            if (typeof d.abuseConfidenceScore === 'number') abuseScore = d.abuseConfidenceScore;
            threatTags = buildThreatTags(d);
          }
        } catch (_) { /* threat best-effort */ }
      }

      // If we got nothing at all, don't cache a useless empty result.
      if (!geo && abuseScore === null) return null;

      const data = {
        is_external:  true,
        country_code: geo ? (geo.countryCode || null) : null,
        country_name: geo ? (geo.country || null) : null,
        city:         geo ? (geo.city || null) : null,
        asn:          geo ? parseAsn(geo.as) : null,
        asn_org:      geo ? (geo.asname || geo.as || null) : null,
        abuse_score:  abuseScore,
        is_known_bad: abuseScore !== null && abuseScore >= 50,
        threat_tags:  threatTags,
        last_enriched: new Date(),
      };

      cache.set(cleanIP, { data, cachedAt: Date.now() });
      return data;
    } finally {
      pendingEnrich.delete(cleanIP);
    }
  } catch (_) {
    return null; // NEVER throw
  }
}

module.exports = { enrichExternalIP, isPrivateIP };
