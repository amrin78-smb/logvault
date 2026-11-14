'use strict';

/**
 * suiteSmtp.js — resolve the SMTP TRANSPORT from the NocVault hub, with a
 * fail-soft fallback to LogVault's own `app_settings` config.
 *
 * Phase 2 of the suite SMTP centralization
 * (net-vault/docs/nocvault-smtp-centralization-plan.md §3, §5).
 *
 * WHAT THE HUB OWNS: host, port, secure, username, password, allow_self_signed.
 * WHAT STAYS LOCAL:  the From identity (`smtp_from`), the `smtp_enabled` master
 *                    switch, recipients, severity/category/vendor filters,
 *                    cooldowns, digest mode and the HTML templates. Centralizing
 *                    the transport must not change WHO gets mail or WHICH alerts
 *                    send — only which relay carries them.
 *
 * WHY IT LIVES IN collector/ RATHER THAN A NEW ROOT lib/: this repo already has
 * exactly this shape twice — collector/emailer.js and collector/safeRegex.js are
 * both required by api/server.js. The api -> collector direction is the existing
 * convention for code both processes need; a new top-level lib/ would be a third
 * place to look for shared code.
 *
 * ⛔ THIS MODULE MUST NOT THROW. EVER. NOT AT LOAD, NOT ON ANY CALL.
 *
 * ⛔ DO NOT ADD A MODULE-LOAD THROW WHEN `NEXTAUTH_SECRET` IS ABSENT, even
 *    though ddivault/collector/credStore.js — the module this decrypt is a
 *    byte-for-byte copy of — does exactly that, and even though doing so looks
 *    like the obviously-correct security posture.
 *
 *    The difference is what each module is reached from. credStore.js guards
 *    WRITES: it is the thing that would otherwise encrypt a real DHCP/DNS admin
 *    password under a known hardcoded fallback key, so failing loud at load is
 *    right there. THIS module only ever READS, and it is required (via
 *    collector/emailer.js) by **collector/collector.js** — the syslog receiver.
 *    A throw at module load in this file does not disable email; it stops the
 *    collector from starting at all, which stops syslog ingestion for the whole
 *    product. Trading log ingestion for a mail setting is never the right call.
 *
 *    The window where this matters is real, not hypothetical: the hub's
 *    `smtp_config` table ships in a NetVault release, and a suite where NetVault
 *    has not been updated yet will answer this module's query with
 *    `42P01 undefined_table`. That is the NORMAL state of a mid-upgrade suite,
 *    and it must read as "no hub config, use local", not as an incident.
 *
 *    So: every failure path here falls back to the caller's local config and
 *    warns ONCE per process. Never per call, never per email.
 */

const crypto   = require('crypto');
const { Pool } = require('pg');

// Matches the app's dynamic-settings pattern (CLAUDE.md "Dynamic Settings — No
// Restart Pattern"): a hub SMTP change is picked up within 5 minutes with no
// service restart. Negative results are cached for the same window, so a hub
// that has no smtp_config table is queried at most once per 5 minutes rather
// than once per email.
const CACHE_TTL = 5 * 60 * 1000;

const ALGORITHM = 'aes-256-gcm';

let hubCache   = null;   // the last resolved hub config, or null for "no hub config"
let hubCacheAt = 0;
// ⛔ ONE LOOKUP AT A TIME, SHARED BY EVERY CONCURRENT CALLER. See the long note
// on getHubSmtp() — the TTL cache bounds how OFTEN we ask, this bounds how many
// ask at once, and only the second one survives a burst of alert emails.
let hubInflight   = null;
let hubGeneration = 0;
let nvPool     = null;   // created lazily — see getPool()
let lastSource = null;   // for the one-line log when the active source changes

// Warn-once bookkeeping. Keyed by failure reason, never by call site, so a
// repeated failure stays at exactly one log line per process.
const warned = new Set();
function warnOnce(key, message) {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(`[SuiteSMTP] ${message}`);
}

/**
 * The NetVault pool. Same credentials and shape as collector/netvaultSync.js's
 * nvPool (the `netvault` role, which owns smtp_config and needs no new grant),
 * but deliberately smaller and shorter-fused: this is a 5-minutely config read,
 * not a sync job, and it must never be the thing that holds up an alert email.
 *
 * Created lazily so that merely requiring this file opens no sockets and reads
 * no env.
 */
function getPool() {
  if (nvPool) return nvPool;
  nvPool = new Pool({
    host:     process.env.NETVAULT_DB_HOST || 'localhost',
    port:     parseInt(process.env.NETVAULT_DB_PORT || '5432', 10) || 5432,
    database: process.env.NETVAULT_DB_NAME || 'netvault',
    user:     process.env.NETVAULT_DB_USER || 'netvault',
    password: process.env.NETVAULT_DB_PASS,
    ssl:      false,
    max:      2,
    idleTimeoutMillis:       10000,
    connectionTimeoutMillis: 3000,
    query_timeout:           5000,
    statement_timeout:       5000,
  });
  // ⛔ REQUIRED, not defensive. node-postgres emits 'error' on a pool whose IDLE
  // client dies (a Postgres restart, an idle-session timeout, a dropped link).
  // An 'error' event with no listener is rethrown by EventEmitter as an
  // uncaught exception — which api/server.js turns into process.exit(1) and
  // which would take the COLLECTOR down from a background socket event that has
  // nothing to do with any call this module made. Swallow it: the next query
  // will open a fresh client, and if that also fails it falls back to local.
  nvPool.on('error', (err) => {
    warnOnce('pool', `NetVault pool error, hub SMTP lookups may fall back to local config: ${err.message}`);
  });
  return nvPool;
}

/**
 * Decrypt a hub-stored password.
 *
 * ⛔ CONTRACT: byte-identical to ddivault/collector/credStore.js and
 * net-vault/lib/credStore.ts — AES-256-GCM, stored as `ivHex:tagHex:cipherHex`,
 * 12-byte IV, key = sha256(NEXTAUTH_SECRET). A value written by the hub MUST
 * decrypt here. If you change the format in any of those three files, change it
 * in all of them (tests/suiteSmtp.test.js pins a fixed vector produced by
 * ddivault's credStore for exactly this reason).
 *
 * The secret is read at CALL time, never at module load — see the ⛔ at the top.
 *
 * @returns {string|null} plaintext, or null when it could not be decrypted.
 */
function decryptSecret(encrypted, secret) {
  if (!encrypted) return '';
  if (!secret) return null;
  try {
    const parts = String(encrypted).split(':');
    if (parts.length !== 3) return null;
    const key      = crypto.createHash('sha256').update(secret).digest();
    const iv       = Buffer.from(parts[0], 'hex');
    const tag      = Buffer.from(parts[1], 'hex');
    const data     = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch (_err) {
    // Never log the error text — a GCM failure message is not sensitive, but the
    // caller logs a single sanitized line and the password must stay out of it.
    return null;
  }
}

/**
 * Read the hub's SMTP transport, or null when there is not a usable one.
 * NEVER throws, NEVER rejects.
 *
 * @returns {Promise<null|{host,port,secure,username,password,fromEmail,allowSelfSigned}>}
 */
async function getHubSmtp() {
  const now = Date.now();
  // hubCacheAt === 0 means "never looked", which is NOT the same as "looked and
  // found nothing" (hubCache === null with a timestamp) — the second is a real,
  // cacheable answer and must not re-query for 5 minutes.
  if (hubCacheAt !== 0 && now - hubCacheAt < CACHE_TTL) return hubCache;

  // ── The cache does not bound CONCURRENCY, only frequency ────────────────
  // It is written once an answer exists, so every send that starts inside the
  // same cold window opens its own lookup. A correlation rule firing on a burst
  // of syslog does exactly that, and this pool is deliberately small with a
  // short connect timeout: the lookups then fail on contention, each returns
  // null, each null reads as "the hub offers no mail server", and the last one
  // to land writes that into the cache for the next five minutes. The burst
  // manufactured the fallback it would then be blamed on.
  //
  // Callers arriving while a lookup is open therefore await the SAME promise. A
  // rejection is deliberately NOT cached (the `.then` never runs), so an
  // unforeseen throw cannot freeze the answer either.
  if (hubInflight) return hubInflight;
  const gen = hubGeneration;
  const p = readHubRow()
    .then((hub) => {
      // A _resetCache() (or a save) that landed mid-flight wins: this answer is
      // handed to whoever was waiting but must not become the cached one.
      if (gen === hubGeneration) { hubCache = hub; hubCacheAt = Date.now(); }
      return hub;
    })
    .finally(() => { if (hubInflight === p) hubInflight = null; });
  hubInflight = p;
  return p;
}

/**
 * The actual read. Returns the hub transport or null; never throws, never
 * rejects — every failure path returns null after warning once.
 */
async function readHubRow() {
  let row = null;
  try {
    const { rows } = await getPool().query(
      `SELECT host, port, secure, username, password, from_email, enabled, allow_self_signed
         FROM smtp_config
        ORDER BY id
        LIMIT 1`
    );
    row = rows[0] || null;
  } catch (err) {
    // FALLBACK 1 — the hub has no smtp_config table. This is a NetVault that
    // predates the feature, which is the normal state of a partly-upgraded
    // suite. Calm wording on purpose: it is not a fault.
    if (err && err.code === '42P01') {
      warnOnce('no_table',
        'NetVault has no smtp_config table (hub not updated yet) — using this app\'s own SMTP settings.');
    } else {
      // FALLBACK 2 — any other query or connection error: unreachable DB,
      // bad/absent NETVAULT_DB_PASS, timeout, permission denied.
      warnOnce('query',
        `Could not read the hub SMTP config (${(err && err.message) || 'unknown error'}) — using this app\'s own SMTP settings.`);
    }
    return null;
  }

  // No row, disabled, or no host => the hub is not offering a transport. Not a
  // failure and not worth a warning — it is the default state of the feature.
  if (!row || row.enabled !== true || !row.host || !String(row.host).trim()) {
    return null;
  }

  // FALLBACK 3 — NEXTAUTH_SECRET missing. Only an obstacle when there is
  // actually a password to decrypt: an on-premises relay with no auth stores an
  // empty password, and that config is perfectly usable without the secret.
  const stored = row.password || '';
  let password = '';
  if (stored) {
    const secret = process.env.NEXTAUTH_SECRET;
    if (!secret) {
      warnOnce('no_secret',
        'NEXTAUTH_SECRET is not set in this process, so the hub SMTP password cannot be decrypted — using this app\'s own SMTP settings.');
      return null;
    }
    // FALLBACK 4 — the password does not decrypt under this secret (the hub was
    // reinstalled with a new NEXTAUTH_SECRET, or the column was hand-edited).
    const plain = decryptSecret(stored, secret);
    if (plain === null) {
      warnOnce('decrypt',
        'The hub SMTP password could not be decrypted with this install\'s NEXTAUTH_SECRET — using this app\'s own SMTP settings.');
      return null;
    }
    password = plain;
  }

  return {
    host:            String(row.host).trim(),
    port:            parseInt(row.port, 10) || 587,
    secure:          row.secure === true,
    username:        row.username || '',
    password,
    fromEmail:       row.from_email || '',
    allowSelfSigned: row.allow_self_signed === true,
  };
}

/**
 * Resolve the SMTP config this app should actually use.
 *
 * @param {object} localCfg  LogVault's own config as read from app_settings:
 *                           { host, port, user, pass, from, enabled }
 * @returns {Promise<{source:'hub'|'local', cfg:object}>}  NEVER throws.
 */
async function resolveSmtp(localCfg) {
  const local = localCfg || {};
  let hub = null;
  try {
    hub = await getHubSmtp();
  } catch (err) {
    // Belt-and-braces: getHubSmtp already swallows everything, but this function
    // is on the path of every alert email and the collector must never see a
    // rejection from it.
    warnOnce('resolve', `Unexpected error resolving the hub SMTP config (${(err && err.message) || 'unknown'}) — using this app\'s own SMTP settings.`);
    hub = null;
  }

  if (!hub) {
    if (lastSource !== 'local') {
      lastSource = 'local';
      console.log('[SuiteSMTP] Using this app\'s own SMTP settings.');
    }
    return { source: 'local', cfg: { ...local, secureExplicit: false, allowSelfSigned: false } };
  }

  if (lastSource !== 'hub') {
    lastSource = 'hub';
    console.log(`[SuiteSMTP] Using the NetVault hub's SMTP transport (${hub.host}:${hub.port}).`);
  }

  return {
    source: 'hub',
    cfg: {
      // ── from the hub ──
      host:   hub.host,
      port:   hub.port,
      secure: hub.secure,
      // `secure` here is a REAL stored boolean, so the caller must use it
      // verbatim instead of deriving TLS from `port === 465`. A relay on 25 or
      // 2525 speaking STARTTLS has no correct derived answer. This flag tells
      // buildTransport() which of the two it is looking at.
      secureExplicit:  true,
      allowSelfSigned: hub.allowSelfSigned,
      user: hub.username,
      pass: hub.password,

      // ── stays local ──
      // The From identity is deliberately NOT centralized (plan §3): seeing
      // "LogVault Alerts" rather than a generic suite sender is the point. The
      // hub's own from_email is only a last resort for an install that never
      // filled in smtp_from — previously that fell through to the local SMTP
      // username, which is empty whenever the hub owns the transport.
      from: local.from || hub.fromEmail || '',
      // LogVault's own master switch still decides whether mail is sent at all.
      // Centralizing the transport must not turn email on for an install that
      // had it off.
      enabled: local.enabled === true,
    },
  };
}

/** Test seam — drop the cached hub config and the warn-once state. */
function _resetCache() {
  hubCache = null;
  hubCacheAt = 0;
  // Bumping the generation is what stops a lookup already in the air from
  // writing its stale answer over the next one.
  hubInflight = null;
  hubGeneration += 1;
  lastSource = null;
  warned.clear();
}

module.exports = { resolveSmtp, getHubSmtp, decryptSecret, _resetCache, CACHE_TTL };
