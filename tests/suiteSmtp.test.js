'use strict';

/**
 * collector/suiteSmtp.js — the two things that have no second chance at runtime:
 *   1. the decrypt is byte-compatible with the format the HUB writes, and
 *   2. nothing in this module can throw into the collector.
 */

const test   = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { decryptSecret, resolveSmtp, _resetCache } = require('../collector/suiteSmtp');

// ── 1. CROSS-IMPLEMENTATION FIXED VECTOR ───────────────────────────────────
//
// This ciphertext was produced by ddivault/collector/credStore.js's encrypt()
// — the module net-vault/lib/credStore.ts (which writes netvault.smtp_config's
// password column) is itself a copy of — under the secret below. It is pasted
// here as a LITERAL on purpose: re-deriving it with this file's own crypto
// would only prove the module agrees with itself. If this test fails, the three
// implementations have drifted and a hub-written password will not decrypt in
// LogVault.
const VECTOR_SECRET = 'nocvault-suite-smtp-test-secret';
const VECTOR_CIPHER =
  'b0a9ad2995f8593cb4d11d0c:9617a295ecb5c5863afe49f985c00e3d:' +
  'b59f22c4b16746406685c5eb785b6dd7d42376454f4a947426529a782d697f1b04609656';
const VECTOR_PLAIN = 'P@ssw0rd-with-ünïcode-and-:colons:';

test('decrypts a value produced by ddivault credStore under the same secret', () => {
  assert.strictEqual(decryptSecret(VECTOR_CIPHER, VECTOR_SECRET), VECTOR_PLAIN);
});

test('decrypt returns null (never throws) on the failure shapes', () => {
  assert.strictEqual(decryptSecret(VECTOR_CIPHER, 'a-different-secret'), null, 'wrong key');
  assert.strictEqual(decryptSecret(VECTOR_CIPHER, ''), null, 'no secret at all');
  assert.strictEqual(decryptSecret('not:enough'), null, 'malformed');
  assert.strictEqual(decryptSecret('zz:zz:zz', VECTOR_SECRET), null, 'non-hex');
  assert.strictEqual(decryptSecret('', VECTOR_SECRET), '', 'empty stays empty');
});

test('key derivation is sha256(secret), 12-byte IV, aes-256-gcm', () => {
  // A second, independent assertion of the contract: encrypt here with the
  // documented parameters and require this module to read it back.
  const key = crypto.createHash('sha256').update(VECTOR_SECRET).digest();
  const iv  = crypto.randomBytes(12);
  const c   = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update('hello', 'utf8'), c.final()]);
  const blob = `${iv.toString('hex')}:${c.getAuthTag().toString('hex')}:${enc.toString('hex')}`;
  assert.strictEqual(decryptSecret(blob, VECTOR_SECRET), 'hello');
});

// ── 2. FAIL SOFT ───────────────────────────────────────────────────────────
//
// NETVAULT_DB_* points at nothing in a test run, so the hub lookup fails at
// connect. That is one of the four documented fallbacks and must surface as the
// local config, not as a rejected promise — a throw here would reach the
// collector's own alert path.
test('resolveSmtp falls back to the local config when the hub DB is unreachable', async () => {
  _resetCache();
  process.env.NETVAULT_DB_HOST = '127.0.0.1';
  process.env.NETVAULT_DB_PORT = '1';   // nothing listens here
  const local = { host: 'smtp.local', port: 587, user: 'u', pass: 'p', from: 'LogVault <a@b.c>', enabled: true };
  const r = await resolveSmtp(local);
  assert.strictEqual(r.source, 'local');
  assert.strictEqual(r.cfg.host, 'smtp.local');
  assert.strictEqual(r.cfg.from, 'LogVault <a@b.c>');
  // A local config must never claim the hub's explicit `secure` column.
  assert.strictEqual(r.cfg.secureExplicit, false);
});

test('resolveSmtp tolerates being called with nothing at all', async () => {
  _resetCache();
  const r = await resolveSmtp(undefined);
  assert.strictEqual(r.source, 'local');
  assert.ok(r.cfg);
});
