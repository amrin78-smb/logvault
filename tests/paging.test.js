'use strict';

/**
 * Tests for the `page` clamp (api/paging.js) — the unbounded-OFFSET finding on
 * GET /api/logs. The pre-fix expression was:
 *
 *   const page   = Math.max(parseInt(req.query.page || '1'), 1);
 *   const offset = (page - 1) * limit;
 *
 * i.e. a floor but no ceiling, so ?page=100000000 became OFFSET 9,999,999,900.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { safePage, MAX_OFFSET_ROWS } = require('../api/paging');

test('ordinary pages are unchanged', () => {
  assert.deepEqual(safePage(undefined, 100), { page: 1, offset: 0, clamped: false });
  assert.deepEqual(safePage('1', 100),       { page: 1, offset: 0, clamped: false });
  assert.deepEqual(safePage('2', 100),       { page: 2, offset: 100, clamped: false });
  assert.deepEqual(safePage('7', 200),       { page: 7, offset: 1200, clamped: false });
});

test('garbage and out-of-range pages degrade to page 1, not to an error', () => {
  for (const v of ['abc', '', '0', '-5', null, {}, []]) {
    assert.deepEqual(safePage(v, 100), { page: 1, offset: 0, clamped: false }, `input ${JSON.stringify(v)}`);
  }
});

test('a huge page is clamped and the clamp is reported', () => {
  const r = safePage('100000000', 100);
  assert.equal(r.clamped, true);
  assert.ok(r.offset <= MAX_OFFSET_ROWS, `offset ${r.offset} must stay within the cap`);
  // The pre-fix value, for contrast.
  assert.equal((100000000 - 1) * 100, 9999999900);
  assert.ok(r.offset < 9999999900);
});

test('the offset is always a safe integer Postgres can bind as a bigint', () => {
  // ?page=100000000000000000000 made parseInt return 1e20 — a FLOAT — which
  // Postgres rejects for an integer parameter, so the endpoint 500'd
  // unconditionally rather than returning anything at all.
  const adversarial = [
    '100000000000000000000',
    '1'.repeat(40),
    String(Number.MAX_SAFE_INTEGER),
    '9007199254740993',
    '1e23',
    Number.POSITIVE_INFINITY,
    'Infinity',
  ];
  for (const v of adversarial) {
    const r = safePage(v, 100);
    assert.ok(Number.isSafeInteger(r.offset), `offset for ${v} must be a safe integer, got ${r.offset}`);
    assert.ok(r.offset >= 0 && r.offset <= MAX_OFFSET_ROWS, `offset for ${v} out of range: ${r.offset}`);
    assert.ok(Number.isSafeInteger(r.page));
  }
});

test('the cap is expressed in ROWS, so it holds at every page size', () => {
  for (const limit of [1, 10, 100, 200, 500]) {
    const r = safePage('99999999', limit);
    assert.equal(r.clamped, true);
    assert.ok(r.offset <= MAX_OFFSET_ROWS, `limit ${limit} -> offset ${r.offset}`);
  }
  // A nonsensical limit must not produce a division blow-up.
  for (const limit of [0, -1, NaN, undefined]) {
    const r = safePage('5', limit);
    assert.ok(Number.isSafeInteger(r.offset));
  }
});

test('the last reachable page is still reachable (the clamp is not off by one)', () => {
  const limit = 100;
  const lastPage = Math.floor(MAX_OFFSET_ROWS / limit) + 1;
  const r = safePage(String(lastPage), limit);
  assert.equal(r.clamped, false);
  assert.equal(r.offset, MAX_OFFSET_ROWS);
  assert.equal(safePage(String(lastPage + 1), limit).clamped, true);
});
