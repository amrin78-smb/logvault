'use strict';

/**
 * Tests for the acknowledge write path (api/ackScope.js), i.e. the HIGH finding
 * where all four acknowledge routes ran with no role gate and no site filter.
 *
 * The role gate itself is Express middleware (`requireAdmin` from api/rbac.js)
 * and is tested here against the middleware directly — api/server.js cannot be
 * required from a test, because requiring it starts the HTTP listener and
 * connects to Postgres. The wiring of that middleware onto the four routes is
 * therefore NOT covered by an automated test; it was verified by reading the
 * four `app.patch(... requireAdmin ...)` registrations.
 *
 * What IS covered end-to-end as pure functions: the id validation, the
 * empty-ids 400, and the exact SQL + bind parameters the routes execute —
 * including that `alert_events` is scoped by source_host and not source_ip.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { MAX_ACK_IDS, parseAckId, parseAckIds, buildAckUpdate } = require('../api/ackScope');
const { requireAdmin, getAlertSiteFilter, getSiteFilter } = require('../api/rbac');

const ADMIN      = { role: 'admin', isAdmin: true, isSuperAdmin: false, userId: 1, allowedSiteIds: null };
const SCOPED     = { role: 'user',  isAdmin: false, isSuperAdmin: false, userId: 9, allowedSiteIds: [5, 7] };
const NO_SITES   = { role: 'user',  isAdmin: false, isSuperAdmin: false, userId: 9, allowedSiteIds: [] };

// ── id validation ──────────────────────────────────────────────────────────

test('parseAckId accepts a positive int and rejects everything else', () => {
  assert.equal(parseAckId('12'), 12);
  assert.equal(parseAckId(12), 12);
  assert.equal(parseAckId(' 12 '), 12);

  // The pre-fix routes passed req.params.id straight to an int column: these
  // all reached Postgres and 500'd with 22P02 instead of answering 400.
  assert.equal(parseAckId('abc'), null);
  assert.equal(parseAckId("1 OR 1=1"), null);
  assert.equal(parseAckId(''), null);
  assert.equal(parseAckId(undefined), null);
  assert.equal(parseAckId('0'), null);
  assert.equal(parseAckId('-3'), null);
  assert.equal(parseAckId('1.5'), null);
  assert.equal(parseAckId('1e3'), null);
  // parseInt('7abc') is 7 — a DIFFERENT but perfectly valid row.
  assert.equal(parseAckId('7abc'), null);
  // int4 upper bound.
  assert.equal(parseAckId('2147483647'), 2147483647);
  assert.equal(parseAckId('2147483648'), null);
});

test('parseAckIds requires a non-empty id array — empty is 400, never "all"', () => {
  // THE finding: an empty/missing body used to take the else-branch and
  // acknowledge every open alert estate-wide.
  assert.ok(parseAckIds(undefined).error);
  assert.ok(parseAckIds({}).error);
  assert.ok(parseAckIds({ ids: [] }).error);
  assert.ok(parseAckIds({ ids: null }).error);
  assert.ok(parseAckIds({ ids: 'all' }).error);
  assert.ok(parseAckIds({ ids: ['abc', '-1', 0, 1.5] }).error);
  // No `ids` key is reported, so a caller can never read the error as success.
  assert.equal(parseAckIds({}).ids, undefined);
});

test('parseAckIds normalises, de-duplicates and caps the id list', () => {
  assert.deepEqual(parseAckIds({ ids: [3, '4', 4, 3] }).ids, [3, 4]);
  // Invalid entries are dropped, valid ones survive.
  assert.deepEqual(parseAckIds({ ids: ['x', 8, null, 9] }).ids, [8, 9]);
  const many = parseAckIds({ ids: Array.from({ length: MAX_ACK_IDS + 50 }, (_, i) => i + 1) });
  assert.equal(many.ids.length, MAX_ACK_IDS);
});

// ── SQL + site scoping ─────────────────────────────────────────────────────

test('buildAckUpdate always constrains by an explicit id list', () => {
  const { sql } = buildAckUpdate('alert_events', [1, 2], '9', getAlertSiteFilter(ADMIN, 3, 'ae'));
  assert.match(sql, /ae\.id = ANY\(\$1::int\[\]\)/);
  // The pre-fix "acknowledge everything open" statement must not be
  // constructible at all any more.
  assert.doesNotMatch(sql, /WHERE\s+acknowledged\s*=\s*FALSE/i);
  assert.match(sql, /RETURNING ae\.id/);
});

test('buildAckUpdate refuses an empty id list and an unknown table', () => {
  assert.throws(() => buildAckUpdate('alert_events', [], '9', { clause: '', params: [] }));
  assert.throws(() => buildAckUpdate('syslog_entries', [1], '9', { clause: '', params: [] }));
});

test('alert ack for an admin is unscoped and binds exactly ids + actor', () => {
  const sf = getAlertSiteFilter(ADMIN, 3, 'ae');
  const { sql, params } = buildAckUpdate('alert_events', [11, 12], '1', sf);
  assert.equal(sf.clause, '');
  assert.deepEqual(params, [[11, 12], '1']);
  assert.doesNotMatch(sql, /known_hosts/);
});

test('alert ack for a site-scoped user is scoped by source_host, NOT source_ip', () => {
  const sf = getAlertSiteFilter(SCOPED, 3, 'ae');
  const { sql, params } = buildAckUpdate('alert_events', [11], '9', sf);

  // This is the whole point of the finding: the UPDATE now carries the SAME
  // predicate GET /api/alerts/events uses, so a user can only acknowledge
  // alerts from relays at their own sites.
  assert.match(sql, /ae\.source_host IN \(/);
  assert.match(sql, /known_hosts kh/);
  assert.match(sql, /kh\.site_id = ANY\(\$3::int\[\]\)/);
  // ae.source_ip is the internal ACTOR ip and must NOT be the scoping key —
  // filtering on it collapses alert visibility to zero for every scoped user.
  assert.doesNotMatch(sql, /ae\.source_ip/);
  assert.deepEqual(params, [[11], '9', [5, 7]]);
});

test('alert ack for a user with no assigned sites matches nothing', () => {
  const sf = getAlertSiteFilter(NO_SITES, 3, 'ae');
  const { sql, params } = buildAckUpdate('alert_events', [11], '9', sf);
  assert.match(sql, /AND 1=0/);
  assert.deepEqual(params, [[11], '9']);
});

// anomaly_events uses server.js's anomalySiteFilter (getSiteFilter on
// source_ip, plus an IS NULL allowance). That wrapper lives in server.js, which
// cannot be required here, so the wrapper is reproduced exactly as server.js
// defines it — if the two ever diverge this test is testing the wrong thing,
// which is why the shape is asserted rather than just the presence of a clause.
function anomalySiteFilter(rbac, startParamIndex, tableAlias) {
  const sf = getSiteFilter(rbac, startParamIndex, tableAlias);
  if (!sf.clause) return sf;
  const inner = sf.clause.replace(/^AND\s+/i, '');
  return {
    clause: `AND (${inner} OR ${tableAlias}.source_ip IS NULL)`,
    params: sf.params,
    nextParamIndex: sf.nextParamIndex,
  };
}

test('anomaly ack is scoped by source_ip with the same NULL allowance as the read', () => {
  const sf = anomalySiteFilter(SCOPED, 3, 'ae');
  const { sql, params } = buildAckUpdate('anomaly_events', [4], '9', sf);
  assert.match(sql, /UPDATE anomaly_events ae/);
  assert.match(sql, /ae\.source_ip IN \(/);
  assert.match(sql, /OR ae\.source_ip IS NULL/);
  assert.deepEqual(params, [[4], '9', [5, 7]]);

  const admin = buildAckUpdate('anomaly_events', [4], '1', anomalySiteFilter(ADMIN, 3, 'ae'));
  assert.doesNotMatch(admin.sql, /known_hosts/);
});

// ── the role gate itself ───────────────────────────────────────────────────

test('requireAdmin blocks the read-only user role and allows admins', () => {
  const run = (rbac) => {
    let status = null; let body = null; let nexted = false;
    const res = { status(s) { status = s; return this; }, json(b) { body = b; return this; } };
    requireAdmin({ rbac }, res, () => { nexted = true; });
    return { status, body, nexted };
  };

  assert.deepEqual(run(SCOPED), { status: 403, body: { error: 'Insufficient permissions' }, nexted: false });
  assert.deepEqual(run(NO_SITES).status, 403);
  assert.equal(run(undefined).status, 403);           // no rbac at all = refused
  assert.equal(run(ADMIN).nexted, true);
  assert.equal(run({ isAdmin: true, isSuperAdmin: true }).nexted, true);
});
