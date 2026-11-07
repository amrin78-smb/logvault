'use strict';

/**
 * Tests for the stored-ReDoS mitigation (collector/safeRegex.js).
 *
 * Pre-fix, POST /api/alerts/rules validated `match_pattern` for SYNTAX ONLY
 * (`try { new RegExp(p) }`) and the collector then ran it against every
 * ingested entry with no bound at all. The two halves tested here are the
 * write-time screen (must reject the catastrophic shapes WITHOUT rejecting
 * legitimate alert patterns) and the match-time budget/quarantine (must bound
 * the damage of a pattern that reached the DB another way).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const sr = require('../collector/safeRegex');

// ── write-time screen: it must REJECT ──────────────────────────────────────

test('the classic nested-quantifier shapes are rejected statically', () => {
  for (const p of ['(a+)+$', '(a*)*$', '(a+)*$', '([a-z]+)+$', '(\\d+){2,}$', '((a+)+)+$', '(x+x+)+y']) {
    const reason = sr.staticScreen(p);
    assert.ok(reason, `${p} must be rejected`);
    assert.match(reason, /nested quantifier/);
    // new RegExp() accepts every one of them — which is exactly why
    // syntax-only validation was not a check at all.
    assert.equal(sr.syntaxError(p), null, `${p} is valid syntax`);
  }
});

test('absurd bounded repetition and over-long patterns are rejected', () => {
  assert.match(sr.staticScreen('a{100000}'), /bounded repetition/);
  assert.match(sr.staticScreen('(ab){5000,}'), /bounded repetition/);
  assert.match(sr.staticScreen('a'.repeat(sr.MAX_PATTERN_LENGTH + 1)), /too long/);
});

test('a pattern with no nested quantifier but exponential backtracking is caught by the probe', () => {
  // Overlapping alternation: static analysis cannot see this (no quantified
  // group contains a quantifier), so the empirical probe has to earn its keep.
  //
  // NOTE on what is deliberately NOT asserted: `(a|ab)*c$` is the textbook
  // "ambiguous alternation" example, but measured against this V8 it is fast on
  // every input shape tried (the 'a' branch dead-ends on the next character, so
  // the search tree stays bounded). It is not listed below, because asserting
  // that the probe rejects it would be asserting something untrue about the
  // engine. The probe catches patterns that are ACTUALLY slow here, which is
  // the property that matters — it is not a complete detector, which is why the
  // match-time budget below exists behind it.
  for (const p of ['(a|a)*$', '(a|a|a)*$']) {
    assert.equal(sr.staticScreen(p), null, `${p} is invisible to the static screen`);
    const reason = sr.unsafePatternReason(p, 'i');
    assert.ok(reason, `${p} must be rejected by the probe`);
    assert.match(reason, /backtracks catastrophically/);
  }
});

test('the probe itself stays bounded — screening a hostile pattern is fast', () => {
  // The ramp (short inputs first, each gated on the previous one finishing
  // inside the budget) is what keeps the write path from hanging while it
  // measures. Generous ceiling so this is not a flaky timing test; the point
  // is that it is milliseconds, not the minutes an unramped probe would take.
  const started = Date.now();
  assert.ok(sr.unsafePatternReason('(a|a|a)*$', 'i'));
  assert.ok(sr.unsafePatternReason('(a+)+$', 'i'));
  assert.ok(Date.now() - started < 3000, `screening took ${Date.now() - started}ms`);
});

test('invalid syntax is still rejected, with the engine reason', () => {
  assert.match(sr.unsafePatternReason('(unclosed', 'i'), /invalid regex/);
  assert.match(sr.unsafePatternReason('a{2,1}', 'i'), /invalid regex/);
});

// ── write-time screen: it must ACCEPT ──────────────────────────────────────
//
// A false positive here is not cosmetic: it would 400 a legitimate alert rule,
// and if the seeded rules in scripts/schema.sql ever stopped passing, an admin
// could not re-save them.

test('the rule patterns LogVault actually ships are accepted', () => {
  const real = [
    // scripts/schema.sql's seeded 'Auth Failures' rule, verbatim.
    'login fail|authentication fail|failed login|failed authentication|ssl-login-fail|logon fail',
    'Interface .* changed state to down',
    '^%ASA-[0-9]-[0-9]+',
    'denied|blocked|dropped',
    '.*',
    '.*deny.*',
    'srcip=\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}',
    '^(ERROR|WARN)\\s+\\[[a-z0-9_-]+\\]\\s+.*(denied|blocked)$',
    '(?:config|configuration)\\s+(?:change|changed)',
    'user[=:]\\s*\\w+',
    '[a-z]*[0-9]*fail',
    'a?b?c?d?e?f?g?h?',          // many optionals, but '?' cannot blow up
    '(abc)+',                    // quantified group with NO inner quantifier
    '(a|b|c)+',                  // non-overlapping alternation
  ];
  for (const p of real) {
    assert.equal(sr.unsafePatternReason(p, 'i'), null, `${p} must be accepted`);
  }
});

test('match_host is screened in its EXPANDED form, the one the collector runs', () => {
  assert.equal(sr.hostPatternToRegexSource('FGT%_TUS'), 'FGT.*_TUS');
  assert.equal(sr.hostPatternToRegexSource('%'), '.*');
  assert.equal(sr.unsafePatternReason(sr.hostPatternToRegexSource('FGT%_TUS'), 'i'), null);
  // A hostile match_host reaches the same hot path as match_pattern.
  assert.ok(sr.unsafePatternReason(sr.hostPatternToRegexSource('(a+)+$'), 'i'));
});

test('an absent pattern is not an error (no pattern = match all)', () => {
  assert.equal(sr.unsafePatternReason(null), null);
  assert.equal(sr.unsafePatternReason(''), null);
  assert.equal(sr.unsafePatternReason(undefined), null);
  assert.equal(sr.unsafePatternReason(42), 'pattern must be a string');
});

// ── match-time budget + quarantine ─────────────────────────────────────────

test('testWithBudget returns correct match results and does not lose matches', () => {
  sr._resetState();
  // The behaviour that must NOT regress: a legitimate rule still matches what
  // it matched before, and a non-match is a non-match (not a skip).
  const p = 'login fail|authentication fail';
  assert.deepEqual(
    { ...sr.testWithBudget(p, 'SSL VPN login fail from 203.0.113.9', 'test'), ms: 0 },
    { matched: true, skipped: false, ms: 0 });
  assert.equal(sr.testWithBudget(p, 'LOGIN FAIL', 'test').matched, true, 'case-insensitive, as before');
  assert.equal(sr.testWithBudget(p, 'all good', 'test').matched, false);
  assert.equal(sr.testWithBudget(p, 'all good', 'test').skipped, false);
  assert.equal(sr.testWithBudget(p, null, 'test').matched, false);
  assert.equal(sr.quarantineReport().length, 0, 'a healthy pattern is never quarantined');
});

test('a cached pattern keeps no state between calls', () => {
  sr._resetState();
  const p = 'fail';
  for (let i = 0; i < 5; i++) {
    assert.equal(sr.testWithBudget(p, 'login fail', 'test').matched, true, `call ${i}`);
  }
  // compile() returns the same object (the hot path no longer recompiles per
  // message), which is only safe because lastIndex is reset.
  assert.equal(sr.compile(p, 'i'), sr.compile(p, 'i'));
});

test('an uncompilable pattern is skipped, not thrown', () => {
  sr._resetState();
  const r = sr.testWithBudget('(unclosed', 'anything', 'test');
  assert.deepEqual(r, { matched: false, skipped: true, ms: 0 });
});

test('a pattern that blows the per-message budget is quarantined after one message', () => {
  sr._resetState();
  const evil = '(a+)+$';
  const input = `${'a'.repeat(25)}!`;   // ~2^25 backtracks: hundreds of ms

  const first = sr.testWithBudget(evil, input, 'rule 1 (Evil) match_pattern');
  assert.equal(first.skipped, false, 'the FIRST message is still evaluated — we cannot preempt V8');
  assert.ok(first.ms > sr.MATCH_BUDGET_MS,
    `expected the probe input to exceed the ${sr.MATCH_BUDGET_MS}ms budget, took ${first.ms}ms`);

  // THE mitigation: every later message skips it, so one bad rule costs one
  // message instead of halting ingestion for the life of the process.
  assert.equal(sr.isQuarantined(evil, 'i'), true);
  const second = sr.testWithBudget(evil, input, 'rule 1 (Evil) match_pattern');
  assert.deepEqual(second, { matched: false, skipped: true, ms: 0 });

  // And it is reportable, so the suppressed rule cannot pass unnoticed.
  const report = sr.quarantineReport();
  assert.equal(report.length, 1);
  assert.equal(report[0].pattern, evil);
  assert.match(report[0].label, /rule 1 \(Evil\) match_pattern/);

  // Quarantine is keyed on the pattern TEXT, so editing the rule to a safe
  // pattern un-blocks it with no restart.
  assert.equal(sr.isQuarantined('login fail', 'i'), false);
  assert.equal(sr.testWithBudget('login fail', 'login fail', 'rule 1 fixed').matched, true);
});
