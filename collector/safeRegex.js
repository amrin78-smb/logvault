'use strict';

/**
 * Safety wrapper for OPERATOR-SUPPLIED regular expressions (alert rules).
 *
 * THE PROBLEM (stored ReDoS, fixed 2026-11)
 * -----------------------------------------
 * `alert_rules.match_pattern` and `alert_rules.match_host` are free-text
 * patterns written by an admin through POST /api/alerts/rules, and the
 * collector compiles and executes BOTH against every ingested syslog entry
 * (`checkAlertRules()` in collector.js). The write path used to validate
 * syntax only — `try { new RegExp(p) }` — so `(a+)+$` was accepted, stored,
 * and then run on every message. One catastrophically-backtracking pattern
 * pins a CPU core per message, stalls the collector's flush loop, and halts
 * ingestion: a SIEM blinded by a config write, persisting across restarts.
 *
 * WHY THERE IS NO ONE-LINE FIX
 * ----------------------------
 * Node has no way to interrupt a running regex. `vm`'s `timeout` does not
 * reliably preempt V8's backtracking loop, and a worker-thread round trip per
 * message is far too expensive for the ingest hot path. A complete STATIC
 * detector is also impossible (deciding the worst-case step count of an
 * arbitrary backtracking regex is undecidable in general). So this module is a
 * deliberate combination of three bounded, well-understood measures, with the
 * residual risk stated honestly at the bottom. No new dependency.
 *
 *   1. WRITE-TIME STATIC SCREEN (`staticScreen`)
 *      Rejects the shapes that cause exponential backtracking in practice:
 *      a quantified group whose body itself contains an unbounded quantifier
 *      ((a+)+, (a*)*, (\d+){2,}), absurd bounded repeats (a{100000}), and
 *      over-long patterns. Cheap, exact for the classic cases, incomplete by
 *      construction.
 *
 *   2. WRITE-TIME EMPIRICAL PROBE (`probe`)
 *      What static analysis cannot see — e.g. overlapping alternation like
 *      `(a|a)*$`, which is exponential but has no nested quantifier — is
 *      caught by actually RUNNING the candidate against adversarial inputs at
 *      RAMPED lengths (10, 14, 18, 22, 26 chars) with a per-step time budget.
 *      The ramp is what makes the probe itself safe: a pattern only gets a
 *      longer input if the shorter one finished inside the budget, so the
 *      worst case the API process can be made to pay is roughly one budget's
 *      worth of growth, not an open-ended hang. An exponential pattern is
 *      3-5 orders of magnitude over the budget by length 14-22; a linear one
 *      finishes in microseconds at 26. There is a wide gap to aim at.
 *
 *   3. MATCH-TIME BUDGET + QUARANTINE (`testWithBudget` / `quarantine`)
 *      Measures 1 and 2 guard the API write path, but NOT a pattern inserted
 *      straight into Postgres (migration, psql, restore of an old row written
 *      before this fix). So the collector also times each match and, when one
 *      message costs more than MATCH_BUDGET_MS, QUARANTINES that pattern:
 *      every later message skips it. We cannot preempt the first slow match,
 *      so this does not make that one message free — it bounds the damage to
 *      ONE message instead of every message for the rest of the process's
 *      life, which is the difference between a blip and a dead SIEM.
 *
 *      A quarantine means that rule stops matching, i.e. it TRADES a silent
 *      total ingest stall for a LOUD partial loss of one rule's alerts. It is
 *      therefore logged as an error on quarantine and re-reported by
 *      collector.js on every rules refresh while it holds, so it cannot pass
 *      unnoticed. Quarantine is keyed by the pattern TEXT, so an admin editing
 *      the offending rule produces a new key and is automatically un-blocked
 *      with no restart.
 *
 * RESIDUAL RISK (stated, not hidden)
 *   - A pattern that is fast on the probe inputs but catastrophic on a REAL
 *     message shape still costs one message's worth of CPU before it is
 *     quarantined. Bounded, but not zero.
 *   - The static screen is heuristic: it can over-reject an exotic but safe
 *     pattern (the admin gets a 400 explaining exactly why, immediately — not
 *     a silent failure) and it cannot catch every unsafe one, which is why
 *     measures 2 and 3 exist behind it.
 *   - Quarantine is per-process: each collector process decides independently.
 *
 * Lives in collector/ because the hot path it protects is here; api/server.js
 * imports it for the write-time screen, the same direction as its existing
 * `require('../collector/emailer')`.
 */

// ── Tunables ────────────────────────────────────────────────────────────────
const MAX_PATTERN_LENGTH = 500;   // an alert-rule pattern far beyond any real use
const MAX_BOUNDED_REPEAT = 1000;  // reject a{100000} style blowups
const PROBE_LENGTHS      = [10, 14, 18, 22, 26];
const PROBE_BUDGET_MS    = 15;    // per probe step; linear patterns are ~1000x under this
const MATCH_BUDGET_MS    = 100;   // one message, one pattern, in the collector hot path

/** Syntax check. Returns the engine's message, or null when the pattern compiles. */
function syntaxError(pattern) {
  try {
    new RegExp(pattern);
    return null;
  } catch (err) {
    return err.message;
  }
}

/**
 * The collector turns an `match_host` ILIKE-style pattern into a regex by
 * expanding `%` to `.*`. Exported so the API screens the SAME source text the
 * collector will actually execute — screening the raw `%` form would check a
 * different pattern than the one that runs.
 */
function hostPatternToRegexSource(matchHost) {
  return String(matchHost == null ? '' : matchHost).replace(/%/g, '.*');
}

// ── 1. Static screen ───────────────────────────────────────────────────────
//
// Walks the pattern once, tracking group nesting, and flags a group that is
// QUANTIFIED (by *, +, {n,} or {n,m} with m>1) and whose own body contains an
// unbounded quantifier — the (a+)+ / (a*)* / (\d+){2,} family, which is the
// shape behind essentially every real-world ReDoS report. Character classes
// and escapes are skipped so `[+*]` and `\+` are not mistaken for quantifiers.
function staticScreen(pattern) {
  const src = String(pattern);
  if (src.length > MAX_PATTERN_LENGTH) {
    return `pattern is too long (${src.length} chars, max ${MAX_PATTERN_LENGTH})`;
  }

  // Stack of open groups; each entry records whether a quantifier has been
  // seen inside that group so far.
  const stack = [];
  let inClass = false;

  for (let i = 0; i < src.length; i++) {
    const c = src[i];

    if (c === '\\') { i++; continue; }          // escaped char — never a quantifier
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; continue; }

    if (c === '(') { stack.push({ hasQuantifier: false }); continue; }

    if (c === ')') {
      const group = stack.pop() || { hasQuantifier: false };
      const q = quantifierAt(src, i + 1);
      // A quantifier on a GROUP needs the same size check as one on a single
      // atom — `(ab){5000,}` is just as expensive as `a{100000}`.
      if (q && q.tooLarge) {
        return `bounded repetition is too large (max ${MAX_BOUNDED_REPEAT})`;
      }
      if (q && q.repeats && group.hasQuantifier) {
        return 'nested quantifier (a quantified group that itself contains + * or {n,}) — '
             + 'this is the catastrophic-backtracking shape, e.g. (a+)+';
      }
      // A quantifier on this group still counts as "a quantifier inside" for
      // any enclosing group, so ((a+)+)+ is caught at the outer level too.
      if (q && q.repeats && stack.length) stack[stack.length - 1].hasQuantifier = true;
      if (q) i += q.length - 1;
      continue;
    }

    const q = quantifierAt(src, i);
    if (q) {
      if (q.tooLarge) {
        return `bounded repetition is too large (max ${MAX_BOUNDED_REPEAT})`;
      }
      if (q.repeats && stack.length) stack[stack.length - 1].hasQuantifier = true;
      i += q.length - 1;
      continue;
    }
  }

  return null;
}

/**
 * Describe the quantifier starting at `src[i]`, if any.
 * `repeats` is true when the quantifier can match its atom MORE THAN ONCE
 * (`?` cannot, so it never contributes to a nested-quantifier blowup).
 */
function quantifierAt(src, i) {
  const c = src[i];
  if (c === '*' || c === '+') {
    const lazy = src[i + 1] === '?' || src[i + 1] === '+';
    return { length: lazy ? 2 : 1, repeats: true, tooLarge: false };
  }
  if (c === '?') {
    const lazy = src[i + 1] === '?';
    return { length: lazy ? 2 : 1, repeats: false, tooLarge: false };
  }
  if (c === '{') {
    const m = /^\{(\d*)(,(\d*))?\}/.exec(src.slice(i));
    if (!m) return null;                        // a literal '{' — not a quantifier
    const min = m[1] === '' ? 0 : parseInt(m[1], 10);
    const max = m[2] === undefined ? min : (m[3] === '' ? Infinity : parseInt(m[3], 10));
    const lazy = src[i + m[0].length] === '?' || src[i + m[0].length] === '+';
    return {
      length: m[0].length + (lazy ? 1 : 0),
      repeats: max > 1,
      tooLarge: (Number.isFinite(min) && min > MAX_BOUNDED_REPEAT)
             || (Number.isFinite(max) && max > MAX_BOUNDED_REPEAT),
    };
  }
  return null;
}

// ── 2. Empirical probe ─────────────────────────────────────────────────────
//
// Adversarial inputs: repeated single characters (the classic trigger) and a
// couple of mixed shapes, each ending in a character that forces the engine to
// fail the match and backtrack over everything it just consumed.
function probeInputs(len) {
  const rep = (s) => s.repeat(Math.ceil(len / s.length)).slice(0, len);
  return [
    rep('a') + '!',
    rep('ab') + '!',
    rep('0') + '!',
    rep(' ') + '!',
    rep('a1-_') + '!',
    rep('/') + '!',
  ];
}

/**
 * Run the candidate at ramped input lengths under a per-step time budget.
 * Returns a reason string when it blows the budget, else null.
 */
function probe(pattern, flags = 'i') {
  let re;
  try { re = new RegExp(pattern, flags); } catch (err) { return `invalid regex: ${err.message}`; }

  for (const len of PROBE_LENGTHS) {
    for (const input of probeInputs(len)) {
      const started = process.hrtime.bigint();
      try { re.test(input); } catch (_e) { /* runtime error — not a timing problem */ }
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      if (ms > PROBE_BUDGET_MS) {
        return `pattern backtracks catastrophically: it took ${ms.toFixed(0)}ms on a `
             + `${input.length}-character test string (budget ${PROBE_BUDGET_MS}ms). `
             + 'Rewrite it without overlapping repetition.';
      }
    }
  }
  return null;
}

/**
 * The whole write-time gate. Returns a human-readable reason to REJECT, or
 * null when the pattern is acceptable. `flags` must match what the collector
 * will actually use ('i').
 */
function unsafePatternReason(pattern, flags = 'i') {
  if (pattern == null || pattern === '') return null;   // no pattern = match-all, nothing to run
  if (typeof pattern !== 'string') return 'pattern must be a string';
  const syn = syntaxError(pattern);
  if (syn) return `invalid regex: ${syn}`;
  const stat = staticScreen(pattern);
  if (stat) return stat;
  return probe(pattern, flags);
}

// ── 3. Match-time budget + quarantine ──────────────────────────────────────

const compiled = new Map();     // `${flags}\u0000${pattern}` -> RegExp | null (uncompilable)
const quarantined = new Map();  // same key -> { ms, at, label }

function cacheKey(pattern, flags) { return `${flags}\u0000${pattern}`; }

/**
 * Compile once and reuse. The previous hot path built a brand-new RegExp for
 * every rule on every message; caching is both a safety win (one place to
 * consult the quarantine) and a straight perf win.
 * Returns null when the pattern does not compile.
 */
function compile(pattern, flags = 'i') {
  const key = cacheKey(pattern, flags);
  if (compiled.has(key)) return compiled.get(key);
  let re;
  try { re = new RegExp(pattern, flags); } catch (_e) { re = null; }
  compiled.set(key, re);
  return re;
}

function isQuarantined(pattern, flags = 'i') {
  return quarantined.has(cacheKey(pattern, flags));
}

/** Pattern texts currently quarantined — for the collector's periodic report. */
function quarantineReport() {
  return [...quarantined.entries()].map(([key, v]) => ({
    pattern: key.slice(key.indexOf('\u0000') + 1),
    label: v.label,
    ms: v.ms,
    at: v.at,
  }));
}

/**
 * Test `input` against `pattern`, timing the call.
 *
 * Returns { matched, skipped, ms }:
 *   - skipped=true means the pattern is quarantined (or uncompilable) and was
 *     NOT evaluated. Callers must treat this as "no opinion", NOT as a match.
 *   - the first call that exceeds MATCH_BUDGET_MS quarantines the pattern but
 *     still returns its (correct) result — we only stop evaluating it NEXT time.
 *
 * `label` is used only for the log line (e.g. 'rule 7 match_pattern').
 */
function testWithBudget(pattern, input, label, flags = 'i') {
  const key = cacheKey(pattern, flags);
  if (quarantined.has(key)) return { matched: false, skipped: true, ms: 0 };

  const re = compile(pattern, flags);
  if (!re) return { matched: false, skipped: true, ms: 0 };

  // A fresh lastIndex is irrelevant without /g, but be explicit: the cached
  // RegExp object is shared across calls and must not carry state.
  re.lastIndex = 0;

  const started = process.hrtime.bigint();
  let matched = false;
  try {
    matched = re.test(String(input == null ? '' : input));
  } catch (_e) {
    matched = false;
  }
  const ms = Number(process.hrtime.bigint() - started) / 1e6;

  if (ms > MATCH_BUDGET_MS) {
    quarantined.set(key, { ms, at: new Date().toISOString(), label });
    console.error(
      `[Regex] QUARANTINED ${label}: one message took ${ms.toFixed(0)}ms `
      + `(budget ${MATCH_BUDGET_MS}ms) — pattern /${pattern}/${flags}. `
      + 'This rule will NOT be evaluated again in this process; its alerts are '
      + 'suppressed until the pattern is rewritten. Edit the rule to clear it.',
    );
  }

  return { matched, skipped: false, ms };
}

/** Test hook only — lets a test start from a clean slate. */
function _resetState() {
  compiled.clear();
  quarantined.clear();
}

module.exports = {
  MAX_PATTERN_LENGTH,
  MAX_BOUNDED_REPEAT,
  MATCH_BUDGET_MS,
  PROBE_BUDGET_MS,
  syntaxError,
  hostPatternToRegexSource,
  staticScreen,
  probe,
  unsafePatternReason,
  compile,
  isQuarantined,
  quarantineReport,
  testWithBudget,
  _resetState,
};
