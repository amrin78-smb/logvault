'use strict';

/**
 * Tests for the CSV formula-injection finding on GET /api/logs/export.
 *
 * The route hand-rolled its own esc() with RFC-4180 quoting only, while
 * api/csv.js — which exists for exactly this and adds the formula guard — was
 * never imported by server.js. `message` is attacker-supplied by design:
 * anything that can reach the unauthenticated syslog listener on UDP/TCP 514
 * can plant `=cmd|' /C calc'!A1` and have it execute when an operator opens the
 * export in Excel.
 *
 * `legacyEsc`/`legacyRow` below reproduce the PRE-FIX route verbatim. They are
 * here so "ordinary rows are byte-identical" is an assertion rather than a
 * claim, and so the formula case can be shown to differ.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { escapeCsvCell, buildLogsExportCsv, LOGS_EXPORT_HEADER } = require('../api/csv');

// ── the pre-fix implementation, copied from api/server.js ───────────────────
const legacyEsc = (v) => {
  if (v == null) return '';
  const s = String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const legacyClean = (v) => (v == null || v === 'N/A' || v === '') ? '' : v;
const legacyRow = (r) => [
  legacyEsc(r.received_at), legacyEsc(r.source_host), legacyEsc(r.source_ip),
  legacyEsc(legacyClean(r.remote_ip)), legacyEsc(legacyClean(r.country)), legacyEsc(legacyClean(r.usr)),
  legacyEsc(r.category), legacyEsc(legacyClean(r.subcategory)), legacyEsc(legacyClean(r.action)),
  legacyEsc(legacyClean(r.subtype)), legacyEsc(legacyClean(r.dstip)),
  legacyEsc(r.severity_label), r.risk_score != null ? r.risk_score : '',
  legacyEsc(r.vendor), legacyEsc(r.program), legacyEsc(legacyClean(r.reason)), legacyEsc(r.message),
].join(',');

const ordinaryRows = [
  {
    received_at: '2026-11-07T04:05:06.000Z', source_host: 'FGT200E_TUS', source_ip: '192.168.6.1',
    remote_ip: '203.0.113.9', country: 'Thailand', usr: 'amrin', category: 'vpn',
    subcategory: 'login_failed', action: 'blocked', subtype: 'vpn', dstip: '10.1.2.3',
    severity_label: 'Error', risk_score: 72, vendor: 'fortinet', program: 'sslvpnd',
    reason: 'sslvpn_login_permission_denied', message: 'SSL VPN login fail from 203.0.113.9',
  },
  // N/A placeholders, nulls, and the RFC-4180 cases (comma / quote / newline).
  {
    received_at: '2026-11-07T04:05:07.000Z', source_host: 'SW-CORE-01', source_ip: '192.168.6.2',
    remote_ip: 'N/A', country: '', usr: null, category: 'interface',
    subcategory: undefined, action: 'N/A', subtype: '', dstip: null,
    severity_label: 'Warning', risk_score: null, vendor: 'cisco', program: null,
    reason: 'link down, port 3', message: 'Interface "Gi1/0/3" changed state\nto down',
  },
];

test('ordinary rows come out byte-identical to the pre-fix route', () => {
  const produced = buildLogsExportCsv(ordinaryRows);
  const legacy = 'Time,Reporting Device,Reporting Device IP,Remote Source IP,Country,User,Category,'
    + 'Subcategory,Action,Subtype,Dest IP,Severity,Risk Score,Vendor,Program,Reason,Message\n'
    + ordinaryRows.map(legacyRow).join('\n');
  assert.equal(produced, legacy);
});

test('the header is unchanged', () => {
  assert.equal(LOGS_EXPORT_HEADER,
    'Time,Reporting Device,Reporting Device IP,Remote Source IP,Country,User,Category,'
    + 'Subcategory,Action,Subtype,Dest IP,Severity,Risk Score,Vendor,Program,Reason,Message');
  assert.equal(buildLogsExportCsv([]), LOGS_EXPORT_HEADER + '\n');
});

test('a formula-shaped syslog message is neutralised in the export', () => {
  const payload = "=cmd|' /C calc'!A1";
  const csv = buildLogsExportCsv([{ ...ordinaryRows[0], message: payload }]);
  const lastCell = csv.split('\n')[1].split(',').pop();

  assert.equal(lastCell, "'=cmd|' /C calc'!A1");
  assert.ok(lastCell.startsWith("'"), 'must be prefixed so Excel renders it as text');
  // And this is what the pre-fix route emitted for the same input.
  assert.equal(legacyEsc(payload), payload);
  assert.notEqual(lastCell, legacyEsc(payload));
});

test('every formula lead character is guarded, in every column', () => {
  for (const lead of ['=', '+', '-', '@', '\t', '\r']) {
    const out = escapeCsvCell(`${lead}SUM(A1)`);
    // The guard prefix comes first; RFC-4180 quoting may then wrap the whole
    // cell (it does for \r, which is in the quoting set), so allow the leading
    // double-quote before the apostrophe.
    assert.match(out, /^"?'/, `lead ${JSON.stringify(lead)} -> ${JSON.stringify(out)}`);
    assert.ok(out.includes(`'${lead}SUM(A1)`), `lead ${JSON.stringify(lead)} -> ${JSON.stringify(out)}`);
  }
  // Not just `message`: a hostname or vendor string from a device can carry it
  // too, so the guard has to be on the cell, not on one column. (Not split on
  // ',' here — a guarded cell containing a comma is also RFC-4180 quoted, so
  // the row is checked as a whole.)
  const row = { ...ordinaryRows[0], source_host: '=HYPERLINK("http://evil","x")', usr: '@SUM(1)' };
  const line = buildLogsExportCsv([row]).split('\n')[1];
  assert.ok(line.includes('"\'=HYPERLINK(""http://evil"",""x"")"'), line);
  assert.ok(line.includes("'@SUM(1)"), line);
});

test('ordinary text is NOT mangled by the guard', () => {
  // A false positive here would corrupt every export, so pin the common cases.
  assert.equal(escapeCsvCell('fortinet'), 'fortinet');
  assert.equal(escapeCsvCell('192.168.6.1'), '192.168.6.1');
  assert.equal(escapeCsvCell(72), '72');
  assert.equal(escapeCsvCell(0), '0');
  assert.equal(escapeCsvCell(null), '');
  assert.equal(escapeCsvCell('Interface Gi1/0/3 is down'), 'Interface Gi1/0/3 is down');
  // A dash INSIDE the value is untouched; only a leading one is a formula lead.
  assert.equal(escapeCsvCell('ssl-login-fail'), 'ssl-login-fail');
});

test('RFC-4180 quoting still applies, including to a guarded cell', () => {
  assert.equal(escapeCsvCell('a,b'), '"a,b"');
  assert.equal(escapeCsvCell('say "hi"'), '"say ""hi"""');
  assert.equal(escapeCsvCell('line1\nline2'), '"line1\nline2"');
  assert.equal(escapeCsvCell('line1\rline2'), '"line1\rline2"');
  assert.equal(escapeCsvCell('=a,b'), '"\'=a,b"');
});
