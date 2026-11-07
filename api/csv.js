'use strict';

/**
 * Escape a single value for a CSV cell, with a CSV/formula-injection guard.
 *
 * A cell that starts with = + - @ (or a leading tab/CR) is interpreted as a FORMULA
 * by Excel / Google Sheets, so a network-sourced string like `=cmd|...` would execute
 * when someone opens the exported file. Neutralize it by prefixing a single quote so
 * it renders as text, then apply standard RFC-4180 quoting when the value contains a
 * quote, comma, or newline.
 *
 * Ported verbatim from DDIVault's api/csv.js (portable, no app-specific coupling).
 * Every CSV export in LogVault should route through this — cells carry
 * device/host/vendor/user-supplied strings, so the guard belongs in one shared
 * place that can't drift or be forgotten.
 */
function escapeCsvCell(v) {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  // \r is in the quoting test as well as \n: syslog messages really do carry a
  // bare CR mid-string, and an unquoted CR inside a field splits the record for
  // most parsers. /api/logs/export's own hand-rolled esc() quoted on \r before
  // it was routed through this helper, and that behaviour must not be lost —
  // this only ever adds quoting, never removes it. (DDIVault's copy tests
  // /[",\n]/; this one extra character is the sole intentional divergence.)
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// ── /api/logs/export row builder ────────────────────────────────────────────
//
// Lives here, next to the escape helper, rather than inline in the route.
//
// WHY: the export route used to hand-roll its OWN `esc()` with RFC-4180
// quoting only and no formula guard, while this module — whose docstring says
// every LogVault CSV export should route through it — sat unimported by
// server.js (only api/reports.js used it). A syslog `message` of
// `=cmd|' /C calc'!A1`, which ANYONE who can reach the unauthenticated syslog
// listener on UDP/TCP 514 can plant, was emitted raw as the final column and
// executed when an operator opened the export in Excel. Keeping the column
// layout in the same file as the escaper means the next person to add a column
// cannot reintroduce a parallel escaper by accident.
//
// `clean()` blanks the firewall's "N/A" placeholders so columns stay
// analysis-friendly — unchanged from the original route.
const LOGS_EXPORT_HEADER = 'Time,Reporting Device,Reporting Device IP,Remote Source IP,'
  + 'Country,User,Category,Subcategory,Action,Subtype,Dest IP,Severity,Risk Score,'
  + 'Vendor,Program,Reason,Message';

function clean(v) {
  return (v == null || v === 'N/A' || v === '') ? '' : v;
}

/**
 * Render /api/logs/export rows as a CSV body (header + rows, LF-separated).
 * Column order and `clean()` semantics are byte-identical to the pre-fix
 * route for ordinary values; the only difference is that every cell — the
 * `message` column above all — now passes the formula guard.
 */
function buildLogsExportCsv(rows) {
  const e = escapeCsvCell;
  const body = (rows || []).map((r) => [
    e(r.received_at), e(r.source_host), e(r.source_ip),
    e(clean(r.remote_ip)), e(clean(r.country)), e(clean(r.usr)),
    e(r.category), e(clean(r.subcategory)), e(clean(r.action)), e(clean(r.subtype)),
    e(clean(r.dstip)), e(r.severity_label), e(r.risk_score != null ? r.risk_score : ''),
    e(r.vendor), e(r.program), e(clean(r.reason)), e(r.message),
  ].join(','));
  return `${LOGS_EXPORT_HEADER}\n${body.join('\n')}`;
}

module.exports = { escapeCsvCell, buildLogsExportCsv, LOGS_EXPORT_HEADER };
