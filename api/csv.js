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
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

module.exports = { escapeCsvCell };
