'use client';

/**
 * Canonical syslog-severity palette + helpers for the LogVault suite.
 *
 * Reconciles the previously-duplicated `SEV_COLORS` maps across
 * LogDetailPanel / AlertDetailPanel / SecurityAnalysis (the `{ color, bg }`
 * tint-token form, with a `debug` entry) into one source of truth. A `border`
 * token is added per entry so the same map can drive the bordered `SevBadge`
 * pill (matching the badge styling already used in SecurityAnalysis).
 *
 * Chart series palettes (raw hex in SeverityChart/TimelineChart) are NOT this
 * map — those colors ARE the data signal and stay where they are.
 */
export interface SevStyle {
  color:  string;
  bg:     string;
  border: string;
}

export const SEV_COLORS: Record<string, SevStyle> = {
  emergency: { color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)',     border: 'var(--tint-danger)' },
  alert:     { color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)',     border: 'var(--tint-danger)' },
  critical:  { color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)',     border: 'var(--tint-danger)' },
  error:     { color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)',       border: 'var(--tint-warn)' },
  warning:   { color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)',       border: 'var(--tint-warn)' },
  notice:    { color: 'var(--tint-info-fg)',    bg: 'var(--tint-info)',       border: 'var(--tint-info)' },
  info:      { color: 'var(--tint-success-fg)', bg: 'var(--tint-success)',    border: 'var(--tint-success)' },
  debug:     { color: 'var(--text-muted)',      bg: 'var(--surface-subtle)',  border: 'var(--border)' },
};

// Fallback for an unknown/missing severity label.
export const SEV_FALLBACK: SevStyle = {
  color: 'var(--text-muted)', bg: 'var(--surface-subtle)', border: 'var(--border)',
};

// Numeric syslog severity (0-7) → label, matching the standard syslog mapping.
const NUM_TO_LABEL: Record<number, string> = {
  0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
  4: 'warning',   5: 'notice', 6: 'info',    7: 'debug',
};

/**
 * Normalise a severity (numeric 0-7 or a label string) to a canonical
 * lower-case syslog label. Unknown values pass through lower-cased so callers
 * can still look them up (and fall back to SEV_FALLBACK).
 */
export function sevLabel(severity: number | string): string {
  if (typeof severity === 'number') {
    return NUM_TO_LABEL[severity] || 'info';
  }
  const s = String(severity ?? '').trim().toLowerCase();
  if (s === '') return 'info';
  if (NUM_TO_LABEL[Number(s)]) return NUM_TO_LABEL[Number(s)];
  return s;
}

/** Look up the style for a severity label, with a safe fallback. */
export function sevStyle(label: string): SevStyle {
  return SEV_COLORS[sevLabel(label)] || SEV_FALLBACK;
}

/** Inline-styled severity pill, matching the suite badge idiom. */
export function SevBadge({ label }: { label: string }) {
  const st = sevStyle(label);
  return (
    <span style={{ padding: '2px 7px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 700,
      background: st.bg, color: st.color, border: `1px solid ${st.border}`,
      textTransform: 'uppercase', letterSpacing: '0.4px', whiteSpace: 'nowrap' }}>
      {label}
    </span>
  );
}
