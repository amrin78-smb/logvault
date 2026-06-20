'use client';

/**
 * Tiny inline-styled trend indicator: ▲/▼/– arrow + percent change vs `prev`.
 *
 * Default coloring is tuned for SECURITY metrics where "up is bad":
 *   up   → red   (var(--tint-danger-fg))
 *   down → green (var(--tint-success-fg))
 *   flat → muted
 * Pass `invert` for metrics where up is good (flips red/green).
 *
 * Edge cases:
 *   prev === 0 && value > 0  → "new" (muted-positive — no finite percent)
 *   prev === 0 && value === 0 → "—"  (nothing to compare)
 */
export function Trend({ value, prev, invert }: { value: number; prev: number; invert?: boolean }) {
  const v = Number(value) || 0;
  const p = Number(prev) || 0;

  const baseStyle: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', gap: 2,
    fontSize: 'var(--text-xs)', fontWeight: 700, whiteSpace: 'nowrap',
  };

  // No prior value to compare against.
  if (p === 0) {
    if (v === 0) {
      return <span style={{ ...baseStyle, color: 'var(--text-muted)' }}>—</span>;
    }
    return <span style={{ ...baseStyle, color: 'var(--text-muted)' }}>new</span>;
  }

  const pct = ((v - p) / p) * 100;
  const rounded = Math.round(Math.abs(pct));

  // Flat (rounds to 0%).
  if (rounded === 0) {
    return <span style={{ ...baseStyle, color: 'var(--text-muted)' }}>– 0%</span>;
  }

  const up = pct > 0;
  // Default: up = bad (red), down = good (green). invert flips it.
  const isBad = invert ? !up : up;
  const color = isBad ? 'var(--tint-danger-fg)' : 'var(--tint-success-fg)';
  const arrow = up ? '▲' : '▼';

  return (
    <span style={{ ...baseStyle, color }}>
      <span style={{ fontSize: 9, lineHeight: 1 }}>{arrow}</span>
      {rounded}%
    </span>
  );
}
