'use client';

/**
 * Reusable hour-of-week heatmap. Pure divs + inline styles, no deps.
 *
 * Renders a 7-row (Sun–Sat) × 24-col grid. Each cell's background is
 * interpolated on a single-hue ramp from `var(--surface-subtle)` (zero/low) to
 * `var(--primary)` (max) by its `count`, with a per-cell `title` tooltip
 * (e.g. "Mon 14:00 — 42 events"). Reusable: a failed-logins heatmap passes the
 * same `{ dow, hour, count }[]` shape.
 *
 * `dow`: 0 = Sunday … 6 = Saturday. `hour`: 0–23. Out-of-range cells are
 * ignored. Duplicate (dow,hour) entries are summed.
 */
export interface HeatmapCell {
  dow:   number;
  hour:  number;
  count: number;
}

const DAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
// Hour labels shown along the top — every 3 hours keeps it readable.
const HOUR_LABELS = [0, 3, 6, 9, 12, 15, 18, 21];

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function Heatmap({ data, title, cellHeight = 18 }: { data: HeatmapCell[]; title?: string; cellHeight?: number }) {
  // Build a 7×24 grid of counts.
  const grid: number[][] = Array.from({ length: 7 }, () => new Array(24).fill(0));
  let max = 0;
  for (const c of (data || [])) {
    const d = Number(c?.dow);
    const h = Number(c?.hour);
    const n = Number(c?.count) || 0;
    if (!Number.isInteger(d) || d < 0 || d > 6) continue;
    if (!Number.isInteger(h) || h < 0 || h > 23) continue;
    grid[d][h] += n;
    if (grid[d][h] > max) max = grid[d][h];
  }

  // Interpolate surface-subtle → primary by intensity. We can't read CSS-var
  // values in JS for a true mix, so we lay --primary over the subtle surface at
  // an opacity proportional to count (sqrt eases low counts into visibility).
  const cellBg = (count: number): string => {
    if (count <= 0 || max <= 0) return 'var(--surface-subtle)';
    const t = Math.sqrt(count / max); // 0..1, eased
    const opacity = Math.max(0.08, Math.min(1, t));
    return `linear-gradient(var(--primary-overlay, rgba(200,16,46,${opacity})), var(--primary-overlay, rgba(200,16,46,${opacity}))), var(--surface-subtle)`;
  };

  const ROW_LABEL_W = 30;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {title && (
        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
          {title}
        </div>
      )}

      {/* Hour labels row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <div style={{ width: ROW_LABEL_W, flexShrink: 0 }} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(24, 1fr)', gap: 2, flex: 1 }}>
          {Array.from({ length: 24 }, (_, h) => (
            <div key={h} style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
              textAlign: 'center', lineHeight: 1 }}>
              {HOUR_LABELS.includes(h) ? h : ''}
            </div>
          ))}
        </div>
      </div>

      {/* Day rows */}
      {grid.map((row, d) => (
        <div key={d} style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <div style={{ width: ROW_LABEL_W, flexShrink: 0, fontSize: 'var(--text-xs)',
            color: 'var(--text-muted)', fontWeight: 600 }}>
            {DAY_LABELS[d]}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(24, 1fr)', gap: 2, flex: 1 }}>
            {row.map((count, h) => (
              <div key={h}
                title={`${DAY_LABELS[d]} ${pad2(h)}:00 — ${count} event${count === 1 ? '' : 's'}`}
                style={{ height: cellHeight, minWidth: 0, borderRadius: 2,
                  background: cellBg(count), border: '1px solid var(--border-light)' }} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
