'use client';
import { useState } from 'react';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#dc2626',
  error: '#ea580c', warning: '#ca8a04', notice: '#2563eb',
  info: '#16a34a', debug: '#9ca3af',
};
const SEV_FILTER: Record<string, string> = {
  emergency: '0', alert: '1', critical: '2', error: '3',
  warning: '4', notice: '5', info: '6', debug: '7',
};
const RADIAN = Math.PI / 180;
const CX = 90; const CY = 70; const INNER = 30; const OUTER = 50;

// Label fitting. The slice labels sit on a radius OUTER+16 = 66 from CX = 90, so
// a label for a slice centred on the left runs outward from x ~= 24 with
// textAnchor="end" — i.e. leftward, past x = 0 and out of the viewBox, where the
// svg's overflow:hidden clips it. A single dominant slice puts its label exactly
// there, which is the common case rather than an edge case: 97% warning rendered
// as a clipped "g 97%".
//
// So measure before drawing. estLabelWidth over-estimates on purpose — being too
// generous shortens a label that would have fitted, being too mean clips it, and
// only one of those is recoverable by eye.
const VB_W = 180;          // viewBox width — labels must land inside 0..VB_W
const LABEL_FS = 7.5;      // must match the <text> fontSize below
const LABEL_PAD = 2;
const estLabelWidth = (s: string) => s.length * LABEL_FS * 0.6;

export default function SeverityChart({ summary, onSeverityClick, compact }: {
  summary: any[]; onSeverityClick?: (severity: string) => void; compact?: boolean;
}) {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; label: string; value: number } | null>(null);

  const data = summary.filter(r => parseInt(r.log_count) > 0)
    .map(r => ({ name: r.severity_label, value: parseInt(r.log_count), color: SEV_COLORS[r.severity_label] || '#9ca3af' }));
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const handleClick = (entry: any) => { if (onSeverityClick) onSeverityClick(SEV_FILTER[entry.name] || ''); };

  let angle = 90;
  const slices = data.map((entry, i) => {
    const pct = entry.value / total; const sweep = pct * 360;
    const startAngle = angle; const midAngle = angle + sweep / 2; angle += sweep;
    const sa = startAngle * RADIAN; const ea = (startAngle + sweep) * RADIAN;
    const isActive = activeIndex === i; const r = isActive ? OUTER + 4 : OUTER;
    const x1 = CX + INNER*Math.cos(sa); const y1 = CY - INNER*Math.sin(sa);
    const x2 = CX + r*Math.cos(sa);     const y2 = CY - r*Math.sin(sa);
    const x3 = CX + r*Math.cos(ea);     const y3 = CY - r*Math.sin(ea);
    const x4 = CX + INNER*Math.cos(ea); const y4 = CY - INNER*Math.sin(ea);
    const large = sweep > 180 ? 1 : 0;
    const d = `M ${x1} ${y1} L ${x2} ${y2} A ${r} ${r} 0 ${large} 0 ${x3} ${y3} L ${x4} ${y4} A ${INNER} ${INNER} 0 ${large} 1 ${x1} ${y1} Z`;
    const ma = midAngle * RADIAN;
    const lr = OUTER + 16; const lx = CX + lr*Math.cos(-ma + Math.PI/2); const ly = CY - lr*Math.sin(-ma + Math.PI/2);
    return { entry, i, d, pct, lx, ly, isActive };
  });

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
      padding: '16px 20px', height: '100%', boxSizing: 'border-box',
      display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 1, flexShrink: 0 }}>Severity Distribution</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4, flexShrink: 0 }}>Click a segment to filter</div>
      {data.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>No data</div>
      ) : (
        <>
          <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
            <svg width="100%" height="100%" viewBox="0 0 180 140"
              style={{ display: 'block', overflow: 'hidden' }}>
              {slices.map(({ entry, i, d, isActive }) => (
                <path key={i} d={d} fill={entry.color}
                  fillOpacity={activeIndex === null || isActive ? 1 : 0.35}
                  stroke="#fff" strokeWidth={isActive ? 3 : 1.5}
                  style={{ cursor: onSeverityClick ? 'pointer' : 'default', transition: 'fill-opacity 0.15s' }}
                  onClick={() => handleClick(entry)}
                  onMouseEnter={(e) => {
                    setActiveIndex(i);
                    const rect = (e.currentTarget.closest('svg') as SVGSVGElement).getBoundingClientRect();
                    setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, label: entry.name, value: entry.value });
                  }}
                  onMouseMove={(e) => {
                    const rect = (e.currentTarget.closest('svg') as SVGSVGElement).getBoundingClientRect();
                    setTooltip(t => t ? { ...t, x: e.clientX - rect.left, y: e.clientY - rect.top } : null);
                  }}
                  onMouseLeave={() => { setActiveIndex(null); setTooltip(null); }}
                />
              ))}
              {slices.map(({ entry, i, pct, lx, ly }) => {
                if (pct < 0.08) return null;
                const onLeft = lx <= CX;
                const percent = `${(pct*100).toFixed(0)}%`;
                // Room between the label's anchor and the edge it grows toward.
                const room = (onLeft ? lx : VB_W - lx) - LABEL_PAD;
                // Drop the severity name rather than let it run off the edge —
                // the legend below already names every slice, and the label sits
                // against its own slice, so the percentage alone still reads.
                const text = estLabelWidth(`${entry.name} ${percent}`) <= room
                  ? `${entry.name} ${percent}`
                  : percent;
                // Last guard: a near-vertical slice can leave less room than even
                // the percentage needs, so pin it inside the box.
                const w = estLabelWidth(text);
                const x = onLeft
                  ? Math.max(lx, w + LABEL_PAD)
                  : Math.min(lx, VB_W - w - LABEL_PAD);
                return (
                  <text key={`lbl-${i}`} x={x} y={ly} fill="var(--text-secondary)"
                    textAnchor={onLeft ? 'end' : 'start'}
                    dominantBaseline="central" fontSize={LABEL_FS} fontWeight={600}
                    style={{ pointerEvents: 'none', userSelect: 'none' }}>
                    {text}
                  </text>
                );
              })}
            </svg>
            {tooltip && (
              <div style={{ position: 'absolute', left: tooltip.x + 8, top: tooltip.y - 14,
                background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                padding: '4px 8px', fontSize: 'var(--text-xs)', color: 'var(--text-primary)', pointerEvents: 'none',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)', whiteSpace: 'nowrap', zIndex: 10 }}>
                <span style={{ textTransform: 'capitalize', fontWeight: 600 }}>{tooltip.label}</span>
                <span style={{ color: 'var(--text-muted)', marginLeft: 5 }}>{tooltip.value.toLocaleString()}</span>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 6, flexShrink: 0 }}>
            {data.map(d => (
              <div key={d.name} onClick={() => handleClick(d)}
                style={{ display: 'flex', alignItems: 'center', gap: 3, background: 'var(--surface-subtle)',
                  border: '1px solid var(--border)', borderRadius: 'var(--radius-pill)', padding: '2px 6px',
                  cursor: onSeverityClick ? 'pointer' : 'default' }}
                onMouseEnter={e => { if (onSeverityClick) (e.currentTarget as HTMLElement).style.background = 'var(--tint-info)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}>
                {/* intentional: 2px on a 5x5 legend swatch — a 6px token radius would render it as a circle */}
                <div style={{ width: 5, height: 5, borderRadius: 2, background: d.color }} />
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{d.name}</span>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontWeight: 700 }}>{d.value}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
