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
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
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
                return (
                  <text key={`lbl-${i}`} x={lx} y={ly} fill="var(--text-secondary)"
                    textAnchor={lx > CX ? 'start' : 'end'}
                    dominantBaseline="central" fontSize={7.5} fontWeight={600}
                    style={{ pointerEvents: 'none', userSelect: 'none' }}>
                    {`${entry.name} ${(pct*100).toFixed(0)}%`}
                  </text>
                );
              })}
            </svg>
            {tooltip && (
              <div style={{ position: 'absolute', left: tooltip.x + 8, top: tooltip.y - 14,
                background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6,
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
                style={{ display: 'flex', alignItems: 'center', gap: 3, background: '#f8f9fb',
                  border: '1px solid var(--border)', borderRadius: 20, padding: '2px 6px',
                  cursor: onSeverityClick ? 'pointer' : 'default' }}
                onMouseEnter={e => { if (onSeverityClick) (e.currentTarget as HTMLElement).style.background = '#eff6ff'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#f8f9fb'; }}>
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
