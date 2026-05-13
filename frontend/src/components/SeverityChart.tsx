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
const CX = 150; const CY = 105;
const INNER = 48; const OUTER = 72;

export default function SeverityChart({ summary, onSeverityClick }: {
  summary: any[];
  onSeverityClick?: (severity: string) => void;
}) {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const [tooltip, setTooltip]         = useState<{ x: number; y: number; label: string; value: number } | null>(null);

  const data = summary
    .filter(r => parseInt(r.log_count) > 0)
    .map(r => ({
      name:  r.severity_label,
      value: parseInt(r.log_count),
      color: SEV_COLORS[r.severity_label] || '#9ca3af',
    }));

  const total = data.reduce((s, d) => s + d.value, 0) || 1;

  const handleClick = (entry: any) => {
    if (onSeverityClick) onSeverityClick(SEV_FILTER[entry.name] || '');
  };

  // Build slice paths
  let angle = 90;
  const slices = data.map((entry, i) => {
    const pct        = entry.value / total;
    const sweep      = pct * 360;
    const startAngle = angle;
    const midAngle   = angle + sweep / 2;
    angle           += sweep;

    const sa = startAngle * RADIAN;
    const ea = (startAngle + sweep) * RADIAN;
    const isActive = activeIndex === i;
    const r  = isActive ? OUTER + 5 : OUTER;

    const x1 = CX + INNER * Math.cos(sa); const y1 = CY - INNER * Math.sin(sa);
    const x2 = CX + r     * Math.cos(sa); const y2 = CY - r     * Math.sin(sa);
    const x3 = CX + r     * Math.cos(ea); const y3 = CY - r     * Math.sin(ea);
    const x4 = CX + INNER * Math.cos(ea); const y4 = CY - INNER * Math.sin(ea);
    const large = sweep > 180 ? 1 : 0;
    const d = `M ${x1} ${y1} L ${x2} ${y2} A ${r} ${r} 0 ${large} 0 ${x3} ${y3} L ${x4} ${y4} A ${INNER} ${INNER} 0 ${large} 1 ${x1} ${y1} Z`;

    // Label position
    const ma  = midAngle * RADIAN;
    const lr  = OUTER + 18;
    const lx  = CX + lr * Math.cos(-ma + Math.PI / 2);
    const ly  = CY - lr * Math.sin(-ma + Math.PI / 2);

    return { entry, i, d, pct, midAngle, lx, ly, isActive };
  });

  return (
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Severity Distribution</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 8 }}>Click a segment to filter logs</div>

      {data.length === 0 ? (
        <div style={{ height: 210, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>
      ) : (
        <div style={{ position: 'relative' }}>
          <svg width="100%" viewBox="0 0 300 210" style={{ overflow: 'visible', display: 'block' }}>
            {/* Slices */}
            {slices.map(({ entry, i, d, pct, isActive }) => (
              <path key={i} d={d}
                fill={entry.color}
                fillOpacity={activeIndex === null || isActive ? 1 : 0.35}
                stroke="#fff" strokeWidth={isActive ? 3 : 1.5}
                style={{ cursor: onSeverityClick ? 'pointer' : 'default', transition: 'fill-opacity 0.15s' }}
                onClick={() => handleClick(entry)}
                onMouseEnter={(e) => {
                  setActiveIndex(i);
                  const rect = (e.currentTarget.closest('svg') as SVGSVGElement).getBoundingClientRect();
                  const svgX = e.clientX - rect.left;
                  const svgY = e.clientY - rect.top;
                  setTooltip({ x: svgX, y: svgY, label: entry.name, value: entry.value });
                }}
                onMouseMove={(e) => {
                  const rect = (e.currentTarget.closest('svg') as SVGSVGElement).getBoundingClientRect();
                  setTooltip(t => t ? { ...t, x: e.clientX - rect.left, y: e.clientY - rect.top } : null);
                }}
                onMouseLeave={() => { setActiveIndex(null); setTooltip(null); }}
              />
            ))}

            {/* Labels — always on top, never re-render on hover */}
            {slices.map(({ entry, i, pct, lx, ly }) => {
              if (pct < 0.06) return null;
              return (
                <text key={`lbl-${i}`} x={lx} y={ly}
                  fill="#374151" textAnchor={lx > CX ? 'start' : 'end'}
                  dominantBaseline="central" fontSize={9.5} fontWeight={600}
                  style={{ pointerEvents: 'none', userSelect: 'none' }}>
                  {`${entry.name} ${(pct * 100).toFixed(0)}%`}
                </text>
              );
            })}
          </svg>

          {/* Tooltip */}
          {tooltip && (
            <div style={{ position: 'absolute', left: tooltip.x + 10, top: tooltip.y - 16,
              background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6,
              padding: '6px 10px', fontSize: 12, color: '#1a202c', pointerEvents: 'none',
              boxShadow: '0 2px 8px rgba(0,0,0,0.12)', whiteSpace: 'nowrap', zIndex: 10 }}>
              <span style={{ textTransform: 'capitalize', fontWeight: 600 }}>{tooltip.label}</span>
              <span style={{ color: '#718096', marginLeft: 6 }}>{tooltip.value.toLocaleString()} logs</span>
            </div>
          )}
        </div>
      )}

      {/* Legend chips */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 4 }}>
        {data.map(d => (
          <div key={d.name} onClick={() => handleClick(d)}
            style={{ display: 'flex', alignItems: 'center', gap: 5, background: '#f8f9fb',
              border: '1px solid #e2e6ea', borderRadius: 20, padding: '3px 9px',
              cursor: onSeverityClick ? 'pointer' : 'default', transition: 'background 0.15s' }}
            onMouseEnter={e => { if (onSeverityClick) (e.currentTarget as HTMLElement).style.background = '#eff6ff'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#f8f9fb'; }}>
            <div style={{ width: 7, height: 7, borderRadius: 2, background: d.color }} />
            <span style={{ fontSize: 11, color: '#4a5568', textTransform: 'capitalize' }}>{d.name}</span>
            <span style={{ fontSize: 11, color: '#1a202c', fontWeight: 700 }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
