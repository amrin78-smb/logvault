'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', unknown: '#9ca3af',
};

export default function TopTalkers({ hours, onHostClick, compact }: {
  hours: number; onHostClick?: (host: string) => void; compact?: boolean;
}) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-talkers?hours=${hours}&limit=5`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const max = data[0] ? parseInt(data[0].log_count) : 1;
  return (
    <div style={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 10,
      padding: '12px 14px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: '#1a202c', marginBottom: 1, flexShrink: 0 }}>Top Talkers</div>
      <div style={{ fontSize: 10, color: '#9ca3af', marginBottom: 8, flexShrink: 0 }}>Most active — {hours}h</div>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 7, justifyContent: 'space-evenly' }}>
        {data.slice(0, 5).map((row, i) => {
          const pct = Math.round((parseInt(row.log_count) / max) * 100);
          const color = VENDOR_COLORS[row.vendor] || '#9ca3af';
          return (
            <div key={i} onClick={() => onHostClick && onHostClick(row.host)}
              style={{ cursor: onHostClick ? 'pointer' : 'default' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
                  <span style={{ fontSize: 11, color: '#1a202c', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500, maxWidth: 90, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.host}</span>
                </div>
                <span style={{ fontSize: 11, color: '#4a5568', fontWeight: 600 }}>{parseInt(row.log_count).toLocaleString()}</span>
              </div>
              <div style={{ height: 4, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }} />
              </div>
            </div>
          );
        })}
        {data.length === 0 && <div style={{ textAlign: 'center', color: '#9ca3af', fontSize: 12 }}>No data</div>}
      </div>
    </div>
  );
}
