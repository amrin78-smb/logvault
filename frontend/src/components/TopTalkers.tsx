'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', unknown: '#9ca3af',
};

export default function TopTalkers({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-talkers?hours=${hours}&limit=8`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const max = data[0] ? parseInt(data[0].log_count) : 1;
  return (
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Top Talkers</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Most active sources by log volume</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {data.map((row, i) => {
          const pct   = Math.round((parseInt(row.log_count) / max) * 100);
          const color = VENDOR_COLORS[row.vendor] || '#9ca3af';
          return (
            <div key={i}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: '#1a202c', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500 }}>
                    {row.host}
                  </span>
                  <span style={{ fontSize: 10, color: '#9ca3af', textTransform: 'capitalize',
                    background: '#f0f2f5', padding: '1px 6px', borderRadius: 10 }}>{row.vendor}</span>
                </div>
                <span style={{ fontSize: 12, color: '#4a5568', fontWeight: 600 }}>
                  {parseInt(row.log_count).toLocaleString()}
                </span>
              </div>
              <div style={{ height: 5, background: '#f0f2f5', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3, transition: 'width 0.5s' }} />
              </div>
            </div>
          );
        })}
        {data.length === 0 && <div style={{ padding: '32px 0', textAlign: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>}
      </div>
    </div>
  );
}
