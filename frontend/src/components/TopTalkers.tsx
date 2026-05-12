'use client';
import { useEffect, useState } from 'react';

export default function TopTalkers({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/stats/top-talkers?hours=${hours}&limit=8`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  const max = data[0] ? parseInt(data[0].log_count) : 1;

  const VENDOR_COLORS: Record<string, string> = {
    cisco: '#58a6ff', paloalto: '#db6d28', fortinet: '#f85149',
    aruba: '#a371f7', sangfor: '#39d353', generic: '#6e7681', unknown: '#6e7681',
  };

  return (
    <div style={{ background: '#161c26', border: '1px solid #30363d', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>Top Talkers</div>
      <div style={{ fontSize: 11, color: '#6e7681', marginBottom: 16 }}>Most active sources by log volume</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {data.map((row, i) => {
          const pct   = Math.round((parseInt(row.log_count) / max) * 100);
          const color = VENDOR_COLORS[row.vendor] || '#6e7681';
          return (
            <div key={i}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>
                    {row.host}
                  </span>
                  <span style={{ fontSize: 10, color: '#6e7681', textTransform: 'capitalize' }}>{row.vendor}</span>
                </div>
                <span style={{ fontSize: 12, color: '#8b949e', fontWeight: 500 }}>
                  {parseInt(row.log_count).toLocaleString()}
                </span>
              </div>
              <div style={{ height: 4, background: '#21262d', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color,
                  borderRadius: 2, transition: 'width 0.5s ease' }} />
              </div>
            </div>
          );
        })}
        {data.length === 0 && (
          <div style={{ padding: '40px 0', textAlign: 'center', color: '#6e7681', fontSize: 13 }}>
            No data for this period
          </div>
        )}
      </div>
    </div>
  );
}
