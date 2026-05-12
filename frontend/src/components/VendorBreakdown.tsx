'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#58a6ff', paloalto: '#db6d28', fortinet: '#f85149',
  aruba: '#a371f7', sangfor: '#39d353', generic: '#6e7681', unknown: '#6e7681',
};

export default function VendorBreakdown({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/stats/by-vendor?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  const total = data.reduce((s, r) => s + parseInt(r.log_count), 0) || 1;

  return (
    <div style={{ background: '#161c26', border: '1px solid #30363d', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>Logs by Vendor</div>
      <div style={{ fontSize: 11, color: '#6e7681', marginBottom: 16 }}>Distribution across device types</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {data.map(row => {
          const count  = parseInt(row.log_count);
          const pct    = Math.round((count / total) * 100);
          const color  = VENDOR_COLORS[row.vendor] || '#6e7681';
          const crit   = parseInt(row.critical_count);
          const err    = parseInt(row.error_count);
          return (
            <div key={row.vendor}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: color }} />
                  <span style={{ fontSize: 12, color: '#e6edf3', fontWeight: 500, textTransform: 'capitalize' }}>
                    {row.vendor}
                  </span>
                  <span style={{ fontSize: 10, color: '#6e7681' }}>{pct}%</span>
                </div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  {crit > 0 && (
                    <span style={{ fontSize: 10, color: '#f85149', background: '#2d1b1b',
                      padding: '1px 6px', borderRadius: 10, fontWeight: 500 }}>
                      {crit} crit
                    </span>
                  )}
                  {err > 0 && (
                    <span style={{ fontSize: 10, color: '#db6d28', background: '#2d1f0e',
                      padding: '1px 6px', borderRadius: 10, fontWeight: 500 }}>
                      {err} err
                    </span>
                  )}
                  <span style={{ fontSize: 12, color: '#8b949e', fontWeight: 600 }}>
                    {count.toLocaleString()}
                  </span>
                </div>
              </div>
              <div style={{ height: 5, background: '#21262d', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color,
                  borderRadius: 3, transition: 'width 0.5s ease' }} />
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
