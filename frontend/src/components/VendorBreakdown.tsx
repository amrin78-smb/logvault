'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#1d6fa5', paloalto: '#f97316', fortinet: '#ef4444',
  aruba: '#8b5cf6', sangfor: '#06b6d4', generic: '#475569', unknown: '#374151',
};

export default function VendorBreakdown({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/stats/by-vendor?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Logs by Vendor</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {data.map(row => {
          const total  = parseInt(row.log_count);
          const maxVal = data[0] ? parseInt(data[0].log_count) : 1;
          const pct    = Math.round((total / maxVal) * 100);
          const color  = VENDOR_COLORS[row.vendor] || '#475569';
          return (
            <div key={row.vendor}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'capitalize' }}>{row.vendor}</span>
                <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
                  {parseInt(row.critical_count) > 0 && <span style={{ color: '#ef4444' }}>⬤ {row.critical_count} crit</span>}
                  {parseInt(row.error_count) > 0   && <span style={{ color: '#f97316' }}>⬤ {row.error_count} err</span>}
                  <span style={{ color: '#64748b' }}>{total.toLocaleString()}</span>
                </div>
              </div>
              <div style={{ height: 6, background: '#1e2d40', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3, transition: 'width 0.4s ease' }} />
              </div>
            </div>
          );
        })}
        {data.length === 0 && <div style={{ fontSize: 12, color: '#475569', textAlign: 'center', padding: '40px 0' }}>No data for this period</div>}
      </div>
    </div>
  );
}
