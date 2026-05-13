'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', unknown: '#9ca3af',
};

export default function VendorBreakdown({ hours, onVendorClick }: {
  hours: number;
  onVendorClick?: (vendor: string) => void;
}) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/by-vendor?hours=${hours}`).then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  const total = data.reduce((s, r) => s + parseInt(r.log_count), 0) || 1;

  return (
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Logs by Vendor</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
        {onVendorClick ? 'Click a vendor to filter logs' : 'Distribution across device types'}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {data.map(row => {
          const count = parseInt(row.log_count);
          const pct   = Math.round((count / total) * 100);
          const color = VENDOR_COLORS[row.vendor] || '#9ca3af';
          const crit  = parseInt(row.critical_count);
          const err   = parseInt(row.error_count);
          return (
            <div key={row.vendor} onClick={() => onVendorClick && onVendorClick(row.vendor)}
              style={{ cursor: onVendorClick ? 'pointer' : 'default', padding: '4px 6px', borderRadius: 6, transition: 'background 0.15s' }}
              onMouseEnter={e => { if (onVendorClick) (e.currentTarget as HTMLElement).style.background = '#f0f7ff'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: color }} />
                  <span style={{ fontSize: 12, color: '#1a202c', fontWeight: 600, textTransform: 'capitalize' }}>{row.vendor}</span>
                  <span style={{ fontSize: 10, color: '#9ca3af' }}>{pct}%</span>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  {crit > 0 && <span style={{ fontSize: 10, color: '#dc2626', background: '#fef2f2', border: '1px solid #fecaca', padding: '1px 6px', borderRadius: 10, fontWeight: 600 }}>{crit} crit</span>}
                  {err  > 0 && <span style={{ fontSize: 10, color: '#ea580c', background: '#fff7ed', border: '1px solid #fed7aa', padding: '1px 6px', borderRadius: 10, fontWeight: 600 }}>{err} err</span>}
                  <span style={{ fontSize: 12, color: '#4a5568', fontWeight: 700 }}>{count.toLocaleString()}</span>
                </div>
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
