'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', unknown: '#9ca3af',
  forcepoint: '#003087', checkpoint: '#E31937', juniper: '#84BD00',
  windows: '#0078D4', sonicwall: '#FF6600',
};

export default function VendorBreakdown({ hours, onVendorClick, compact }: {
  hours: number; onVendorClick?: (vendor: string) => void; compact?: boolean;
}) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/by-vendor?hours=${hours}`).then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const total = data.reduce((s, r) => s + parseInt(r.log_count), 0) || 1;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '16px 20px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 1, flexShrink: 0 }}>Logs by Vendor</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8, flexShrink: 0 }}>Distribution — {hours}h</div>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 7, justifyContent: 'space-evenly' }}>
        {data.map(row => {
          const count = parseInt(row.log_count); const pct = Math.round((count / total) * 100);
          const color = VENDOR_COLORS[row.vendor] || '#9ca3af';
          const crit = parseInt(row.critical_count); const err = parseInt(row.error_count);
          return (
            <div key={row.vendor} onClick={() => onVendorClick && onVendorClick(row.vendor)}
              style={{ cursor: onVendorClick ? 'pointer' : 'default' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 3 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 7, height: 7, borderRadius: 2, background: color }} />
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontWeight: 600, textTransform: 'capitalize' }}>{row.vendor}</span>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{pct}%</span>
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  {crit > 0 && <span style={{ fontSize: 'var(--text-xs)', color: '#dc2626', background: '#fef2f2', border: '1px solid #fecaca', padding: '1px 4px', borderRadius: 6, fontWeight: 600 }}>{crit}c</span>}
                  {err  > 0 && <span style={{ fontSize: 'var(--text-xs)', color: '#ea580c', background: '#fff7ed', border: '1px solid #fed7aa', padding: '1px 4px', borderRadius: 6, fontWeight: 600 }}>{err}e</span>}
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 700 }}>{count.toLocaleString()}</span>
                </div>
              </div>
              <div style={{ height: 4, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }} />
              </div>
            </div>
          );
        })}
        {data.length === 0 && <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>No data</div>}
      </div>
    </div>
  );
}
