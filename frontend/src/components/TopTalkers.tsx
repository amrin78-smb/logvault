'use client';
import { useEffect, useState } from 'react';

const VENDOR_COLORS: Record<string, string> = {
  cisco: '#2563eb', paloalto: '#ea580c', fortinet: '#dc2626',
  aruba: '#7c3aed', sangfor: '#0891b2', generic: '#9ca3af', unknown: '#9ca3af',
  forcepoint: '#003087', checkpoint: '#E31937', juniper: '#84BD00',
  windows: '#0078D4', sonicwall: '#FF6600',
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
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '16px 20px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 1, flexShrink: 0 }}>Top Talkers</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8, flexShrink: 0 }}>Most active — {hours}h</div>
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
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500, maxWidth: 90, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.host}</span>
                </div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 600 }}>{parseInt(row.log_count).toLocaleString()}</span>
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
