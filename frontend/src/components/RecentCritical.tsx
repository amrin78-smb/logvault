'use client';
import { useEffect, useState } from 'react';

const SEV_STYLE: Record<string, { bg: string; color: string; border: string }> = {
  emergency: { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
  alert:     { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
  critical:  { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
  error:     { bg: '#fff7ed', color: '#ea580c', border: '#fed7aa' },
};

const SEV_FILTER: Record<string, string> = {
  emergency: '0', alert: '1', critical: '2', error: '3',
};

export default function RecentCritical({ hours, onRowClick }: {
  hours: number;
  onRowClick?: (severity: string) => void;
}) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/logs/recent-critical?hours=${hours}`).then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid #e2e6ea', borderRadius: 8, padding: 16 }}>
      <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Recent Critical &amp; Error Events</div>
      <div style={{ fontSize: 'var(--text-xs)', color: '#718096', marginBottom: 16 }}>
        {onRowClick ? 'Click a row to view similar logs' : 'Latest severity 0–3 events'}
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #f0f2f5' }}>
              {['Time','Host','Vendor','Severity','Message'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#718096', fontWeight: 600, fontSize: 'var(--text-xs)', whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => {
              const sev = SEV_STYLE[row.severity_label] || SEV_STYLE.error;
              return (
                <tr key={i}
                  onClick={() => onRowClick && onRowClick(SEV_FILTER[row.severity_label] || '3')}
                  style={{ borderBottom: '1px solid #f0f2f5',
                    background: i % 2 === 0 ? '#fafbfc' : 'var(--bg-card)',
                    cursor: onRowClick ? 'pointer' : 'default',
                    transition: 'background 0.1s' }}
                  onMouseEnter={e => { if (onRowClick) (e.currentTarget as HTMLElement).style.background = '#eff6ff'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? '#fafbfc' : 'var(--bg-card)'; }}>
                  <td style={{ padding: '8px 12px', color: '#9ca3af', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                    {new Date(row.received_at).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: '8px 12px', color: '#1a202c', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 500 }}>
                    {row.source_host || row.source_ip}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ fontSize: 'var(--text-xs)', color: '#4a5568', background: '#f0f2f5', padding: '2px 8px', borderRadius: 10, textTransform: 'capitalize' }}>{row.vendor}</span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 700,
                      background: sev.bg, color: sev.color, border: `1px solid ${sev.border}`,
                      textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {row.severity_label}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', color: '#4a5568', maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {row.message}
                  </td>
                </tr>
              );
            })}
            {data.length === 0 && (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>
                ✓ No critical events in the last {hours}h
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
