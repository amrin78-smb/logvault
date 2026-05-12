'use client';
import { useEffect, useState } from 'react';

const SEV_BG: Record<string, string> = {
  emergency: '#7f1d1d', alert: '#7f1d1d', critical: '#7f1d1d', error: '#431407',
};

export default function RecentCritical({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/logs/recent-critical?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Recent Critical / Error Events</div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e2d40' }}>
              {['Time','Host','Vendor','Severity','Message'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#64748b', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #0f1117', background: i % 2 === 0 ? '#0f1520' : 'transparent' }}>
                <td style={{ padding: '7px 12px', color: '#64748b', whiteSpace: 'nowrap' }}>{new Date(row.received_at).toLocaleTimeString()}</td>
                <td style={{ padding: '7px 12px', color: '#94a3b8' }}>{row.source_host || row.source_ip}</td>
                <td style={{ padding: '7px 12px', color: '#94a3b8', textTransform: 'capitalize' }}>{row.vendor}</td>
                <td style={{ padding: '7px 12px' }}>
                  <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                    background: SEV_BG[row.severity_label] || '#431407', color: '#fca5a5', textTransform: 'uppercase' }}>
                    {row.severity_label}
                  </span>
                </td>
                <td style={{ padding: '7px 12px', color: '#cbd5e1', maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {row.message}
                </td>
              </tr>
            ))}
            {data.length === 0 && (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: 'center', color: '#22c55e' }}>No critical events in the last {hours}h</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
