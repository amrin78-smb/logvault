'use client';
import { useEffect, useState } from 'react';

const SEV_STYLE: Record<string, { bg: string; color: string }> = {
  emergency: { bg: '#3d0f0f', color: '#f85149' },
  alert:     { bg: '#3d0f0f', color: '#f85149' },
  critical:  { bg: '#3d0f0f', color: '#f85149' },
  error:     { bg: '#2d1b0e', color: '#db6d28' },
};

export default function RecentCritical({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/logs/recent-critical?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: '#161c26', border: '1px solid #30363d', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>
        Recent Critical &amp; Error Events
      </div>
      <div style={{ fontSize: 11, color: '#6e7681', marginBottom: 16 }}>Latest severity 0–3 events</div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #21262d' }}>
              {['Time','Host','Vendor','Severity','Message'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#8b949e',
                  fontWeight: 600, whiteSpace: 'nowrap', fontSize: 11 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => {
              const sev = SEV_STYLE[row.severity_label] || { bg: '#2d1b0e', color: '#db6d28' };
              return (
                <tr key={i} style={{ borderBottom: '1px solid #161c26',
                  background: i % 2 === 0 ? '#0d1117' : 'transparent' }}>
                  <td style={{ padding: '8px 12px', color: '#6e7681', whiteSpace: 'nowrap',
                    fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                    {new Date(row.received_at).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: '8px 12px', color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                    {row.source_host || row.source_ip}
                  </td>
                  <td style={{ padding: '8px 12px', color: '#8b949e', textTransform: 'capitalize' }}>
                    {row.vendor}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                      background: sev.bg, color: sev.color, textTransform: 'uppercase',
                      border: `1px solid ${sev.color}44`, letterSpacing: '0.5px' }}>
                      {row.severity_label}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', color: '#c9d1d9', maxWidth: 500,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {row.message}
                  </td>
                </tr>
              );
            })}
            {data.length === 0 && (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: 'center', color: '#3fb950', fontSize: 13 }}>
                ✓ No critical events in the last {hours}h
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
