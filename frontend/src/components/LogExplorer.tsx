'use client';

import { useState, useCallback } from 'react';

const CARD  = { background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 };
const INPUT = {
  background: '#0f1117', border: '1px solid #1e2d40', borderRadius: 6,
  padding: '8px 12px', color: '#e2e8f0', fontSize: 13, outline: 'none'
};
const BTN = (active: boolean) => ({
  padding: '8px 16px', borderRadius: 6, border: '1px solid', cursor: 'pointer',
  fontSize: 13, fontWeight: 500,
  background: active ? '#1e3a5f' : '#161b27',
  borderColor: active ? '#38bdf8' : '#1e2d40',
  color: active ? '#38bdf8' : '#94a3b8'
});

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#ef4444',
  error: '#f97316', warning: '#eab308', notice: '#3b82f6',
  info: '#22c55e', debug: '#475569',
};

const VENDORS    = ['', 'cisco', 'paloalto', 'fortinet', 'aruba', 'sangfor', 'generic'];
const SEVERITIES = [
  { label: 'All Severities', value: '' },
  { label: '🔴 Critical',    value: '0,1,2' },
  { label: '🟠 Error',       value: '3' },
  { label: '🟡 Warning',     value: '4' },
  { label: '🔵 Notice',      value: '5' },
  { label: '🟢 Info',        value: '6' },
  { label: '⚫ Debug',       value: '7' },
];

export default function LogExplorer() {
  const [q, setQ]             = useState('');
  const [vendor, setVendor]   = useState('');
  const [severity, setSev]    = useState('');
  const [host, setHost]       = useState('');
  const [hours, setHours]     = useState('24');
  const [logs, setLogs]       = useState<any[]>([]);
  const [total, setTotal]     = useState(0);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [searched, setSearched] = useState(false);
  const [error, setError]     = useState<string | null>(null);

  const search = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSearched(true);
    try {
      const params = new URLSearchParams({
        hours,
        limit: '200',
        ...(q        && { q }),
        ...(vendor   && { vendor }),
        ...(severity && { severity }),
        ...(host     && { host }),
      });
      const r = await fetch(`/api/logs?${params}`);
      if (!r.ok) throw new Error(`API error: ${r.status}`);
      const d = await r.json();
      setLogs(d.data  || []);
      setTotal(d.total || 0);
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  }, [q, vendor, severity, host, hours]);

  return (
    <div style={CARD}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Log Explorer</div>

      {/* Filters */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16, alignItems: 'center' }}>
        <input value={q} onChange={e => setQ(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Search messages (leave blank for all)..."
          style={{ ...INPUT, flex: 1, minWidth: 200 }} />

        <select value={vendor} onChange={e => setVendor(e.target.value)}
          style={{ ...INPUT, cursor: 'pointer' }}>
          <option value="">All Vendors</option>
          {VENDORS.filter(v => v).map(v => (
            <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>
          ))}
        </select>

        <select value={severity} onChange={e => setSev(e.target.value)}
          style={{ ...INPUT, cursor: 'pointer' }}>
          {SEVERITIES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>

        <input value={host} onChange={e => setHost(e.target.value)}
          placeholder="Host filter..."
          style={{ ...INPUT, width: 140 }} />

        <select value={hours} onChange={e => setHours(e.target.value)}
          style={{ ...INPUT, cursor: 'pointer' }}>
          {[['1','1h'],['6','6h'],['24','24h'],['48','48h'],['168','7d'],['720','30d']].map(([v,l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>

        <button onClick={search} disabled={loading} style={{ ...BTN(true), opacity: loading ? 0.7 : 1 }}>
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {/* Status bar */}
      {searched && !loading && !error && (
        <div style={{ fontSize: 11, color: '#475569', marginBottom: 12 }}>
          {total === 0
            ? `No logs found in the last ${hours}h — try a wider time range`
            : `Showing ${logs.length} of ${total.toLocaleString()} logs`}
        </div>
      )}
      {error && (
        <div style={{ fontSize: 12, color: '#ef4444', marginBottom: 12 }}>Error: {error}</div>
      )}

      {/* Log table */}
      <div style={{ overflowX: 'auto', maxHeight: '60vh', overflowY: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead style={{ position: 'sticky', top: 0, background: '#161b27', zIndex: 1 }}>
            <tr style={{ borderBottom: '1px solid #1e2d40' }}>
              {['Time','Host','Vendor','Severity','Program','Message'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#64748b', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.map((row, i) => (
              <>
                <tr key={i} onClick={() => setExpanded(expanded === i ? null : i)}
                  style={{ borderBottom: '1px solid #0f1117', cursor: 'pointer',
                    background: expanded === i ? '#1a2332' : i % 2 === 0 ? '#0f1520' : 'transparent' }}>
                  <td style={{ padding: '7px 12px', color: '#64748b', whiteSpace: 'nowrap' }}>
                    {new Date(row.received_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '7px 12px', color: '#94a3b8' }}>
                    {row.source_host || row.source_ip}
                  </td>
                  <td style={{ padding: '7px 12px', color: '#94a3b8', textTransform: 'capitalize' }}>
                    {row.vendor}
                  </td>
                  <td style={{ padding: '7px 12px' }}>
                    <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                      color: SEV_COLORS[row.severity_label] || '#94a3b8' }}>
                      {row.severity_label}
                    </span>
                  </td>
                  <td style={{ padding: '7px 12px', color: '#64748b' }}>{row.program || '-'}</td>
                  <td style={{ padding: '7px 12px', color: '#cbd5e1', maxWidth: 500,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {row.message}
                  </td>
                </tr>
                {expanded === i && (
                  <tr key={`exp-${i}`}>
                    <td colSpan={6} style={{ padding: '12px 24px', background: '#0d1521', borderBottom: '1px solid #1e2d40' }}>
                      <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#94a3b8' }}>
                        <div style={{ marginBottom: 8 }}>
                          <strong style={{ color: '#64748b' }}>Message:</strong>
                          <div style={{ marginTop: 4, color: '#cbd5e1', wordBreak: 'break-all' }}>{row.message}</div>
                        </div>
                        {row.structured_data && Object.keys(row.structured_data).length > 0 && (
                          <div>
                            <strong style={{ color: '#64748b' }}>Parsed fields:</strong>
                            <pre style={{ marginTop: 4, color: '#7dd3fc', overflow: 'auto' }}>
                              {JSON.stringify(row.structured_data, null, 2)}
                            </pre>
                          </div>
                        )}
                        <div style={{ display: 'flex', gap: 24, marginTop: 8, color: '#475569', flexWrap: 'wrap' }}>
                          <span>IP: {row.source_ip}</span>
                          <span>Facility: {row.facility_label}</span>
                          <span>Parsed: {row.is_parsed ? 'Yes' : 'No'}</span>
                          {row.log_timestamp && <span>Device time: {new Date(row.log_timestamp).toLocaleString()}</span>}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {logs.length === 0 && !loading && searched && (
              <tr>
                <td colSpan={6} style={{ padding: 48, textAlign: 'center', color: '#475569' }}>
                  No logs found. Try selecting a wider time range.
                </td>
              </tr>
            )}
            {!searched && (
              <tr>
                <td colSpan={6} style={{ padding: 48, textAlign: 'center', color: '#475569' }}>
                  Click Search to load logs
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
