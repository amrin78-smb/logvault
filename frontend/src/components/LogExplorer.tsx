'use client';
import { useState, useCallback } from 'react';

const CARD  = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 };
const INPUT = { background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6, padding: '8px 12px', color: '#1a202c', fontSize: 13, outline: 'none' };
const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#dc2626',
  error: '#ea580c', warning: '#ca8a04', notice: '#2563eb', info: '#16a34a', debug: '#9ca3af',
};

const VENDORS    = ['', 'cisco', 'paloalto', 'fortinet', 'aruba', 'sangfor', 'generic'];
const SEVERITIES = [
  { label: 'All Severities', value: '' }, { label: '🔴 Critical', value: '0,1,2' },
  { label: '🟠 Error', value: '3' }, { label: '🟡 Warning', value: '4' },
  { label: '🔵 Notice', value: '5' }, { label: '🟢 Info', value: '6' },
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
    setLoading(true); setError(null); setSearched(true);
    try {
      const params = new URLSearchParams({ hours, limit: '200', ...(q && { q }), ...(vendor && { vendor }), ...(severity && { severity }), ...(host && { host }) });
      const r = await fetch(`/api/logs?${params}`);
      if (!r.ok) throw new Error(`API error: ${r.status}`);
      const d = await r.json();
      setLogs(d.data || []); setTotal(d.total || 0);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  }, [q, vendor, severity, host, hours]);

  return (
    <div style={CARD}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Log Explorer</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Search and filter all stored logs</div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16, alignItems: 'center' }}>
        <input value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Search messages..." style={{ ...INPUT, flex: 1, minWidth: 200 }} />
        <select value={vendor} onChange={e => setVendor(e.target.value)} style={{ ...INPUT, cursor: 'pointer' }}>
          <option value="">All Vendors</option>
          {VENDORS.filter(v => v).map(v => <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>)}
        </select>
        <select value={severity} onChange={e => setSev(e.target.value)} style={{ ...INPUT, cursor: 'pointer' }}>
          {SEVERITIES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <input value={host} onChange={e => setHost(e.target.value)} placeholder="Host..." style={{ ...INPUT, width: 130 }} />
        <select value={hours} onChange={e => setHours(e.target.value)} style={{ ...INPUT, cursor: 'pointer' }}>
          {[['1','1h'],['6','6h'],['24','24h'],['48','48h'],['168','7d'],['720','30d']].map(([v,l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <button onClick={search} disabled={loading}
          style={{ padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 13,
            fontWeight: 600, background: '#2563eb', color: '#ffffff', opacity: loading ? 0.7 : 1 }}>
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {searched && !loading && !error && (
        <div style={{ fontSize: 11, color: '#718096', marginBottom: 12, padding: '6px 12px',
          background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6 }}>
          {total === 0 ? `No logs found in the last ${hours}h — try a wider time range` : `Showing ${logs.length} of ${total.toLocaleString()} logs`}
        </div>
      )}
      {error && <div style={{ fontSize: 12, color: '#dc2626', marginBottom: 12 }}>Error: {error}</div>}

      <div style={{ overflowX: 'auto', maxHeight: '60vh', overflowY: 'auto', border: '1px solid #e2e6ea', borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead style={{ position: 'sticky', top: 0, background: '#f8f9fb', zIndex: 1 }}>
            <tr style={{ borderBottom: '2px solid #e2e6ea' }}>
              {['Time','Host','Vendor','Severity','Program','Message'].map(h => (
                <th key={h} style={{ padding: '10px 12px', textAlign: 'left', color: '#718096', fontWeight: 600, fontSize: 11, whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.map((row, i) => (
              <>
                <tr key={i} onClick={() => setExpanded(expanded === i ? null : i)}
                  style={{ borderBottom: '1px solid #f0f2f5', cursor: 'pointer',
                    background: expanded === i ? '#eff6ff' : i % 2 === 0 ? '#fafbfc' : '#ffffff' }}>
                  <td style={{ padding: '8px 12px', color: '#9ca3af', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                    {new Date(row.received_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '8px 12px', color: '#1a202c', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, fontWeight: 500 }}>
                    {row.source_host || row.source_ip}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ fontSize: 11, color: '#4a5568', background: '#f0f2f5', padding: '2px 8px', borderRadius: 10, textTransform: 'capitalize' }}>{row.vendor}</span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: SEV_COLORS[row.severity_label] || '#9ca3af' }}>
                      {row.severity_label}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', color: '#9ca3af' }}>{row.program || '-'}</td>
                  <td style={{ padding: '8px 12px', color: '#4a5568', maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {row.message}
                  </td>
                </tr>
                {expanded === i && (
                  <tr key={`exp-${i}`}>
                    <td colSpan={6} style={{ padding: '12px 24px', background: '#f0f7ff', borderBottom: '1px solid #bfdbfe' }}>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#1a202c' }}>
                        <div style={{ marginBottom: 8 }}>
                          <strong style={{ color: '#718096' }}>Message: </strong>
                          <span style={{ color: '#1a202c', wordBreak: 'break-all' }}>{row.message}</span>
                        </div>
                        {row.structured_data && Object.keys(row.structured_data).length > 0 && (
                          <div>
                            <strong style={{ color: '#718096' }}>Parsed fields: </strong>
                            <pre style={{ marginTop: 4, color: '#2563eb', overflow: 'auto', background: '#fff', padding: 8, borderRadius: 4, border: '1px solid #bfdbfe' }}>
                              {JSON.stringify(row.structured_data, null, 2)}
                            </pre>
                          </div>
                        )}
                        <div style={{ display: 'flex', gap: 20, marginTop: 8, color: '#9ca3af', flexWrap: 'wrap' }}>
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
              <tr><td colSpan={6} style={{ padding: 48, textAlign: 'center', color: '#9ca3af' }}>No logs found. Try a wider time range.</td></tr>
            )}
            {!searched && (
              <tr><td colSpan={6} style={{ padding: 48, textAlign: 'center', color: '#9ca3af' }}>Click Search to load logs</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
