'use client';
import { useState, useCallback, useEffect } from 'react';
import type { ExplorerFilter } from '@/app/page';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#dc2626',
  error: '#ea580c', warning: '#ca8a04', notice: '#2563eb',
  info: '#16a34a', debug: '#9ca3af',
};

const VENDOR_COLORS: Record<string, string> = {
  fortinet: '#ee4d2d', cisco: '#1ba0d7', paloalto: '#fa582d',
  aruba: '#f47920', sangfor: '#005bac', generic: '#6b7280',
};

// ── Preset saved searches ─────────────────────────────────────
const PRESETS = [
  { label: '🔐 Failed Logins',      q: 'login failed',           vendor: '',          severity: '0,1,2,3,4' },
  { label: '🛡️ VPN Failures',       q: 'vpn fail',               vendor: 'fortinet',  severity: '3' },
  { label: '⚠️ SSL Alerts',         q: 'ssl-alert',              vendor: 'fortinet',  severity: '' },
  { label: '🔌 Connection Failures', q: 'Connection Failed',      vendor: 'fortinet',  severity: '4' },
  { label: '⚙️ Config Changes',     q: 'configured from',        vendor: '',          severity: '' },
  { label: '🚫 IPS Threats',        q: '',                       vendor: 'fortinet',  severity: '3', extra: { structuredType: 'utm' } },
  { label: '🔴 Critical Only',      q: '',                       vendor: '',          severity: '0,1,2' },
  { label: '🌐 DNS Failures',       q: 'dns',                    vendor: 'fortinet',  severity: '4' },
];

const VENDORS    = ['cisco', 'paloalto', 'fortinet', 'aruba', 'sangfor', 'generic'];
const SEVERITIES = [
  { label: 'Critical',  value: '0,1,2', color: '#dc2626', bg: '#fef2f2', border: '#fecaca' },
  { label: 'Error',     value: '3',     color: '#ea580c', bg: '#fff7ed', border: '#fed7aa' },
  { label: 'Warning',   value: '4',     color: '#ca8a04', bg: '#fefce8', border: '#fde68a' },
  { label: 'Notice',    value: '5',     color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe' },
  { label: 'Info',      value: '6',     color: '#16a34a', bg: '#f0fdf4', border: '#bbf7d0' },
];

interface ActiveFilter { type: 'vendor' | 'severity' | 'host' | 'q'; value: string; label: string; }

export default function LogExplorer({ initialFilter, onFilterUsed }: {
  initialFilter?: ExplorerFilter;
  onFilterUsed?: () => void;
}) {
  const [q,          setQ]         = useState('');
  const [vendor,     setVendor]    = useState('');
  const [severity,   setSev]       = useState('');
  const [host,       setHost]      = useState('');
  const [hours,      setHours]     = useState('24');
  const [logs,       setLogs]      = useState<any[]>([]);
  const [total,      setTotal]     = useState(0);
  const [loading,    setLoading]   = useState(false);
  const [expanded,   setExpanded]  = useState<number | null>(null);
  const [searched,   setSearched]  = useState(false);
  const [error,      setError]     = useState<string | null>(null);
  const [hostInput,  setHostInput] = useState('');
  const [showPresets, setShowPresets] = useState(false);

  // Apply initial filter from dashboard click
  useEffect(() => {
    if (initialFilter && Object.keys(initialFilter).length > 0) {
      if (initialFilter.severity !== undefined) setSev(initialFilter.severity);
      if (initialFilter.vendor   !== undefined) setVendor(initialFilter.vendor);
      if (initialFilter.host     !== undefined) setHost(initialFilter.host);
      if (initialFilter.hours    !== undefined) setHours(initialFilter.hours);
      if (onFilterUsed) onFilterUsed();
      setTimeout(() => triggerSearch(initialFilter), 100);
    }
  }, [initialFilter]);

  const triggerSearch = async (filter?: ExplorerFilter) => {
    setLoading(true); setError(null); setSearched(true);
    const f = filter || {};
    try {
      const params = new URLSearchParams({
        hours: f.hours || hours,
        limit: '200',
        ...(q                        && { q }),
        ...(f.vendor   || vendor     ? { vendor:   f.vendor   || vendor   } : {}),
        ...(f.severity || severity   ? { severity: f.severity || severity } : {}),
        ...(f.host     || host       ? { host:     f.host     || host     } : {}),
      });
      const r = await fetch(`/api/logs?${params}`);
      if (!r.ok) throw new Error(`API error: ${r.status}`);
      const d = await r.json();
      setLogs(d.data || []); setTotal(d.total || 0);
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  const search = useCallback(() => triggerSearch(), [q, vendor, severity, host, hours]);

  const applyPreset = (preset: typeof PRESETS[0]) => {
    setQ(preset.q);
    setVendor(preset.vendor);
    setSev(preset.severity);
    setShowPresets(false);
    setTimeout(() => triggerSearch({ q: preset.q, vendor: preset.vendor, severity: preset.severity } as any), 50);
  };

  const removeFilter = (type: string) => {
    if (type === 'vendor')   { setVendor('');   }
    if (type === 'severity') { setSev('');       }
    if (type === 'host')     { setHost('');      }
    if (type === 'q')        { setQ('');         }
    setTimeout(() => triggerSearch(), 50);
  };

  const clearAll = () => {
    setVendor(''); setSev(''); setHost(''); setQ(''); setHostInput('');
    setTimeout(() => triggerSearch({ hours } as any), 50);
  };

  const addHostFilter = () => {
    if (hostInput.trim()) { setHost(hostInput.trim()); setHostInput(''); setTimeout(() => triggerSearch(), 50); }
  };

  // Active filter chips
  const activeFilters: ActiveFilter[] = [
    ...(vendor   ? [{ type: 'vendor'   as const, value: vendor,   label: `vendor: ${vendor}` }]   : []),
    ...(severity ? [{ type: 'severity' as const, value: severity, label: `severity: ${SEVERITIES.find(s => s.value === severity)?.label || severity}` }] : []),
    ...(host     ? [{ type: 'host'     as const, value: host,     label: `host: ${host}` }]         : []),
    ...(q        ? [{ type: 'q'        as const, value: q,        label: `search: "${q}"` }]         : []),
  ];

  const hasFilters = activeFilters.length > 0;

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
      padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Log Explorer</div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>
        Search and filter all stored logs · Click preset for common investigations
      </div>

      {/* ── Preset searches ── */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500, marginRight: 2 }}>Quick:</span>
          {PRESETS.map((p, i) => (
            <button key={i} onClick={() => applyPreset(p)}
              style={{ padding: '4px 10px', borderRadius: 16, border: '1px solid var(--border)',
                cursor: 'pointer', fontSize: 11, fontWeight: 500,
                background: 'var(--bg-primary)', color: 'var(--text-secondary)',
                transition: 'all 0.15s', whiteSpace: 'nowrap' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#C8102E'; (e.currentTarget as HTMLElement).style.color = '#fff'; (e.currentTarget as HTMLElement).style.borderColor = '#C8102E'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-primary)'; (e.currentTarget as HTMLElement).style.color = 'var(--text-secondary)'; (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}>
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Search bar ── */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        {/* Message search */}
        <input value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Search message text..." 
          style={{ flex: 1, minWidth: 200, padding: '9px 12px', borderRadius: 7,
            border: '1px solid var(--border)', background: 'var(--input-bg)',
            color: 'var(--text-primary)', fontSize: 13, outline: 'none' }} />

        {/* Time range */}
        <select value={hours} onChange={e => setHours(e.target.value)}
          style={{ padding: '9px 12px', borderRadius: 7, border: '1px solid var(--border)',
            background: 'var(--input-bg)', color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer', outline: 'none' }}>
          {[['0.25','15 min'],['1','1h'],['6','6h'],['24','24h'],['48','48h'],['168','7d'],['720','30d']].map(([v,l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>

        {/* Search button */}
        <button onClick={search} disabled={loading}
          style={{ padding: '9px 22px', borderRadius: 7, border: 'none', cursor: 'pointer',
            fontSize: 13, fontWeight: 600, background: '#C8102E', color: '#fff', opacity: loading ? 0.7 : 1 }}>
          {loading ? 'Searching...' : 'Search'}
        </button>

        {/* CSV export */}
        <button onClick={() => {
          const params = new URLSearchParams({ hours, ...(q && { q }), ...(vendor && { vendor }), ...(severity && { severity }), ...(host && { host }) });
          window.open(`/api/logs/export?${params}`, '_blank');
        }} title="Export to CSV"
          style={{ padding: '9px 12px', borderRadius: 7, border: '1px solid var(--border)',
            cursor: 'pointer', fontSize: 12, background: 'var(--input-bg)', color: 'var(--text-secondary)',
            display: 'flex', alignItems: 'center', gap: 5 }}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M6 1v7M3 5l3 3 3-3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M1 9v1a1 1 0 001 1h8a1 1 0 001-1V9" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
          </svg>
          CSV
        </button>
      </div>

      {/* ── Filter chips row ── */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        {/* Vendor chips */}
        {VENDORS.map(v => (
          <button key={v} onClick={() => { setVendor(vendor === v ? '' : v); setTimeout(() => triggerSearch(), 50); }}
            style={{ padding: '4px 10px', borderRadius: 16, border: `1px solid ${vendor === v ? VENDOR_COLORS[v] : 'var(--border)'}`,
              cursor: 'pointer', fontSize: 11, fontWeight: vendor === v ? 600 : 400,
              background: vendor === v ? `${VENDOR_COLORS[v]}18` : 'transparent',
              color: vendor === v ? VENDOR_COLORS[v] : 'var(--text-muted)', transition: 'all 0.15s' }}>
            {v.charAt(0).toUpperCase() + v.slice(1)}
          </button>
        ))}

        <div style={{ width: 1, height: 16, background: 'var(--border)', margin: '0 2px' }} />

        {/* Severity chips */}
        {SEVERITIES.map(s => (
          <button key={s.value} onClick={() => { setSev(severity === s.value ? '' : s.value); setTimeout(() => triggerSearch(), 50); }}
            style={{ padding: '4px 10px', borderRadius: 16,
              border: `1px solid ${severity === s.value ? s.border : 'var(--border)'}`,
              cursor: 'pointer', fontSize: 11, fontWeight: severity === s.value ? 600 : 400,
              background: severity === s.value ? s.bg : 'transparent',
              color: severity === s.value ? s.color : 'var(--text-muted)', transition: 'all 0.15s' }}>
            {s.label}
          </button>
        ))}

        <div style={{ width: 1, height: 16, background: 'var(--border)', margin: '0 2px' }} />

        {/* Host filter input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <input value={hostInput} onChange={e => setHostInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addHostFilter()}
            placeholder="Filter by host/IP..."
            style={{ padding: '4px 10px', borderRadius: 16, border: '1px solid var(--border)',
              background: 'transparent', color: 'var(--text-primary)', fontSize: 11,
              outline: 'none', width: 140 }} />
          {hostInput && (
            <button onClick={addHostFilter}
              style={{ padding: '4px 8px', borderRadius: 16, border: '1px solid #C8102E',
                cursor: 'pointer', fontSize: 10, background: '#C8102E', color: '#fff' }}>
              Add
            </button>
          )}
        </div>
      </div>

      {/* ── Active filter tags (removable) ── */}
      {hasFilters && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Active:</span>
          {activeFilters.map(f => (
            <span key={f.type} style={{ display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '3px 8px 3px 10px', borderRadius: 16, fontSize: 11, fontWeight: 500,
              background: '#1a2744', color: '#fff', border: '1px solid #253352' }}>
              {f.label}
              <button onClick={() => removeFilter(f.type)}
                style={{ background: 'none', border: 'none', cursor: 'pointer',
                  color: '#94a3b8', fontSize: 13, lineHeight: 1, padding: '0 2px' }}>
                ×
              </button>
            </span>
          ))}
          <button onClick={clearAll}
            style={{ padding: '3px 10px', borderRadius: 16, border: '1px solid var(--border)',
              cursor: 'pointer', fontSize: 11, background: 'transparent', color: 'var(--text-muted)' }}>
            Clear all
          </button>
        </div>
      )}

      {/* ── Results summary ── */}
      {searched && !loading && !error && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, padding: '6px 12px',
          background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6 }}>
          {total === 0
            ? 'No logs found — try a wider time range or different filters'
            : `Showing ${logs.length} of ${total.toLocaleString()} logs`}
        </div>
      )}
      {error && <div style={{ fontSize: 12, color: '#dc2626', marginBottom: 12 }}>Error: {error}</div>}

      {/* ── Log table ── */}
      <div style={{ overflowX: 'auto', maxHeight: '60vh', overflowY: 'auto',
        border: '1px solid var(--border)', borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead style={{ position: 'sticky', top: 0, background: '#f9fafb', zIndex: 1 }}>
            <tr style={{ borderBottom: '2px solid var(--border)' }}>
              {['Time','Host','Vendor','Severity','Program','Message'].map(h => (
                <th key={h} style={{ padding: '10px 12px', textAlign: 'left', color: 'var(--text-muted)',
                  fontWeight: 600, fontSize: 11, whiteSpace: 'nowrap',
                  textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.map((row, i) => (
              <>
                <tr key={i} onClick={() => setExpanded(expanded === i ? null : i)}
                  style={{ borderBottom: '1px solid var(--border-light)', cursor: 'pointer',
                    background: expanded === i ? '#eff6ff' : i % 2 === 0 ? 'transparent' : 'var(--bg-primary)' }}
                  onMouseEnter={e => { if (expanded !== i) (e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)'; }}
                  onMouseLeave={e => { if (expanded !== i) (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? 'transparent' : 'var(--bg-primary)'; }}>
                  <td style={{ padding: '9px 12px', color: 'var(--text-muted)', whiteSpace: 'nowrap',
                    fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                    {new Date(row.received_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '9px 12px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: 11, fontWeight: 500, color: 'var(--text-primary)' }}>
                    {row.source_host || row.source_ip}
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 10, textTransform: 'capitalize',
                      background: `${VENDOR_COLORS[row.vendor] || '#6b7280'}18`,
                      color: VENDOR_COLORS[row.vendor] || '#6b7280', fontWeight: 500 }}>
                      {row.vendor}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                      color: SEV_COLORS[row.severity_label] || '#9ca3af' }}>
                      {row.severity_label}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px', color: 'var(--text-muted)', fontSize: 11 }}>
                    {row.program || '-'}
                  </td>
                  <td style={{ padding: '9px 12px', color: 'var(--text-secondary)',
                    maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {row.message}
                  </td>
                </tr>
                {expanded === i && (
                  <tr key={`exp-${i}`}>
                    <td colSpan={6} style={{ padding: '16px 24px', background: '#f0f7ff',
                      borderBottom: '1px solid #bfdbfe' }}>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--text-primary)' }}>
                        <div style={{ marginBottom: 8 }}>
                          <strong style={{ color: 'var(--text-muted)' }}>Message: </strong>
                          <span style={{ wordBreak: 'break-all' }}>{row.message}</span>
                        </div>
                        {row.structured_data && Object.keys(row.structured_data).length > 0 && (
                          <div style={{ marginBottom: 8 }}>
                            <strong style={{ color: 'var(--text-muted)' }}>Parsed fields: </strong>
                            <pre style={{ marginTop: 4, color: '#2563eb', overflow: 'auto',
                              background: '#fff', padding: 8, borderRadius: 4, border: '1px solid #bfdbfe' }}>
                              {JSON.stringify(row.structured_data, null, 2)}
                            </pre>
                          </div>
                        )}
                        <div style={{ display: 'flex', gap: 20, marginTop: 8,
                          color: 'var(--text-muted)', flexWrap: 'wrap' }}>
                          <span>IP: {row.source_ip}</span>
                          <span>Facility: {row.facility_label}</span>
                          <span>Parsed: {row.is_parsed ? 'Yes' : 'No'}</span>
                          {row.log_timestamp && <span>Device time: {new Date(row.log_timestamp).toLocaleString()}</span>}
                        </div>
                        {/* Quick filter buttons from expanded row */}
                        <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
                          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Filter by:</span>
                          {row.source_ip && (
                            <button onClick={() => { setHost(row.source_ip.replace('/32','')); setTimeout(() => triggerSearch(), 50); }}
                              style={{ padding: '2px 8px', borderRadius: 10, border: '1px solid var(--border)',
                                cursor: 'pointer', fontSize: 10, background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                              📍 {row.source_ip.replace('/32','')}
                            </button>
                          )}
                          {row.vendor && (
                            <button onClick={() => { setVendor(row.vendor); setTimeout(() => triggerSearch(), 50); }}
                              style={{ padding: '2px 8px', borderRadius: 10, border: '1px solid var(--border)',
                                cursor: 'pointer', fontSize: 10, background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                              🏷️ {row.vendor}
                            </button>
                          )}
                          {row.severity_label && (
                            <button onClick={() => { const s = SEVERITIES.find(x => x.label.toLowerCase() === row.severity_label); if(s) { setSev(s.value); setTimeout(() => triggerSearch(), 50); } }}
                              style={{ padding: '2px 8px', borderRadius: 10, border: '1px solid var(--border)',
                                cursor: 'pointer', fontSize: 10, background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                              🔴 {row.severity_label}
                            </button>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {logs.length === 0 && !loading && searched && (
              <tr><td colSpan={6} style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
                No logs found. Try adjusting your filters or widening the time range.
              </td></tr>
            )}
            {!searched && (
              <tr><td colSpan={6} style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
                Click a preset above or hit Search to load logs
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
