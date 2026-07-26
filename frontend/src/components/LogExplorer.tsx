'use client';
import { useState, useCallback, useEffect, useRef } from 'react';
import type { ExplorerFilter } from '@/app/page';
import LogDetailPanel from '@/components/LogDetailPanel';

// ExplorerFilter (defined in app/page.tsx) doesn't carry the deep-link `threat`
// filter, so widen it locally for the spots that thread `threat` through.
type ExplorerFilterX = ExplorerFilter & { threat?: string };
import { PageHeader, TableSkeleton, EmptyState } from './ui';
import { sevStyle } from './severity';
import { VENDOR_COLORS } from './palette';

// ── Preset saved searches ─────────────────────────────────────
const PRESETS = [
  { label: '🔐 Failed Logins',       category: 'authentication', severity: '3,4', q: 'fail', vendor: '' },
  { label: '🛡️ VPN Events',          category: 'vpn',            severity: '',    q: '',     vendor: '' },
  { label: '⚠️ SSL Alerts',          category: 'security',       severity: '',    q: 'ssl',  vendor: '' },
  { label: '🔌 Connection Failures', category: 'firewall',       severity: '',    q: 'fail', vendor: '' },
  { label: '⚙️ Config Changes',      category: 'configuration',  severity: '',    q: '',     vendor: '' },
  { label: '🚫 IPS/Security',        category: 'security',       severity: '',    q: '',     vendor: '' },
  { label: '🔴 Critical Only',       category: '',               severity: '0,1,2', q: '',   vendor: '' },
  { label: '🌐 DNS Events',          category: 'dns',            severity: '',    q: '',     vendor: '' },
  { label: '💻 Windows Events',      category: '',               severity: '',    q: '',     vendor: 'windows' },
  { label: '🔥 Check Point',         category: '',               severity: '',    q: '',     vendor: 'checkpoint' },
];

const VENDORS = [
  'fortinet', 'cisco', 'paloalto', 'aruba', 'sangfor',
  'forcepoint', 'checkpoint', 'juniper', 'windows', 'sonicwall', 'generic',
];

const CATEGORIES = [
  { label: 'Auth',      value: 'authentication', color: '#7c3aed' },
  { label: 'VPN',       value: 'vpn',            color: '#0891b2' },
  { label: 'Firewall',  value: 'firewall',       color: '#dc2626' },
  { label: 'Security',  value: 'security',       color: '#ea580c' },
  { label: 'Config',    value: 'configuration',  color: '#ca8a04' },
  { label: 'Interface', value: 'interface',      color: '#16a34a' },
  { label: 'DNS',       value: 'dns',            color: '#2563eb' },
  { label: 'Web',       value: 'web',            color: '#0891b2' },
  { label: 'System',    value: 'system',         color: '#6b7280' },
];
const SEVERITIES = [
  { label: 'Critical',  value: '0,1,2', color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)',  border: 'var(--tint-danger)' },
  { label: 'Error',     value: '3',     color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)',    border: 'var(--tint-warn)' },
  { label: 'Warning',   value: '4',     color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)',    border: 'var(--tint-warn)' },
  { label: 'Notice',    value: '5',     color: 'var(--tint-info-fg)',    bg: 'var(--tint-info)',    border: 'var(--tint-info)' },
  { label: 'Info',      value: '6',     color: 'var(--tint-success-fg)', bg: 'var(--tint-success)', border: 'var(--tint-success)' },
];

interface ActiveFilter { type: 'vendor' | 'severity' | 'category' | 'host' | 'q' | 'technique' | 'threat'; value: string; label: string; }

// For auth/vpn events the syslog sender is the firewall; the meaningful source is the
// remote client (remip / structured_data.srcip). Returns the remote client IP when the
// event carries one AND it differs from the device's own source_ip — else null (unchanged).
function remoteClientIP(row: any): string | null {
  const cat = row?.category;
  if (cat !== 'authentication' && cat !== 'vpn') return null;
  const sd = row?.structured_data;
  if (!sd) return null;
  const remote = String(sd.remip || sd.srcip || '').replace('/32', '');
  if (!remote) return null;
  const deviceIP = (row.source_ip || '').replace('/32', '');
  if (remote === deviceIP) return null;
  return remote;
}

export default function LogExplorer({ initialFilter, onFilterUsed }: {
  initialFilter?: ExplorerFilterX;
  onFilterUsed?: () => void;
}) {
  const [q,          setQ]         = useState('');
  const [vendor,     setVendor]    = useState('');
  const [severity,   setSev]       = useState('');
  const [category,   setCategory]  = useState('');
  const [technique,  setTechnique] = useState('');
  const [threat,     setThreat]    = useState('');
  const [host,       setHost]      = useState('');
  const [hours,      setHours]     = useState('24');
  const [logs,       setLogs]      = useState<any[]>([]);
  const [total,      setTotal]     = useState(0);
  // total_is_capped: true when a free-text (q) search's count was capped at
  // 5,000 (perf pass, 2026-07 — see api/server.js) rather than an exact
  // scan-the-whole-table count. Drives the "5,000+" vs exact display below.
  const [totalCapped, setTotalCapped] = useState(false);
  const [loading,    setLoading]   = useState(false);
  const [selectedLog, setSelectedLog] = useState<any | null>(null);
  const [searched,   setSearched]  = useState(false);
  const [error,      setError]     = useState<string | null>(null);
  const [hostInput,  setHostInput] = useState('');
  const [showPresets, setShowPresets] = useState(false);

  // Apply initial filter from dashboard click
  useEffect(() => {
    if (initialFilter && Object.keys(initialFilter).length > 0) {
      if (initialFilter.q        !== undefined) setQ(initialFilter.q);
      if (initialFilter.severity !== undefined) setSev(initialFilter.severity);
      if (initialFilter.vendor   !== undefined) setVendor(initialFilter.vendor);
      if (initialFilter.category !== undefined) setCategory(initialFilter.category);
      if (initialFilter.technique!== undefined) setTechnique(initialFilter.technique);
      if (initialFilter.threat   !== undefined) setThreat(initialFilter.threat);
      if (initialFilter.host     !== undefined) setHost(initialFilter.host);
      if (initialFilter.hours    !== undefined) setHours(initialFilter.hours);
      if (onFilterUsed) onFilterUsed();
      setTimeout(() => triggerSearch(initialFilter), 100);
    }
  }, [initialFilter]);

  const abortRef = useRef<AbortController | null>(null);

  const triggerSearch = async (filter?: ExplorerFilterX) => {
    // Cancel any in-flight search so an older response can't clobber a newer one.
    if (abortRef.current) abortRef.current.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    setLoading(true); setError(null); setSearched(true);
    const f = filter || {};
    // Explicitly-provided keys (even '') override current state. This lets a toggled-off
    // chip clear its filter instead of falling back to stale closure state.
    const effQ        = 'q'        in f ? (f.q        || '') : q;
    const effVendor   = 'vendor'   in f ? (f.vendor   || '') : vendor;
    const effSeverity = 'severity' in f ? (f.severity || '') : severity;
    const effCategory = 'category' in f ? (f.category || '') : category;
    const effTechnique= 'technique'in f ? (f.technique|| '') : technique;
    const effThreat   = 'threat'   in f ? (f.threat   || '') : threat;
    const effHost     = 'host'     in f ? (f.host     || '') : host;
    try {
      const params = new URLSearchParams({ hours: f.hours || hours, limit: '200' });
      if (effQ)        params.set('q', effQ);
      if (effVendor)   params.set('vendor', effVendor);
      if (effSeverity) params.set('severity', effSeverity);
      if (effCategory) params.set('category', effCategory);
      if (effTechnique) params.set('technique', effTechnique);
      if (effThreat)   params.set('threat', effThreat);
      if (effHost)     params.set('host', effHost);
      const r = await fetch(`/api/logs?${params}`, { signal: ctrl.signal });
      if (!r.ok) throw new Error(`API error: ${r.status}`);
      const d = await r.json();
      setLogs(d.data || []); setTotal(d.total || 0); setTotalCapped(!!d.total_is_capped);
    } catch (e: any) {
      if (e.name === 'AbortError') return;   // superseded by a newer search — it owns the UI
      setError(e.message);
    } finally {
      // Only the most recent search controls the loading flag, so it never sticks.
      if (abortRef.current === ctrl) setLoading(false);
    }
  };

  const search = useCallback(() => triggerSearch(), [q, vendor, severity, category, technique, threat, host, hours]);

  const applyPreset = (preset: typeof PRESETS[0]) => {
    setQ(preset.q);
    setVendor(preset.vendor);
    setSev(preset.severity);
    setCategory(preset.category);
    setTechnique('');
    setShowPresets(false);
    // A preset is a fresh scoped search — clear any active technique deep-link too.
    setTimeout(() => triggerSearch({ q: preset.q, vendor: preset.vendor, severity: preset.severity, category: preset.category, technique: '' } as any), 50);
  };

  const removeFilter = (type: string) => {
    const override: ExplorerFilterX = {};
    if (type === 'vendor')   { setVendor('');   override.vendor = '';   }
    if (type === 'severity') { setSev('');       override.severity = ''; }
    if (type === 'category') { setCategory('');  override.category = ''; }
    if (type === 'technique'){ setTechnique(''); override.technique = ''; }
    if (type === 'threat')   { setThreat('');    override.threat = '';   }
    if (type === 'host')     { setHost('');      override.host = '';     }
    if (type === 'q')        { setQ('');         override.q = '';        }
    setTimeout(() => triggerSearch(override), 50);
  };

  const clearAll = () => {
    setVendor(''); setSev(''); setCategory(''); setTechnique(''); setThreat(''); setHost(''); setQ(''); setHostInput('');
    setTimeout(() => triggerSearch({ hours } as any), 50);
  };

  const addHostFilter = () => {
    if (hostInput.trim()) { setHost(hostInput.trim()); setHostInput(''); setTimeout(() => triggerSearch(), 50); }
  };

  // Active filter chips
  const activeFilters: ActiveFilter[] = [
    ...(vendor   ? [{ type: 'vendor'   as const, value: vendor,   label: `vendor: ${vendor}` }]   : []),
    ...(severity ? [{ type: 'severity' as const, value: severity, label: `severity: ${SEVERITIES.find(s => s.value === severity)?.label || severity}` }] : []),
    ...(category ? [{ type: 'category' as const, value: category, label: `category: ${CATEGORIES.find(c => c.value === category)?.label || category}` }] : []),
    ...(technique? [{ type: 'technique'as const, value: technique, label: `technique: ${technique}` }] : []),
    ...(threat   ? [{ type: 'threat'   as const, value: threat,   label: `threat: ${threat}` }]     : []),
    ...(host     ? [{ type: 'host'     as const, value: host,     label: `host: ${host}` }]         : []),
    ...(q        ? [{ type: 'q'        as const, value: q,        label: `search: "${q}"` }]         : []),
  ];

  const hasFilters = activeFilters.length > 0;

  return (
    <>
    <PageHeader title="Log Explorer" subtitle="Search and filter syslog entries with smart presets" />
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      padding: 16, boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Log Explorer</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
        Search and filter all stored logs · Click preset for common investigations
      </div>

      {/* ── Preset searches ── */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 500, marginRight: 2 }}>Quick:</span>
          {PRESETS.map((p, i) => (
            <button key={i} onClick={() => applyPreset(p)}
              style={{ padding: '4px 10px', borderRadius: 16, border: '1px solid var(--border)',
                cursor: 'pointer', fontSize: 'var(--text-xs)', fontWeight: 500,
                background: 'var(--bg-primary)', color: 'var(--text-secondary)',
                transition: 'all 0.15s', whiteSpace: 'nowrap' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--primary)'; (e.currentTarget as HTMLElement).style.color = '#fff'; (e.currentTarget as HTMLElement).style.borderColor = 'var(--primary)'; }}
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
          style={{ flex: 1, minWidth: 200, padding: '9px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg-input)',
            color: 'var(--text-primary)', fontSize: 'var(--text-base)', outline: 'none' }} />

        {/* Time range */}
        <select value={hours} onChange={e => setHours(e.target.value)}
          style={{ padding: '9px 12px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)', cursor: 'pointer', outline: 'none' }}>
          {[['0.25','15 min'],['1','1h'],['6','6h'],['24','24h'],['48','48h'],['168','7d'],['720','30d']].map(([v,l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>

        {/* Search button */}
        <button onClick={search} disabled={loading}
          style={{ padding: '9px 22px', borderRadius: 6, border: 'none', cursor: 'pointer',
            fontSize: 'var(--text-base)', fontWeight: 600, background: 'var(--primary)', color: '#fff', opacity: loading ? 0.7 : 1 }}>
          {loading ? 'Searching...' : 'Search'}
        </button>

        {/* CSV export */}
        <button onClick={() => {
          const params = new URLSearchParams({ hours, ...(q && { q }), ...(vendor && { vendor }), ...(severity && { severity }), ...(category && { category }), ...(threat && { threat }), ...(host && { host }) });
          window.open(`/api/logs/export?${params}`, '_blank');
        }} title="Export to CSV"
          style={{ padding: '9px 12px', borderRadius: 6, border: '1px solid var(--border)',
            cursor: 'pointer', fontSize: 'var(--text-sm)', background: 'var(--bg-input)', color: 'var(--text-secondary)',
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
              cursor: 'pointer', fontSize: 'var(--text-xs)', fontWeight: vendor === v ? 600 : 400,
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
              cursor: 'pointer', fontSize: 'var(--text-xs)', fontWeight: severity === s.value ? 600 : 400,
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
              background: 'transparent', color: 'var(--text-primary)', fontSize: 'var(--text-xs)',
              outline: 'none', width: 140 }} />
          {hostInput && (
            <button onClick={addHostFilter}
              style={{ padding: '4px 8px', borderRadius: 16, border: '1px solid #C8102E',
                cursor: 'pointer', fontSize: 'var(--text-xs)', background: 'var(--primary)', color: '#fff' }}>
              Add
            </button>
          )}
        </div>
      </div>

      {/* ── Category chips row ── */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 500, marginRight: 2 }}>Category:</span>
        {CATEGORIES.map(c => (
          <button key={c.value} onClick={() => { const next = category === c.value ? '' : c.value; setCategory(next); setTimeout(() => triggerSearch({ category: next }), 50); }}
            style={{ padding: '4px 10px', borderRadius: 16,
              border: `1px solid ${category === c.value ? c.color : 'var(--border)'}`,
              cursor: 'pointer', fontSize: 'var(--text-xs)', fontWeight: category === c.value ? 600 : 400,
              background: category === c.value ? `${c.color}18` : 'transparent',
              color: category === c.value ? c.color : 'var(--text-muted)', transition: 'all 0.15s' }}>
            {c.label}
          </button>
        ))}
      </div>

      {/* ── Active filter tags (removable) ── */}
      {hasFilters && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Active:</span>
          {activeFilters.map(f => (
            <span key={f.type} style={{ display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '3px 8px 3px 10px', borderRadius: 16, fontSize: 'var(--text-xs)', fontWeight: 500,
              background: '#1a2744', color: '#fff', border: '1px solid #253352' }}>
              {f.label}
              <button onClick={() => removeFilter(f.type)}
                style={{ background: 'none', border: 'none', cursor: 'pointer',
                  color: '#94a3b8', fontSize: 'var(--text-base)', lineHeight: 1, padding: '0 2px' }}>
                ×
              </button>
            </span>
          ))}
          <button onClick={clearAll}
            style={{ padding: '3px 10px', borderRadius: 16, border: '1px solid var(--border)',
              cursor: 'pointer', fontSize: 'var(--text-xs)', background: 'transparent', color: 'var(--text-muted)' }}>
            Clear all
          </button>
        </div>
      )}

      {/* ── Results summary ── */}
      {searched && !loading && !error && (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 12, padding: '6px 12px',
          background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6 }}>
          {total === 0
            ? 'No logs found — try a wider time range or different filters'
            : `Showing ${logs.length} of ${total.toLocaleString()}${totalCapped ? '+' : ''} logs`}
        </div>
      )}
      {error && <div style={{ fontSize: 'var(--text-sm)', color: '#dc2626', marginBottom: 12 }}>Error: {error}</div>}

      {/* ── Log table ── */}
      {loading && logs.length === 0 ? (
        <TableSkeleton rows={8} cols={5} />
      ) : searched && !loading && !error && logs.length === 0 ? (
        <EmptyState title="No logs found" message="Try adjusting your filters or time range." />
      ) : (
      <div style={{ overflowX: 'auto', maxHeight: '60vh', overflowY: 'auto',
        border: '1px solid var(--border)', borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
          <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-card)', zIndex: 5, boxShadow: '0 1px 0 var(--border)' }}>
            <tr style={{ borderBottom: '2px solid var(--border)' }}>
              {['Time','Host','Vendor','Severity','Program','Message'].map(h => (
                <th key={h} style={{ padding: '10px 12px', textAlign: 'left', color: 'var(--text-muted)',
                  fontWeight: 600, fontSize: 'var(--text-xs)', whiteSpace: 'nowrap',
                  textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.map((row, i) => (
              <tr key={i} onClick={() => setSelectedLog(row)}
                style={{ borderBottom: '1px solid var(--border-light)', cursor: 'pointer',
                  background: selectedLog?.id === row.id ? 'var(--tint-info)' : i % 2 === 0 ? 'transparent' : 'var(--bg-primary)' }}
                onMouseEnter={e => { if (selectedLog?.id !== row.id) (e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)'; }}
                onMouseLeave={e => { if (selectedLog?.id !== row.id) (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? 'transparent' : 'var(--bg-primary)'; }}>
                <td style={{ padding: '9px 12px', color: 'var(--text-muted)', whiteSpace: 'nowrap',
                  fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                  {new Date(row.received_at).toLocaleString()}
                </td>
                <td style={{ padding: '9px 12px', fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-primary)' }}>
                  {(() => {
                    const remote = remoteClientIP(row);
                    return remote ? (
                      <>
                        <span style={{ color: 'var(--primary)', fontWeight: 600 }}>{remote}</span>
                        <div style={{ color: 'var(--text-muted)', fontWeight: 400, marginTop: 2 }}>
                          via {row.source_host || row.source_ip}
                        </div>
                      </>
                    ) : (row.source_host || row.source_ip);
                  })()}
                </td>
                <td style={{ padding: '9px 12px' }}>
                  <span style={{ fontSize: 'var(--text-xs)', padding: '2px 8px', borderRadius: 10, textTransform: 'capitalize',
                    background: `${VENDOR_COLORS[row.vendor] || '#6b7280'}18`,
                    color: VENDOR_COLORS[row.vendor] || '#6b7280', fontWeight: 500 }}>
                    {row.vendor}
                  </span>
                </td>
                <td style={{ padding: '9px 12px' }}>
                  <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase',
                    color: sevStyle(row.severity_label).color }}>
                    {row.severity_label}
                  </span>
                </td>
                <td style={{ padding: '9px 12px', color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                  {row.program || '-'}
                </td>
                <td style={{ padding: '9px 12px', color: 'var(--text-secondary)',
                  maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {row.message}
                </td>
              </tr>
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
      )}

      {/* Slide-over detail panel */}
      <LogDetailPanel
        log={selectedLog}
        onClose={() => setSelectedLog(null)}
        onFilterIP={ip => { setHost(ip); setTimeout(() => triggerSearch(), 50); }}
        onFilterVendor={v => { setVendor(v); setTimeout(() => triggerSearch(), 50); }}
        onFilterSeverity={s => { setSev(s); setTimeout(() => triggerSearch(), 50); }}
      />
    </div>
    </>
  );
}
