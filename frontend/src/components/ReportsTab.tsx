'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { LineChart, Line, BarChart, Bar, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { PageHeader, EmptyState, TableSkeleton, PagedTableBody } from '@/components/ui';
import TimeRangePicker from '@/components/TimeRangePicker';

// ════════════════════════════════════════════════════════════
// Reports tab — Phase 1. Two-pane layout: left = report catalog
// (3 fixed report types), right = live JSON preview (summary
// tiles + charts + data table) with CSV/PDF export.
//
// RBAC note: every report is scoped server-side to the viewing
// user's assigned sites (identical to every other LogVault page),
// so there is deliberately no site/scope picker here — only a
// time-range control.
// ════════════════════════════════════════════════════════════

// ── API contract (fixed) ───────────────────────────────────────
interface ReportColumn { key: string; label: string; align?: 'left' | 'right' | 'center'; }
interface ReportSummary { label: string; value: string | number; color?: string; }
interface ReportChartSeries { label: string; points: number[]; color?: string; }
interface ReportChart { type: 'line' | 'bar' | 'area'; title: string; x: string[]; series: ReportChartSeries[]; yFormat?: string; }
interface ReportData {
  title: string;
  columns: ReportColumn[];
  rows: Record<string, unknown>[];
  summary: ReportSummary[];
  charts: ReportChart[];
}

type ReportKey = 'security-summary' | 'site-activity' | 'mitre-coverage' | 'web-usage' | 'blocked-threat' | 'custom';

// Builder metadata — served by GET /api/reports/dimensions from the SAME
// whitelist the backend gather enforces, so the picker can never offer an
// option the server would reject.
interface DimensionOpt { key: string; label: string; supportsCategory: boolean; }
interface BuilderMeta { dimensions: DimensionOpt[]; categories: string[]; chartTypes: string[]; limits: number[]; }
interface BuilderCfg { dimension: string; category: string; chart: string; limit: number; }
interface SavedReport { id: number; name: string; report_type: string; params: BuilderCfg; created_by: string | null; }

const DEFAULT_BUILDER: BuilderCfg = { dimension: 'category', category: '', chart: 'bar', limit: 25 };
interface ReportDef { key: ReportKey; title: string; desc: string; color: string; icon: React.ReactNode; }

// Hardcoded chart-series palette (module-level, not a design token) — mirrors
// the SEV_COLORS/VENDOR_COLORS exception documented in CLAUDE.md: chart series
// colors are a semantic data signal, not a themed surface, so they stay literal
// hex rather than var(--*) tokens (recharts SVG color resolution is unreliable
// with CSS custom properties inside stroke/fill attributes).
const CHART_PALETTE = ['#dc2626', '#2563eb', '#16a34a', '#7c3aed', '#ea580c', '#0891b2'];

// icon factory — called once at module init to build REPORTS, not a component
const I = (p: React.ReactNode) => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">{p}</svg>
);

const REPORTS: ReportDef[] = [
  {
    key: 'security-summary',
    title: 'Security Summary',
    desc: 'Severity distribution, category breakdown, alert counts, top talkers/blocked/failures and the log-volume trend.',
    color: 'var(--red)',
    icon: I(<><path d="M12 2.6 4.8 5.8v5.4c0 4.9 3.4 8.3 7.2 9.8 3.8-1.5 7.2-4.9 7.2-9.8V5.8L12 2.6z" /><polyline points="8.2 12.4 10.8 15 15.8 9.4" /></>),
  },
  {
    key: 'site-activity',
    title: 'Site / Device Activity',
    desc: 'Per-site log volume, vendor breakdown, top devices and active alerts by site.',
    color: 'var(--blue)',
    icon: I(<><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>),
  },
  {
    key: 'mitre-coverage',
    title: 'MITRE ATT&CK Coverage',
    desc: 'Tactic and technique coverage matrix with the top techniques observed over the period.',
    color: 'var(--purple)',
    icon: I(<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="0.6" fill="currentColor" /></>),
  },
  {
    key: 'web-usage',
    title: 'Web & User Activity',
    desc: 'Web volume trend, top users and hosts by web activity, with per-user share of the period. Scoped to web-category events only.',
    color: 'var(--teal)',
    icon: I(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18z" /></>),
  },
  {
    key: 'blocked-threat',
    title: 'Blocked & Threat Activity',
    desc: 'Blocked destinations and services, blocked-activity trend, known-bad IP contacts and TLS/IPSec error volume.',
    color: 'var(--orange)',
    icon: I(<><path d="M12 2.6 4.8 5.8v5.4c0 4.9 3.4 8.3 7.2 9.8 3.8-1.5 7.2-4.9 7.2-9.8V5.8L12 2.6z" /><line x1="9.2" y1="9.2" x2="14.8" y2="14.8" /><line x1="14.8" y1="9.2" x2="9.2" y2="14.8" /></>),
  },
  {
    key: 'custom',
    title: 'Custom Report',
    desc: 'Build your own: choose what to group by, optionally filter by category, pick a chart type and how many rows to show. Save it and re-run it later.',
    color: 'var(--green)',
    icon: I(<><line x1="4" y1="20" x2="4" y2="10" /><line x1="10" y1="20" x2="10" y2="4" /><line x1="16" y1="20" x2="16" y2="13" /><line x1="21" y1="20" x2="3" y2="20" /></>),
  },
];

const CARD: React.CSSProperties = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-sm)' };
const MUTED: React.CSSProperties = { fontSize: 'var(--text-sm)', color: 'var(--text-muted)' };

// A report's `summary` array is always a fixed 4 tiles (never shortened when
// there's no data), so `summary.length === 0` can never be true — checking it
// as an emptiness signal was dead code. security-summary's `rows` also isn't
// a reliable signal on its own (its top-talkers/blocked/failures list can be
// empty while totalLogs/the trend chart still have real data from a separate
// query) — so "no data" is judged across rows, chart points, AND summary
// values together, not any single field.
function isEmptyReport(p: ReportData): boolean {
  const hasRows = (p.rows?.length ?? 0) > 0;
  const hasChartData = (p.charts ?? []).some((c) => c.series.some((s) => s.points.some((v) => v !== 0)));
  const hasMeaningfulSummary = (p.summary ?? []).some((s) => {
    if (typeof s.value === 'number') return s.value !== 0;
    const v = String(s.value).trim();
    return v !== '' && v !== '0' && v !== '—' && v !== '-';
  });
  return !hasRows && !hasChartData && !hasMeaningfulSummary;
}

// ── Chart preview (Recharts line chart matching the JSON contract) ─────────
function ReportChartView({ chart }: { chart: ReportChart }) {
  const data = chart.x.map((xVal, i) => {
    const row: Record<string, string | number> = { x: xVal };
    for (const s of chart.series) row[s.label] = s.points[i] ?? 0;
    return row;
  });
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '12px 14px' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>{chart.title}</div>
      <div style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          {chart.type === 'bar' ? (
            <BarChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" vertical={false} />
              <XAxis dataKey="x" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: 12 }} />
              {chart.series.map((s, i) => (
                <Bar key={s.label} dataKey={s.label} name={s.label}
                  fill={s.color || CHART_PALETTE[i % CHART_PALETTE.length]} radius={[3, 3, 0, 0]} />
              ))}
            </BarChart>
          ) : chart.type === 'area' ? (
            <AreaChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
              <XAxis dataKey="x" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: 12 }} />
              {chart.series.map((s, i) => (
                <Area key={s.label} type="monotone" dataKey={s.label} name={s.label}
                  stroke={s.color || CHART_PALETTE[i % CHART_PALETTE.length]}
                  fill={s.color || CHART_PALETTE[i % CHART_PALETTE.length]} fillOpacity={0.15} strokeWidth={1.75} dot={false} />
              ))}
            </AreaChart>
          ) : (
            <LineChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
              <XAxis dataKey="x" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: 12 }} />
              {chart.series.map((s, i) => (
                <Line key={s.label} type="monotone" dataKey={s.label} name={s.label}
                  stroke={s.color || CHART_PALETTE[i % CHART_PALETTE.length]} strokeWidth={1.75} dot={false} />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
      {chart.series.length > 1 && (
        <div style={{ display: 'flex', gap: 12, marginTop: 6, flexWrap: 'wrap', justifyContent: 'center' }}>
          {chart.series.map((s, i) => (
            <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              {/* intentional: 1px on an 8x2 legend sliver — a token radius would round it away */}
              <div style={{ width: 8, height: 2, borderRadius: 1, background: s.color || CHART_PALETTE[i % CHART_PALETTE.length] }} />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{s.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ReportsTab() {
  const [active, setActive] = useState<ReportDef | null>(null);
  const [preview, setPreview] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hours, setHours] = useState(24);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [meta, setMeta] = useState<BuilderMeta | null>(null);
  const [cfg, setCfg] = useState<BuilderCfg>(DEFAULT_BUILDER);
  const [saved, setSaved] = useState<SavedReport[]>([]);
  const [saveName, setSaveName] = useState('');
  const cfgRef = useRef<BuilderCfg>(DEFAULT_BUILDER);
  cfgRef.current = cfg;

  // activeRef mirrors `active` so the hours-change effect can re-fetch the
  // currently-selected report without adding a stale `active` closure to the
  // effect's dependency array (mirrors the previewSeq guard pattern used
  // elsewhere in the suite's ReportsTab reference implementation).
  const activeRef = useRef<ReportDef | null>(null);
  const seqRef = useRef(0);

  // ONE place that turns state into query parameters. Used by the preview
  // fetch AND by both exports — if these were built separately, a custom
  // report could preview one dimension and export another, which is the exact
  // screen-vs-export drift this codebase has been bitten by before.
  const buildQuery = useCallback((def: ReportDef, c: BuilderCfg): URLSearchParams => {
    const qs = new URLSearchParams({ hours: String(Math.max(1, Math.round(hours))) });
    if (def.key === 'custom') {
      qs.set('dimension', c.dimension);
      qs.set('chart', c.chart);
      qs.set('limit', String(c.limit));
      // Only sent when the chosen dimension can honour it — the server rejects
      // a category filter on dimensions whose rollup has no category column,
      // rather than silently returning unfiltered totals.
      const dim = meta?.dimensions.find(d => d.key === c.dimension);
      if (c.category && dim?.supportsCategory) qs.set('category', c.category);
    }
    return qs;
  }, [hours, meta]);

  const generate = useCallback(async (def: ReportDef) => {
    activeRef.current = def;
    setActive(def);
    const seq = ++seqRef.current;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/reports/${def.key}?${buildQuery(def, cfgRef.current).toString()}`);
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { msg = (await res.json()).error || msg; } catch { /* non-JSON error body */ }
        throw new Error(msg);
      }
      const data: ReportData = await res.json();
      if (seq !== seqRef.current) return; // superseded by a newer request
      setPreview(data);
    } catch (e) {
      if (seq !== seqRef.current) return;
      setPreview(null);
      setError((e as Error).message || 'Failed to load report');
    } finally {
      if (seq === seqRef.current) setLoading(false);
    }
  }, [hours, buildQuery]);

  // Re-fetch the active report whenever the time range changes.
  useEffect(() => {
    if (activeRef.current) generate(activeRef.current);
  }, [hours, generate]);

  // Export downloads — mirrors the existing LogVault CSV export precedent
  // (LogExplorer.tsx: `window.open('/api/logs/export?...', '_blank')`).
  // Identity rides the session cookie through proxy.ts edge middleware for a
  // plain browser navigation, same as every other authenticated page/API
  // call in this app, so no fetch/blob indirection is needed here.
  const exportReport = (fmt: 'csv' | 'pdf') => {
    if (!active) return;
    const params = buildQuery(active, cfg);
    params.set('format', fmt);
    window.open(`/api/reports/${active.key}?${params.toString()}`, '_blank');
  };

  // Builder metadata + saved list, loaded once.
  useEffect(() => {
    let off = false;
    fetch('/api/reports/dimensions').then(r => r.ok ? r.json() : null).then(d => { if (!off && d) setMeta(d); }).catch(() => {});
    fetch('/api/reports/saved').then(r => r.ok ? r.json() : null).then(d => { if (!off && d) setSaved(d.data || []); }).catch(() => {});
    return () => { off = true; };
  }, []);

  // Re-run the custom report when its configuration changes.
  useEffect(() => {
    if (activeRef.current?.key === 'custom') generate(activeRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cfg.dimension, cfg.category, cfg.chart, cfg.limit]);

  const saveCurrent = async () => {
    const name = saveName.trim();
    if (!name || !active) return;
    const res = await fetch('/api/reports/saved', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, report_type: active.key, params: active.key === 'custom' ? cfg : {} }),
    });
    if (res.ok) {
      const row = await res.json();
      setSaved(s => [row, ...s]);
      setSaveName('');
    }
  };

  const loadSaved = (s: SavedReport) => {
    const def = REPORTS.find(r => r.key === s.report_type);
    if (!def) return;
    if (s.report_type === 'custom' && s.params) {
      const next = { ...DEFAULT_BUILDER, ...s.params };
      cfgRef.current = next;
      setCfg(next);
    }
    generate(def);
  };

  const deleteSaved = async (id: number) => {
    const res = await fetch(`/api/reports/saved/${id}`, { method: 'DELETE' });
    if (res.ok) setSaved(s => s.filter(x => x.id !== id));
  };

  const activeDim = meta?.dimensions.find(d => d.key === cfg.dimension);
  const SEL: React.CSSProperties = { padding: '6px 8px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 'var(--text-base)' };

  return (
    <div>
      <PageHeader title="Reports" subtitle="Generate exportable security, activity and MITRE coverage reports scoped to your assigned sites.">
        <TimeRangePicker
          hours={hours}
          onHoursChange={setHours}
          refreshInterval={refreshInterval}
          onRefreshChange={setRefreshInterval}
          onRefreshNow={() => { if (activeRef.current) generate(activeRef.current); }}
        />
      </PageHeader>

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        {/* ── LEFT — report catalog ── */}
        <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {REPORTS.map(r => {
            const on = active?.key === r.key;
            return (
              <button key={r.key} type="button" onClick={() => generate(r)}
                style={{ ...CARD, textAlign: 'left', cursor: 'pointer', padding: 14,
                  display: 'flex', gap: 12, alignItems: 'flex-start',
                  border: on ? `1px solid ${r.color}` : '1px solid var(--border)',
                  background: on ? 'var(--surface-subtle)' : 'var(--bg-card)' }}>
                <span style={{ width: 36, height: 36, borderRadius: 'var(--radius)', flexShrink: 0, color: r.color,
                  background: `color-mix(in srgb, ${r.color} 13%, transparent)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  {r.icon}
                </span>
                <span style={{ minWidth: 0 }}>
                  <span style={{ display: 'block', fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)' }}>{r.title}</span>
                  <span style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 3, lineHeight: 1.4 }}>{r.desc}</span>
                </span>
              </button>
            );
          })}

          {saved.length > 0 && (
            <div style={{ ...CARD, padding: 12 }}>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                Saved Reports
              </div>
              {saved.map(s => (
                <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 0', borderTop: '1px solid var(--border-light)' }}>
                  <button type="button" onClick={() => loadSaved(s)}
                    style={{ flex: 1, minWidth: 0, textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                      fontSize: 'var(--text-sm)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.name}
                  </button>
                  <button type="button" title="Delete" onClick={() => deleteSaved(s.id)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', padding: '0 2px' }}>
                    x
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── RIGHT — live preview ── */}
        <div style={{ ...CARD, flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          {!active ? (
            <div style={{ padding: 48 }}>
              <EmptyState title="Select a report" message="Choose a report from the list on the left to generate a preview." />
            </div>
          ) : (
            <>
              <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--border-light)',
                display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', alignItems: 'flex-start' }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)' }}>{preview?.title || active.title}</div>
                  <div style={{ ...MUTED, marginTop: 4 }}>Last {hours}h</div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  <button className="btn" disabled={!active} onClick={() => exportReport('csv')}>Export CSV</button>
                  <button className="btn btn-primary" disabled={!active} onClick={() => exportReport('pdf')}>Export PDF</button>
                </div>
              </div>

              {active.key === 'custom' && (
                <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border-light)', display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                  <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ ...MUTED, fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Group by</span>
                    <select style={SEL} value={cfg.dimension} onChange={e => setCfg(c => ({ ...c, dimension: e.target.value, category: '' }))}>
                      {(meta?.dimensions || []).map(d => <option key={d.key} value={d.key}>{d.label}</option>)}
                    </select>
                  </label>

                  <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ ...MUTED, fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Category</span>
                    {/* Disabled rather than hidden, with the reason stated: only
                        two rollups carry a category column, and the server
                        rejects the filter on the others instead of silently
                        returning unfiltered totals. */}
                    <select style={{ ...SEL, opacity: activeDim?.supportsCategory ? 1 : 0.5 }}
                      disabled={!activeDim?.supportsCategory}
                      title={activeDim?.supportsCategory ? '' : 'This dimension has no category breakdown'}
                      value={cfg.category} onChange={e => setCfg(c => ({ ...c, category: e.target.value }))}>
                      <option value="">All categories</option>
                      {(meta?.categories || []).map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </label>

                  <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ ...MUTED, fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Chart</span>
                    <select style={SEL} value={cfg.chart} onChange={e => setCfg(c => ({ ...c, chart: e.target.value }))}>
                      {(meta?.chartTypes || ['bar']).map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </label>

                  <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ ...MUTED, fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Rows</span>
                    <select style={SEL} value={cfg.limit} onChange={e => setCfg(c => ({ ...c, limit: parseInt(e.target.value, 10) || 25 }))}>
                      {(meta?.limits || [25]).map(n => <option key={n} value={n}>Top {n}</option>)}
                    </select>
                  </label>

                  <div style={{ display: 'flex', gap: 6, marginLeft: 'auto', alignItems: 'flex-end' }}>
                    <input style={{ ...SEL, width: 160 }} placeholder="Name this report" value={saveName}
                      onChange={e => setSaveName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') saveCurrent(); }} />
                    <button className="btn" disabled={!saveName.trim()} onClick={saveCurrent}>Save</button>
                  </div>
                </div>
              )}

              {loading ? (
                <TableSkeleton rows={8} cols={5} />
              ) : error ? (
                <div style={{ margin: 18, padding: '12px 14px', borderRadius: 'var(--radius-sm)',
                  background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)', fontSize: 'var(--text-base)' }}>
                  {error}
                </div>
              ) : preview && isEmptyReport(preview) ? (
                <EmptyState title="No data" message="No records matched the selected time range." />
              ) : preview ? (
                <div>
                  {/* summary tiles */}
                  {preview.summary && preview.summary.length > 0 && (
                    <div style={{ display: 'flex', gap: 12, padding: '14px 18px', flexWrap: 'wrap', borderBottom: '1px solid var(--border-light)' }}>
                      {preview.summary.map((s, i) => (
                        <div key={i} style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '10px 16px', minWidth: 120 }}>
                          <div style={{ fontSize: 'var(--text-xl)', fontWeight: 800, color: s.color || 'var(--text-primary)', lineHeight: 1 }}>{s.value}</div>
                          <div style={{ ...MUTED, marginTop: 4 }}>{s.label}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* charts */}
                  {preview.charts && preview.charts.length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 18px', borderBottom: '1px solid var(--border-light)' }}>
                      {preview.charts.map((c, i) => <ReportChartView key={i} chart={c} />)}
                    </div>
                  )}

                  {/* data table */}
                  {preview.rows && preview.rows.length > 0 && (
                    <div style={{ padding: '4px 18px 18px', overflowX: 'auto' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            {preview.columns.map(c => (
                              <th key={c.key} style={{ textAlign: c.align || 'left' }}>{c.label}</th>
                            ))}
                          </tr>
                        </thead>
                        <PagedTableBody items={preview.rows || []} unit="rows">
                          {rows => rows.map((row, ri) => (
                            <tr key={ri}>
                              {preview.columns.map(c => (
                                <td key={c.key} style={{ textAlign: c.align || 'left' }}>
                                  {String(row[c.key] ?? '—')}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </PagedTableBody>
                      </table>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ padding: 48 }}>
                  <EmptyState title="Ready to run" message="Adjust the time range above and select a report to generate it." />
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
