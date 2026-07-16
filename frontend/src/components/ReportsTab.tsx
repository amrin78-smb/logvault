'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import { LineChart, Line, BarChart, Bar, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { PageHeader, EmptyState, TableSkeleton } from '@/components/ui';
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

type ReportKey = 'security-summary' | 'site-activity' | 'mitre-coverage';
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
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }} />
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
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }} />
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
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }} />
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

  // activeRef mirrors `active` so the hours-change effect can re-fetch the
  // currently-selected report without adding a stale `active` closure to the
  // effect's dependency array (mirrors the previewSeq guard pattern used
  // elsewhere in the suite's ReportsTab reference implementation).
  const activeRef = useRef<ReportDef | null>(null);
  const seqRef = useRef(0);

  const generate = useCallback(async (def: ReportDef) => {
    activeRef.current = def;
    setActive(def);
    const seq = ++seqRef.current;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/reports/${def.key}?hours=${Math.max(1, Math.round(hours))}`);
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
  }, [hours]);

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
    const params = new URLSearchParams({ hours: String(Math.max(1, Math.round(hours))), format: fmt });
    window.open(`/api/reports/${active.key}?${params.toString()}`, '_blank');
  };

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
                <span style={{ width: 36, height: 36, borderRadius: 9, flexShrink: 0, color: r.color,
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
                        <div key={i} style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 10, padding: '10px 16px', minWidth: 120 }}>
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
                        <tbody>
                          {preview.rows.map((row, ri) => (
                            <tr key={ri}>
                              {preview.columns.map(c => (
                                <td key={c.key} style={{ textAlign: c.align || 'left' }}>
                                  {String(row[c.key] ?? '—')}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
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
