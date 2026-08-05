'use client';
import { useEffect, useState, useCallback } from 'react';
import { useToast } from '@/components/Toast';
import {PageHeader, TableSkeleton, EmptyState, PagedTableBody } from './ui';
import { SEV_COLORS, SEV_FALLBACK } from './severity';

// ════════════════════════════════════════════════════════════════════
// Phase 2 "Intelligence" console — behavioral anomalies + UEBA entity
// risk ranking, with drill-downs into the Log Explorer.
// Inline styles only (NocVault suite tokens). All sub-components are
// defined at module scope (never nested) per CLAUDE.md.
// ════════════════════════════════════════════════════════════════════

type DrillFilter = {
  host?: string; q?: string; category?: string; severity?: string;
  vendor?: string; technique?: string; threat?: string;
};

type OpenExplorer = (filter: DrillFilter) => void;

// Rows are loosely typed (`any`) — the backend may add fields and jsonb
// columns (detail / factors) vary in shape.
interface SummaryShape {
  total_24h?: number;
  unacknowledged?: number;
  by_type?: any[];
  by_severity?: any[];
}

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 20, marginBottom: 16 };
const TH   = { padding: '8px 12px', textAlign: 'left' as const, color: 'var(--text-muted)', fontWeight: 600, fontSize: 'var(--text-xs)' };
const TD   = { padding: '9px 12px', fontSize: 'var(--text-sm)' };
const MONO = { fontFamily: 'var(--font-mono)' };

// Anomaly severity → suite tint pair (info / warning / critical). Falls back
// to the canonical syslog palette for any other label, then SEV_FALLBACK.
const ANOMALY_SEV: Record<string, { bg: string; color: string }> = {
  info:     { bg: 'var(--tint-info)',   color: 'var(--tint-info-fg)' },
  warning:  { bg: 'var(--tint-warn)',   color: 'var(--tint-warn-fg)' },
  critical: { bg: 'var(--tint-danger)', color: 'var(--tint-danger-fg)' },
};

function anomalySevStyle(severity?: string): { bg: string; color: string } {
  const s = String(severity || '').toLowerCase();
  if (ANOMALY_SEV[s]) return ANOMALY_SEV[s];
  const c = SEV_COLORS[s] || SEV_FALLBACK;
  return { bg: c.bg, color: c.color };
}

// Map an entity_type → the Log Explorer drill filter. device / srcip search by
// host; user searches by free-text query. Returns null when nothing useful.
function entityDrillFilter(entityType?: string, entityValue?: string): DrillFilter | null {
  if (!entityValue) return null;
  const t = String(entityType || '').toLowerCase();
  if (t === 'device' || t === 'srcip') return { host: entityValue };
  if (t === 'user') return { q: entityValue };
  // Unknown entity type — best-effort free-text search so the link still lands.
  return { q: entityValue };
}

// Anomaly severity pill.
function AnomalySevBadge({ severity }: { severity?: string }) {
  const st = anomalySevStyle(severity);
  return (
    <span style={{ padding: '2px 7px', borderRadius: 'var(--radius-sm)', fontSize: 'var(--text-xs)', fontWeight: 700,
      background: st.bg, color: st.color, textTransform: 'uppercase', letterSpacing: '0.4px', whiteSpace: 'nowrap' }}>
      {severity || '—'}
    </span>
  );
}

// 0-100 risk badge, banded ≥81 critical / ≥61 high / ≥31 medium / else low.
function RiskScoreBadge({ score }: { score?: number | null }) {
  const n = typeof score === 'number' ? score : Number(score) || 0;
  let bg = 'var(--tint-success)'; let color = 'var(--tint-success-fg)'; let label = 'Low';
  if (n >= 81)      { bg = 'var(--tint-danger)';  color = 'var(--tint-danger-fg)';  label = 'Critical'; }
  else if (n >= 61) { bg = 'var(--tint-warn)';    color = 'var(--tint-warn-fg)';    label = 'High'; }
  else if (n >= 31) { bg = 'var(--tint-info)';    color = 'var(--tint-info-fg)';    label = 'Medium'; }
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ padding: '2px 9px', borderRadius: 'var(--radius-pill)', fontSize: 'var(--text-xs)', fontWeight: 700, background: bg, color }}>
        {Math.round(n)}
      </span>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{label}</span>
    </span>
  );
}

// KPI stat tile (mirrors the SecurityAnalysis StatCard idiom).
function StatCard({ value, label, danger = false }: { value: number; label: string; danger?: boolean }) {
  const on = danger && value > 0;
  const bg     = on ? 'var(--tint-danger)' : 'var(--bg-card)';
  const border = on ? 'var(--tint-danger)' : 'var(--border)';
  const color  = on ? 'var(--tint-danger-fg)' : 'var(--text-primary)';
  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 'var(--radius)', padding: '16px 18px',
      position: 'relative', overflow: 'hidden' }}>
      {on && <div style={{ position: 'absolute', top: 8, right: 10, fontSize: 'var(--text-lg)' }}>⚠️</div>}
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.8px' }}>{label}</div>
      <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color, lineHeight: 1 }}>{(value || 0).toLocaleString()}</div>
    </div>
  );
}

// ── UEBA baseline warm-up status panel ──
// Read-only readiness indicator: how many days of data we've accumulated toward
// the 7-day target, how many entities have learned baselines, and when the
// baselines were last rebuilt. Sourced from /api/ueba/baseline-status.
interface BaselineShape {
  target_days?: number;
  days_accumulated?: number;
  days_raw?: number;
  entities?: number;
  device_entities?: number;
  user_entities?: number;
  slots?: number;
  last_update?: string | null;
  earliest_log?: string | null;
  ready?: boolean;
}

function BaselineStatus() {
  const [data, setData] = useState<BaselineShape | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let active = true;
    fetch('/api/ueba/baseline-status')
      .then(r => r.json())
      .then((d: BaselineShape) => { if (active) { setData(d || null); setLoaded(true); } })
      .catch(() => { if (active) setLoaded(true); });
    return () => { active = false; };
  }, []);

  const target = Number(data?.target_days) || 7;
  const daysWhole = Math.max(0, Number(data?.days_accumulated) || 0);
  const daysRaw = Math.max(0, Number(data?.days_raw) || 0);
  const entities = Number(data?.entities) || 0;
  const ready = !!data?.ready;
  // Progress toward the target, by the finer raw days so the bar moves daily.
  const pct = Math.min(100, Math.round((daysRaw / target) * 100));

  const barColor = ready ? 'var(--tint-success-fg)' : 'var(--primary)';
  const statusLabel = !loaded ? 'Loading…'
    : ready ? 'Ready — baselines active'
    : entities > 0 ? 'Warming up — learning normal patterns'
    : 'Collecting data — baselines not built yet';
  const statusColor = ready ? 'var(--tint-success-fg)' : 'var(--text-secondary)';

  return (
    <div style={{ ...CARD, marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 2 }}>
        <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)' }}>UEBA Baseline Status</div>
        <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: statusColor }}>{statusLabel}</span>
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 14 }}>
        Anomaly detection learns each entity&rsquo;s normal hourly/day-of-week activity over a {target}-day window before flagging deviations.
      </div>

      {/* Days-of-data progress toward the target */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 5 }}>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontWeight: 600 }}>Data accumulated</span>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            {daysWhole} of {target} days
          </span>
        </div>
        <div style={{ height: 8, background: 'var(--border-light)', borderRadius: 'var(--radius-pill)', overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${pct}%`, background: barColor, borderRadius: 'var(--radius-pill)', transition: 'width 0.3s ease' }} />
        </div>
      </div>

      {/* Stat row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10 }}>
        <BaselineStat label="Entities with baselines" value={entities.toLocaleString()} />
        <BaselineStat label="Devices" value={(Number(data?.device_entities) || 0).toLocaleString()} />
        <BaselineStat label="Users" value={(Number(data?.user_entities) || 0).toLocaleString()} />
        <BaselineStat
          label="Last rebuild"
          value={data?.last_update ? fmtBaselineTime(data.last_update) : '—'} mono />
      </div>
    </div>
  );
}

// Small labeled stat tile for the baseline panel.
function BaselineStat({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '10px 12px' }}>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
      <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)',
        ...(mono ? { fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' } : {}) }}>{value}</div>
    </div>
  );
}

// Compact "time ago" for the last baseline rebuild.
function fmtBaselineTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '—';
  const mins = Math.floor((Date.now() - t) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// Build a short human summary from an anomaly's detail jsonb object.
function detailSummary(detail: any): string {
  if (!detail || typeof detail !== 'object') return '';
  const parts: string[] = [];
  for (const [k, v] of Object.entries(detail)) {
    if (v === null || v === undefined) continue;
    if (typeof v === 'object') continue; // skip nested objects/arrays for the inline summary
    parts.push(`${k}: ${String(v)}`);
    if (parts.length >= 3) break;
  }
  return parts.join(' · ');
}

// Format the top 1-2 UEBA factors as a compact label string.
function topFactorLabels(factors: any): string {
  if (!Array.isArray(factors) || factors.length === 0) return '—';
  return factors.slice(0, 2).map((f: any) => f?.label || '').filter(Boolean).join(', ') || '—';
}

// ── Entity risk slide-in panel (reuses AlertDetailPanel chrome) ──
function EntityPanel({ entity, openExplorer, onClose }: {
  entity: { type: string; value: string };
  openExplorer?: OpenExplorer;
  onClose: () => void;
}) {
  const [data, setData]       = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    setData(null);
    fetch(`/api/ueba/entity/${encodeURIComponent(entity.type)}/${encodeURIComponent(entity.value)}`)
      .then(r => r.json())
      .then(d => setData(d || null))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [entity.type, entity.value]);

  // Close on Escape.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const risk          = data?.risk || null;
  const factors: any[] = Array.isArray(risk?.factors) ? risk.factors
    : (Array.isArray(data?.risk?.factors) ? data.risk.factors : []);
  const recent: any[] = Array.isArray(data?.recent_anomalies) ? data.recent_anomalies : [];
  const events        = data?.events_summary || null;
  const byCategory: any[] = Array.isArray(events?.by_category) ? events.by_category : [];
  const maxContribution = factors.reduce((m: number, f: any) => Math.max(m, Number(f?.contribution) || 0), 0) || 1;

  const drill = entityDrillFilter(entity.type, entity.value);

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose}
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.3)', zIndex: 200, animation: 'fadeIn 0.2s ease' }} />

      {/* Panel */}
      <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: 480,
        background: 'var(--bg-card)', borderLeft: '1px solid var(--border)',
        boxShadow: '0 4px 16px rgba(0,0,0,0.12)', zIndex: 201, display: 'flex',
        flexDirection: 'column', animation: 'slideInRight 0.25s ease' }}>

        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)',
          background: '#1a2744', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 'var(--text-xs)', padding: '1px 6px', borderRadius: 'var(--radius-sm)',
                background: 'rgba(255,255,255,0.12)', color: '#cbd5e1', fontWeight: 600, textTransform: 'uppercase' }}>
                {entity.type}
              </span>
              <span style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#fff', wordBreak: 'break-all', ...MONO }}>
                {entity.value}
              </span>
            </div>
            <div style={{ marginTop: 8 }}>
              <RiskScoreBadge score={risk ? risk.risk_score : null} />
            </div>
          </div>
          <button onClick={onClose}
            style={{ background: 'rgba(255,255,255,0.1)', border: 'none', cursor: 'pointer',
              color: '#94a3b8', fontSize: 'var(--text-lg)', width: 28, height: 28, borderRadius: 'var(--radius-sm)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            ×
          </button>
        </div>

        {/* Scrollable content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {loading ? (
            <TableSkeleton rows={6} cols={2} />
          ) : !data ? (
            <EmptyState title="Could not load entity" message="No risk detail returned for this entity." />
          ) : (
            <>
              {/* Risk factors */}
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                  textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Risk Factors</div>
                {factors.length === 0 ? (
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                    No scored factors yet.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {factors.map((f: any, i: number) => {
                      const contribution = Number(f?.contribution) || 0;
                      const pct = Math.round((contribution / maxContribution) * 100);
                      return (
                        <div key={i}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{f?.label || '—'}</span>
                            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-secondary)' }}>
                              {contribution.toLocaleString()}
                            </span>
                          </div>
                          <div style={{ height: 8, background: 'var(--border-light)', borderRadius: 'var(--radius-pill)', overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${pct}%`, background: 'var(--primary)', borderRadius: 'var(--radius-pill)' }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Events summary */}
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                  textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Events Summary</div>
                {!events ? (
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                    No event activity recorded.
                  </div>
                ) : (
                  <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 12 }}>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: byCategory.length ? 12 : 0 }}>
                      <div>
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Total events</div>
                        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
                          {(Number(events.total) || 0).toLocaleString()}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Failed logins</div>
                        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--tint-danger-fg)' }}>
                          {(Number(events.failed_logins) || 0).toLocaleString()}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Last seen</div>
                        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-secondary)', ...MONO }}>
                          {events.last_seen ? new Date(events.last_seen).toLocaleString() : '—'}
                        </div>
                      </div>
                    </div>
                    {byCategory.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {byCategory.map((c: any, i: number) => (
                          <span key={i} style={{ fontSize: 'var(--text-xs)', padding: '2px 8px', borderRadius: 'var(--radius-pill)',
                            background: 'var(--surface-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                            {c?.category || '—'}: {(Number(c?.count) || 0).toLocaleString()}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Recent anomalies */}
              <div>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                  textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                  Recent Anomalies ({recent.length})
                </div>
                {recent.length === 0 ? (
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                    No anomalies recorded for this entity.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {recent.map((a: any, i: number) => (
                      <div key={a?.id ?? i} style={{ padding: '8px 12px', background: 'var(--bg-primary)',
                        border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3, flexWrap: 'wrap' }}>
                          <AnomalySevBadge severity={a?.severity} />
                          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{a?.anomaly_type || '—'}</span>
                          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', ...MONO }}>
                            {a?.detected_at ? new Date(a.detected_at).toLocaleString() : ''}
                          </span>
                        </div>
                        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)',
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {a?.title || '—'}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer action */}
        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          {openExplorer && drill ? (
            <button onClick={() => openExplorer(drill)}
              style={{ padding: '8px 16px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                background: 'var(--primary)', color: '#fff', fontSize: 'var(--text-sm)', fontWeight: 600 }}>
              View all events in Log Explorer →
            </button>
          ) : (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Entity risk derived from recent behavior.
            </span>
          )}
        </div>
      </div>

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
      `}</style>
    </>
  );
}

export default function IntelligenceConsole({ openExplorer, hours }: {
  openExplorer?: (filter: { host?: string; q?: string; category?: string; severity?: string; vendor?: string; technique?: string; threat?: string }) => void;
  hours?: string;
}) {
  const { toast } = useToast();
  const [activeTab,  setActiveTab]  = useState<'anomalies' | 'entities'>('anomalies');

  // Summary KPIs
  const [summary, setSummary] = useState<SummaryShape | null>(null);

  // Anomalies view
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [anomLoading, setAnomLoading] = useState(false);
  const [fType,    setFType]    = useState('');
  const [fSeverity, setFSeverity] = useState('');
  const [showAcked, setShowAcked] = useState(false);

  // Entities view
  const [entities, setEntities] = useState<any[]>([]);
  const [entLoading, setEntLoading] = useState(false);
  const [selectedEntity, setSelectedEntity] = useState<{ type: string; value: string } | null>(null);

  const hoursParam = hours || '24';

  const fetchSummary = useCallback(() => {
    fetch('/api/anomalies/summary')
      .then(r => r.json())
      .then(d => setSummary(d || null))
      .catch(() => {});
  }, []);

  const fetchAnomalies = useCallback(() => {
    setAnomLoading(true);
    const params = new URLSearchParams();
    params.set('hours', hoursParam);
    if (fType)     params.set('type', fType);
    if (fSeverity) params.set('severity', fSeverity);
    if (!showAcked) params.set('acknowledged', 'false');
    fetch(`/api/anomalies?${params.toString()}`)
      .then(r => r.json())
      .then(d => setAnomalies(Array.isArray(d?.data) ? d.data : []))
      .catch(() => setAnomalies([]))
      .finally(() => setAnomLoading(false));
  }, [hoursParam, fType, fSeverity, showAcked]);

  const fetchEntities = useCallback(() => {
    setEntLoading(true);
    fetch('/api/ueba/top?limit=50')
      .then(r => r.json())
      .then(d => setEntities(Array.isArray(d?.data) ? d.data : []))
      .catch(() => setEntities([]))
      .finally(() => setEntLoading(false));
  }, []);

  useEffect(() => { fetchSummary(); }, [fetchSummary]);
  useEffect(() => { fetchAnomalies(); }, [fetchAnomalies]);
  useEffect(() => { fetchEntities(); }, [fetchEntities]);

  // Acknowledge a single anomaly.
  const acknowledge = async (id: number) => {
    try {
      await fetch(`/api/anomalies/${id}/acknowledge`, { method: 'PATCH' });
      setAnomalies(prev => prev.map(a => a.id === id ? { ...a, acknowledged: true } : a));
      toast('Anomaly acknowledged', 'success');
      fetchSummary();
      if (!showAcked) fetchAnomalies();
    } catch {
      toast('Failed to acknowledge', 'error');
    }
  };

  // Acknowledge all currently-listed open anomalies.
  const acknowledgeAll = async () => {
    const ids = anomalies.filter(a => !a.acknowledged).map(a => a.id);
    if (ids.length === 0) return;
    try {
      await fetch('/api/anomalies/acknowledge-all', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      setAnomalies(prev => prev.map(a => ({ ...a, acknowledged: true })));
      toast(`${ids.length} anomalies acknowledged`, 'success');
      fetchSummary();
      if (!showAcked) fetchAnomalies();
    } catch {
      toast('Failed to acknowledge all', 'error');
    }
  };

  const drillAnomaly = (a: any) => {
    const filter = entityDrillFilter(a?.entity_type, a?.entity_value);
    if (openExplorer && filter) openExplorer(filter);
  };

  const byType: any[]     = Array.isArray(summary?.by_type) ? summary!.by_type : [];
  const bySeverity: any[] = Array.isArray(summary?.by_severity) ? summary!.by_severity : [];
  const openCount  = Number(summary?.unacknowledged) || 0;
  const total24h   = Number(summary?.total_24h) || 0;
  const openAnomalies = anomalies.filter(a => !a.acknowledged).length;

  const TABS = [
    { id: 'anomalies', label: `Anomalies${openCount > 0 ? ` (${openCount})` : ''}` },
    { id: 'entities',  label: 'Riskiest Entities' },
  ];

  return (
    <div>
      <PageHeader title="Intelligence" subtitle="Behavioral anomalies and entity risk (UEBA)" />

      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 16 }}>
        <StatCard value={openCount} label="Open Anomalies" danger />
        <StatCard value={total24h} label="Anomalies (24h)" />
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '16px 18px' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.8px' }}>By Severity</div>
          {bySeverity.length === 0 ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>—</div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {bySeverity.map((s: any, i: number) => {
                const st = anomalySevStyle(s?.severity);
                return (
                  <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 9px',
                    borderRadius: 'var(--radius-pill)', background: st.bg, color: st.color, fontSize: 'var(--text-xs)', fontWeight: 700 }}>
                    <span style={{ textTransform: 'uppercase', letterSpacing: '0.4px' }}>{s?.severity || '—'}</span>
                    <span>{(Number(s?.count) || 0).toLocaleString()}</span>
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 6, alignItems: 'center', flexWrap: 'wrap' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as 'anomalies' | 'entities')}
            style={{ padding: '6px 16px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
              fontSize: 'var(--text-sm)', fontWeight: activeTab === t.id ? 600 : 400,
              background: activeTab === t.id ? '#1a202c' : 'transparent',
              color: activeTab === t.id ? '#fff' : 'var(--text-muted)', transition: 'all 0.15s' }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── ANOMALIES VIEW ── */}
      {activeTab === 'anomalies' && (
        <div style={CARD}>
          {/* Filter controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
            <select value={fType} onChange={e => setFType(e.target.value)}
              style={{ padding: '6px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)', cursor: 'pointer' }}>
              <option value="">All types</option>
              {byType.map((t: any, i: number) => (
                <option key={i} value={t?.anomaly_type || ''}>
                  {(t?.anomaly_type || '—')}{t?.count != null ? ` (${t.count})` : ''}
                </option>
              ))}
            </select>

            <select value={fSeverity} onChange={e => setFSeverity(e.target.value)}
              style={{ padding: '6px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 'var(--text-sm)', cursor: 'pointer' }}>
              <option value="">All severities</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>

            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-sm)',
              color: 'var(--text-muted)', cursor: 'pointer' }}>
              <input type="checkbox" checked={showAcked} onChange={e => setShowAcked(e.target.checked)} style={{ cursor: 'pointer' }} />
              Show acknowledged
            </label>

            <div style={{ flex: 1 }} />

            {openAnomalies > 0 && (
              <button onClick={acknowledgeAll} disabled={anomLoading}
                style={{ padding: '6px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--tint-danger)', cursor: 'pointer',
                  fontSize: 'var(--text-sm)', fontWeight: 600, background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)' }}>
                Acknowledge All ({openAnomalies})
              </button>
            )}
          </div>

          {anomLoading ? (
            <TableSkeleton rows={8} cols={7} />
          ) : anomalies.length === 0 ? (
            <EmptyState
              title="No anomalies yet"
              message="No anomalies yet — behavioral baselines build over the first 1–2 weeks of data; anomalies appear once normal patterns are learned." />
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                  {['Time','Type','Severity','Entity','Score','Title',''].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <PagedTableBody items={anomalies || []} unit="anomalies">
                {rows => rows.map((a: any, i: number) => {
                  const rowBg = a.acknowledged ? 'var(--bg-primary)' : i % 2 === 0 ? 'var(--bg-card)' : 'var(--surface-subtle)';
                  const summaryText = detailSummary(a?.detail);
                  const canDrill = !!(openExplorer && entityDrillFilter(a?.entity_type, a?.entity_value));
                  return (
                    <tr key={a?.id ?? i} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg,
                      opacity: a.acknowledged ? 0.6 : 1 }}>
                      <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {a?.detected_at ? new Date(a.detected_at).toLocaleString() : '—'}
                      </td>
                      <td style={{ ...TD, color: 'var(--text-secondary)' }}>{a?.anomaly_type || '—'}</td>
                      <td style={TD}><AnomalySevBadge severity={a?.severity} /></td>
                      <td style={{ ...TD, ...MONO, color: 'var(--text-primary)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>{a?.entity_type || '—'}: </span>
                        {a?.entity_value || '—'}
                      </td>
                      <td style={{ ...TD, fontWeight: 700, color: 'var(--text-secondary)' }}>
                        {a?.score != null ? (Number(a.score) || 0).toLocaleString() : '—'}
                      </td>
                      <td style={{ ...TD, color: 'var(--text-primary)', maxWidth: 360 }}>
                        <div style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {a?.title || '—'}
                        </div>
                        {summaryText && (
                          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {summaryText}
                          </div>
                        )}
                      </td>
                      <td style={{ ...TD, whiteSpace: 'nowrap', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                          {canDrill && (
                            <button onClick={() => drillAnomaly(a)} title="Open in Log Explorer"
                              style={{ padding: '3px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', cursor: 'pointer',
                                fontSize: 'var(--text-xs)', background: 'var(--surface-subtle)', color: 'var(--text-secondary)', fontWeight: 500 }}>
                              View in Explorer →
                            </button>
                          )}
                          {a.acknowledged ? (
                            <span style={{ color: '#16a34a', fontSize: 'var(--text-xs)', fontWeight: 600 }}>✓ Acked</span>
                          ) : (
                            <button onClick={() => acknowledge(a.id)}
                              style={{ padding: '3px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', cursor: 'pointer',
                                fontSize: 'var(--text-xs)', background: 'var(--surface-subtle)', color: 'var(--text-secondary)', fontWeight: 500 }}>
                              Acknowledge
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </PagedTableBody>
            </table>
          )}
        </div>
      )}

      {/* ── RISKIEST ENTITIES VIEW ── */}
      {activeTab === 'entities' && (
        <>
        <BaselineStatus />
        <div style={CARD}>
          <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Riskiest Entities</div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
            Ranked by UEBA risk score — click a row to inspect the full risk breakdown
          </div>

          {entLoading ? (
            <TableSkeleton rows={8} cols={6} />
          ) : entities.length === 0 ? (
            <EmptyState
              title="No entity risk scores yet"
              message="No entity risk scores yet — populates as events are scored (within minutes of deploy)." />
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                  {['Entity','Risk','Top Factors','Events','Anomalies','Last Activity'].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <PagedTableBody items={entities || []} unit="entities">
                {rows => rows.map((r: any, i: number) => {
                  const rowBg = i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                  return (
                    <tr key={i}
                      onClick={() => setSelectedEntity({ type: r?.entity_type, value: r?.entity_value })}
                      title="View entity risk detail"
                      style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, cursor: 'pointer' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = rowBg; }}>
                      <td style={{ ...TD, ...MONO, color: 'var(--text-primary)', fontWeight: 500, whiteSpace: 'nowrap' }}>
                        <span style={{ color: 'var(--text-muted)' }}>{r?.entity_type || '—'}: </span>
                        {r?.entity_value || '—'}
                      </td>
                      <td style={TD}><RiskScoreBadge score={r?.risk_score} /></td>
                      <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 280, overflow: 'hidden',
                        textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {topFactorLabels(r?.factors)}
                      </td>
                      <td style={{ ...TD, color: 'var(--text-secondary)' }}>{(Number(r?.event_count) || 0).toLocaleString()}</td>
                      <td style={TD}>
                        <span style={{ fontWeight: 700, padding: '2px 8px', borderRadius: 'var(--radius-pill)',
                          background: (Number(r?.anomaly_count) || 0) > 0 ? 'var(--tint-danger)' : 'var(--surface-subtle)',
                          color: (Number(r?.anomaly_count) || 0) > 0 ? 'var(--tint-danger-fg)' : 'var(--text-muted)' }}>
                          {(Number(r?.anomaly_count) || 0).toLocaleString()}
                        </span>
                      </td>
                      <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {r?.last_activity ? new Date(r.last_activity).toLocaleString() : '—'}
                      </td>
                    </tr>
                  );
                })}
              </PagedTableBody>
            </table>
          )}
        </div>
        </>
      )}

      {/* Entity slide-in panel */}
      {selectedEntity && selectedEntity.type && selectedEntity.value && (
        <EntityPanel
          entity={selectedEntity}
          openExplorer={openExplorer}
          onClose={() => setSelectedEntity(null)} />
      )}
    </div>
  );
}
