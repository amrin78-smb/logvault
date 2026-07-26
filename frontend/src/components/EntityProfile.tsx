'use client';
import { useEffect, useMemo, useState } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import type { ExplorerFilter } from '@/app/page';
import { PageHeader, EmptyState, TableSkeleton, Skeleton, Spinner } from './ui';
import { SevBadge, sevLabel } from './severity';
import { RiskBadge, riskBand } from './palette';

// ════════════════════════════════════════════════════════════════════
// Phase 3 "Entity Profile" flagship page — a full UEBA entity explorer:
// a master list of risk-ranked entities on the left, a rich behavioral
// profile (risk-factor explainability, activity trend, recent anomalies,
// events summary) on the right.
//
// Companion to IntelligenceConsole's slide-in EntityPanel — this is the
// full dedicated page. Inline styles + NocVault suite design tokens only;
// all sub-components defined at module scope (never nested) per CLAUDE.md.
// ════════════════════════════════════════════════════════════════════

// ── Shared style consts ──────────────────────────────────────────────
const CARD: React.CSSProperties = {
  background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 20, marginBottom: 16,
};
const SECTION_LABEL: React.CSSProperties = {
  fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
  textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10,
};
const MONO: React.CSSProperties = { fontFamily: 'var(--font-mono)' };
const NOTE_BOX: React.CSSProperties = {
  fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12,
  background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8,
};

// ── Types (loose — the backend may add fields / jsonb shapes vary) ────
interface EntityRow {
  entity_type: string;
  entity_value: string;
  source_ip?: string | null;
  risk_score?: number | null;
  factors?: any;
  event_count?: number | null;
  anomaly_count?: number | null;
  last_activity?: string | null;
  updated_at?: string | null;
}
interface RiskFactor { label?: string; contribution?: number }
interface EntityRisk {
  risk_score?: number | null;
  factors?: RiskFactor[];
  event_count?: number | null;
  anomaly_count?: number | null;
  last_activity?: string | null;
}
interface RecentAnomaly {
  id?: number; detected_at?: string; anomaly_type?: string; severity?: string;
  title?: string; detail?: any; acknowledged?: boolean;
}
interface EventsSummary {
  total?: number;
  by_category?: { category?: string; count?: number }[];
  failed_logins?: number;
  last_seen?: string | null;
}
interface Profile {
  entity?: { type?: string; value?: string };
  risk?: EntityRisk | null;
  recent_anomalies?: RecentAnomaly[];
  events_summary?: EventsSummary | null;
}
interface TrendPoint { date?: string; count?: number; failed_logins?: number }
interface TrendAnomaly { detected_at?: string; anomaly_type?: string; severity?: string; title?: string }
interface Trend {
  type?: string; value?: string;
  series?: TrendPoint[];
  anomalies?: TrendAnomaly[];
}

// Type-filter tabs → the /api/ueba/top `type` query value.
const TYPE_TABS: { id: string; label: string }[] = [
  { id: '',       label: 'All' },
  { id: 'device', label: 'Devices' },
  { id: 'user',   label: 'Users' },
  { id: 'srcip',  label: 'Source IPs' },
];

// Human label for an entity_type chip.
function typeLabel(t?: string): string {
  const s = String(t || '').toLowerCase();
  if (s === 'device') return 'Device';
  if (s === 'user')   return 'User';
  if (s === 'srcip')  return 'Source IP';
  return t || '—';
}

// Adaptive tint pair per entity type for the small type chip.
function typeChipStyle(t?: string): { bg: string; color: string } {
  const s = String(t || '').toLowerCase();
  if (s === 'device') return { bg: 'var(--tint-info)',    color: 'var(--tint-info-fg)' };
  if (s === 'user')   return { bg: 'var(--tint-purple)',  color: 'var(--tint-purple-fg)' };
  if (s === 'srcip')  return { bg: 'var(--tint-warn)',    color: 'var(--tint-warn-fg)' };
  return { bg: 'var(--surface-subtle)', color: 'var(--text-secondary)' };
}

// Map an entity_type → the Log Explorer drill filter. device / srcip map to
// the log source, so search by host; user is a free-text query. (Mirrors the
// entityDrillFilter choice in IntelligenceConsole.)
function entityExplorerFilter(entityType?: string, entityValue?: string): ExplorerFilter | null {
  if (!entityValue) return null;
  const t = String(entityType || '').toLowerCase();
  if (t === 'device' || t === 'srcip') return { host: entityValue };
  return { q: entityValue };
}

// Compact "time ago".
function fmtRelative(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '—';
  const mins = Math.floor((Date.now() - t) / 60000);
  if (mins < 0) return 'just now';
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

// Short axis label for a YYYY-MM-DD trend point.
function fmtDay(date?: string): string {
  if (!date) return '';
  const d = new Date(`${date}T00:00:00`);
  if (isNaN(d.getTime())) return String(date);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function toNum(v: any): number { const n = Number(v); return isNaN(n) ? 0 : n; }

// ── Small type chip ──────────────────────────────────────────────────
function TypeChip({ type }: { type?: string }) {
  const st = typeChipStyle(type);
  return (
    <span style={{ fontSize: 'var(--text-xs)', padding: '1px 7px', borderRadius: 4, fontWeight: 600,
      background: st.bg, color: st.color, whiteSpace: 'nowrap', textTransform: 'uppercase', letterSpacing: '0.3px' }}>
      {typeLabel(type)}
    </span>
  );
}

// ── Master-list row ──────────────────────────────────────────────────
function EntityListItem({ row, active, onSelect }: {
  row: EntityRow; active: boolean; onSelect: () => void;
}) {
  const anomalies = toNum(row.anomaly_count);
  return (
    <button
      onClick={onSelect}
      title={row.entity_value}
      style={{
        display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer',
        padding: '10px 14px', border: 'none', borderLeft: `3px solid ${active ? 'var(--primary)' : 'transparent'}`,
        borderBottom: '1px solid var(--border-light)',
        background: active ? 'var(--primary-light)' : 'transparent',
        transition: 'background 0.12s',
      }}
      onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
      onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 5 }}>
        <TypeChip type={row.entity_type} />
        <RiskBadge score={toNum(row.risk_score)} />
      </div>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 500,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', ...MONO }}>
        {row.entity_value || '—'}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {toNum(row.event_count).toLocaleString()} events
        </span>
        {anomalies > 0 && (
          <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, padding: '0 6px', borderRadius: 8,
            background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)' }}>
            {anomalies.toLocaleString()} anomal{anomalies === 1 ? 'y' : 'ies'}
          </span>
        )}
      </div>
    </button>
  );
}

// ── Risk-factor breakdown (explainability) ───────────────────────────
function RiskFactors({ factors }: { factors: RiskFactor[] }) {
  const maxContribution = factors.reduce((m, f) => Math.max(m, toNum(f.contribution)), 0) || 1;
  if (factors.length === 0) {
    return <div style={NOTE_BOX}>No scored risk factors yet for this entity.</div>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {factors.map((f, i) => {
        const contribution = toNum(f.contribution);
        const pct = Math.round((contribution / maxContribution) * 100);
        return (
          <div key={i}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{f.label || '—'}</span>
              <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-secondary)', ...MONO }}>
                +{contribution.toLocaleString()}
              </span>
            </div>
            <div style={{ height: 8, background: 'var(--border-light)', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: 'var(--primary)', borderRadius: 4,
                transition: 'width 0.3s ease' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Activity trend (14-day area chart, anomaly days marked) ──────────
function ActivityTrend({ trend, loading }: { trend: Trend | null; loading: boolean }) {
  const series = Array.isArray(trend?.series) ? trend!.series! : [];
  const data = series.map(p => ({
    day: fmtDay(p.date),
    rawDate: p.date,
    count: toNum(p.count),
    failed_logins: toNum(p.failed_logins),
  }));
  // Anomaly days that fall on a series date → vertical reference markers.
  const anomalyDays = new Set(
    (Array.isArray(trend?.anomalies) ? trend!.anomalies! : [])
      .map(a => (a.detected_at ? String(a.detected_at).slice(0, 10) : ''))
      .filter(Boolean),
  );
  const markerDays = data.filter(d => d.rawDate && anomalyDays.has(String(d.rawDate))).map(d => d.day);
  const hasFailed = data.some(d => d.failed_logins > 0);
  const hasData = data.some(d => d.count > 0 || d.failed_logins > 0);

  return (
    <div style={{ height: 220 }}>
      {loading ? (
        <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Spinner size={18} />
        </div>
      ) : !hasData ? (
        <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
          No activity recorded in the last 14 days.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 8, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="ep-count" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="var(--primary)" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
            <XAxis dataKey="day" tick={{ fontSize: 'var(--text-xs)', fill: 'var(--text-muted)' }}
              axisLine={{ stroke: 'var(--border)' }} tickLine={false} interval="preserveStartEnd" />
            <YAxis tick={{ fontSize: 'var(--text-xs)', fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 6, fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }} />
            {markerDays.map((d, i) => (
              <ReferenceLine key={i} x={d} stroke="var(--tint-danger-fg)" strokeDasharray="2 2" strokeOpacity={0.7} />
            ))}
            <Area type="monotone" dataKey="count" name="Events" stroke="var(--primary)" strokeWidth={1.8}
              fill="url(#ep-count)" />
            {hasFailed && (
              <Area type="monotone" dataKey="failed_logins" name="Failed logins" stroke="#dc2626" strokeWidth={1.5}
                fill="#dc2626" fillOpacity={0.08} />
            )}
          </AreaChart>
        </ResponsiveContainer>
      )}
      {/* Legend */}
      <div style={{ display: 'flex', gap: 14, marginTop: 6, justifyContent: 'center', flexWrap: 'wrap' }}>
        <LegendDot color="var(--primary)" label="Events / day" />
        {hasFailed && <LegendDot color="#dc2626" label="Failed logins" />}
        {markerDays.length > 0 && <LegendDot color="var(--tint-danger-fg)" label="Anomaly day" dashed />}
      </div>
    </div>
  );
}

function LegendDot({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      <span style={{ width: dashed ? 12 : 8, height: dashed ? 0 : 8, borderRadius: dashed ? 0 : 2,
        background: dashed ? 'transparent' : color,
        borderTop: dashed ? `2px dashed ${color}` : undefined, display: 'inline-block' }} />
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{label}</span>
    </div>
  );
}

// ── Recent-anomalies list ────────────────────────────────────────────
function RecentAnomalies({ anomalies }: { anomalies: RecentAnomaly[] }) {
  if (anomalies.length === 0) {
    return <div style={NOTE_BOX}>No anomalies recorded for this entity.</div>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {anomalies.map((a, i) => (
        <div key={a.id ?? i} style={{ padding: '10px 12px', background: 'var(--bg-primary)',
          border: '1px solid var(--border)', borderRadius: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
            <SevBadge label={sevLabel(a.severity ?? '')} />
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 600 }}>
              {a.anomaly_type || '—'}
            </span>
            <span style={{ flex: 1 }} />
            {a.acknowledged && (
              <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, padding: '1px 7px', borderRadius: 8,
                background: 'var(--tint-success)', color: 'var(--tint-success-fg)' }}>
                ✓ Acknowledged
              </span>
            )}
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap', ...MONO }}>
              {fmtRelative(a.detected_at)}
            </span>
          </div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{a.title || '—'}</div>
          {a.detail && typeof a.detail === 'string' && (
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 3 }}>{a.detail}</div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Events summary ───────────────────────────────────────────────────
function EventsSummaryPane({ summary }: { summary: EventsSummary | null }) {
  if (!summary) {
    return <div style={NOTE_BOX}>No event activity recorded for this entity.</div>;
  }
  const byCategory = (Array.isArray(summary.by_category) ? summary.by_category : [])
    .slice()
    .sort((a, b) => toNum(b.count) - toNum(a.count));
  const maxCat = byCategory.reduce((m, c) => Math.max(m, toNum(c.count)), 0) || 1;
  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10, marginBottom: byCategory.length ? 16 : 0 }}>
        <SummaryStat label="Total events" value={toNum(summary.total).toLocaleString()} />
        <SummaryStat label="Failed logins" value={toNum(summary.failed_logins).toLocaleString()} danger={toNum(summary.failed_logins) > 0} />
        <SummaryStat label="Last seen" value={fmtRelative(summary.last_seen)} mono />
      </div>
      {byCategory.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
          {byCategory.map((c, i) => {
            const count = toNum(c.count);
            const pct = Math.round((count / maxCat) * 100);
            return (
              <div key={i}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                    {c.category || '—'}
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-secondary)', ...MONO }}>
                    {count.toLocaleString()}
                  </span>
                </div>
                <div style={{ height: 6, background: 'var(--border-light)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: 'var(--text-muted)', borderRadius: 3 }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SummaryStat({ label, value, danger, mono }: { label: string; value: string; danger?: boolean; mono?: boolean }) {
  return (
    <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px' }}>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
      <div style={{ fontSize: mono ? 'var(--text-sm)' : 'var(--text-lg)', fontWeight: 700,
        color: danger ? 'var(--tint-danger-fg)' : 'var(--text-primary)', ...(mono ? MONO : {}) }}>
        {value}
      </div>
    </div>
  );
}

// ── Profile pane (right column) ──────────────────────────────────────
function ProfilePane({ entity, profile, trend, loading, trendLoading, error, openExplorer }: {
  entity: { type: string; value: string };
  profile: Profile | null;
  trend: Trend | null;
  loading: boolean;
  trendLoading: boolean;
  error: boolean;
  openExplorer: (filter: ExplorerFilter) => void;
}) {
  if (loading) {
    return (
      <div style={CARD}>
        <Skeleton height={26} width="45%" />
        <div style={{ height: 12 }} />
        <Skeleton height={14} width="30%" />
        <div style={{ height: 24 }} />
        <TableSkeleton rows={6} cols={2} />
      </div>
    );
  }
  if (error) {
    return (
      <div style={CARD}>
        <EmptyState
          title="Could not load entity profile"
          message="The profile request failed. Try selecting the entity again, or pick another entity from the list." />
      </div>
    );
  }
  if (!profile) {
    return (
      <div style={CARD}>
        <EmptyState
          title="Entity not found"
          message="No profile is available for this entity — it may no longer have recent activity." />
      </div>
    );
  }

  const risk = profile.risk || null;
  const factors: RiskFactor[] = Array.isArray(risk?.factors) ? risk!.factors! : [];
  const recent: RecentAnomaly[] = Array.isArray(profile.recent_anomalies) ? profile.recent_anomalies : [];
  const events = profile.events_summary || null;
  const score = risk ? toNum(risk.risk_score) : null;
  const band = score != null ? riskBand(score) : null;
  const lastActivity = risk?.last_activity || events?.last_seen || null;
  const filter = entityExplorerFilter(entity.type, entity.value);

  return (
    <div>
      {/* Header card */}
      <div style={{ ...CARD, padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '18px 20px', background: 'var(--navy)',
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
              <span style={{ fontSize: 'var(--text-xs)', padding: '1px 7px', borderRadius: 4, fontWeight: 600,
                background: 'rgba(255,255,255,0.12)', color: '#cbd5e1', textTransform: 'uppercase', letterSpacing: '0.3px' }}>
                {typeLabel(entity.type)}
              </span>
              <span style={{ fontSize: 'var(--text-xs)', color: '#94a3b8' }}>
                Last activity {fmtRelative(lastActivity)}
              </span>
            </div>
            <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: '#fff', wordBreak: 'break-all', ...MONO }}>
              {entity.value}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0 }}>
            {/* Big risk score */}
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, lineHeight: 1,
                color: band ? band.fg : '#cbd5e1' }}>
                {score != null ? score : '—'}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: '#94a3b8', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
                {band ? `${band.label} risk` : 'No risk score'}
              </div>
            </div>
            {filter && (
              <button onClick={() => openExplorer(filter)}
                style={{ padding: '8px 16px', borderRadius: 6, border: 'none', cursor: 'pointer',
                  background: 'var(--primary)', color: '#fff', fontSize: 'var(--text-sm)', fontWeight: 600, whiteSpace: 'nowrap' }}>
                View logs →
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Two-up: risk factors + activity trend */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginBottom: 16 }}>
        <div style={{ ...CARD, marginBottom: 0 }}>
          <div style={SECTION_LABEL}>Risk factor breakdown</div>
          {!risk ? (
            <div style={NOTE_BOX}>
              This entity has recent activity but no computed risk score yet — baselines are still learning its normal behavior.
            </div>
          ) : (
            <RiskFactors factors={factors} />
          )}
        </div>
        <div style={{ ...CARD, marginBottom: 0 }}>
          <div style={SECTION_LABEL}>Activity trend · 14 days</div>
          <ActivityTrend trend={trend} loading={trendLoading} />
        </div>
      </div>

      {/* Events summary */}
      <div style={CARD}>
        <div style={SECTION_LABEL}>Events summary</div>
        <EventsSummaryPane summary={events} />
      </div>

      {/* Recent anomalies */}
      <div style={CARD}>
        <div style={SECTION_LABEL}>Recent anomalies ({recent.length})</div>
        <RecentAnomalies anomalies={recent} />
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════
// Main page
// ════════════════════════════════════════════════════════════════════
export default function EntityProfile({ hours, openExplorer }: {
  hours: number;
  openExplorer: (filter: ExplorerFilter) => void;
}) {
  // `hours` is part of the page's shared time-range contract; the entity list
  // and profile are risk-rollup driven (not hour-scoped) so it isn't sent to
  // the UEBA endpoints, but it's referenced here to satisfy the shared prop
  // signature and re-runs the list fetch if the shell changes the range.
  void hours;

  // Master list
  const [rows, setRows] = useState<EntityRow[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState(false);
  const [typeFilter, setTypeFilter] = useState('');
  const [search, setSearch] = useState('');

  // Selection + profile
  const [selected, setSelected] = useState<{ type: string; value: string } | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [trend, setTrend] = useState<Trend | null>(null);
  const [profileLoading, setProfileLoading] = useState(false);
  const [trendLoading, setTrendLoading] = useState(false);
  const [profileError, setProfileError] = useState(false);

  // Fetch the master list on type-filter change.
  useEffect(() => {
    let active = true;
    setListLoading(true);
    setListError(false);
    const params = new URLSearchParams({ limit: '100' });
    if (typeFilter) params.set('type', typeFilter);
    fetch(`/api/ueba/top?${params.toString()}`)
      .then(r => r.json())
      .then(d => { if (active) setRows(Array.isArray(d?.data) ? d.data : []); })
      .catch(() => { if (active) { setRows([]); setListError(true); } })
      .finally(() => { if (active) setListLoading(false); });
    return () => { active = false; };
  }, [typeFilter, hours]);

  // Fetch profile + trend on selection change.
  useEffect(() => {
    if (!selected) { setProfile(null); setTrend(null); return; }
    let active = true;
    setProfileLoading(true);
    setTrendLoading(true);
    setProfileError(false);
    setProfile(null);
    setTrend(null);
    const { type, value } = selected;
    const base = `${encodeURIComponent(type)}/${encodeURIComponent(value)}`;

    fetch(`/api/ueba/entity/${base}`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => { if (active) setProfile(d || null); })
      .catch(() => { if (active) { setProfile(null); setProfileError(true); } })
      .finally(() => { if (active) setProfileLoading(false); });

    fetch(`/api/soc/entity-timeline/${base}?days=14`)
      .then(r => r.json())
      .then(d => { if (active) setTrend(d || null); })
      .catch(() => { if (active) setTrend(null); })
      .finally(() => { if (active) setTrendLoading(false); });

    return () => { active = false; };
  }, [selected]);

  // Client-side search + risk-desc sort.
  const visibleRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows
      .filter(r => !q || String(r.entity_value || '').toLowerCase().includes(q))
      .slice()
      .sort((a, b) => toNum(b.risk_score) - toNum(a.risk_score));
  }, [rows, search]);

  return (
    <div>
      <PageHeader title="Entity Profiles" subtitle="UEBA entity risk explorer — behavior, risk explainability, and anomalies per entity" />

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        {/* ── Master list (left) ── */}
        <div style={{ width: 320, flexShrink: 0, background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 10, overflow: 'hidden', alignSelf: 'stretch' }}>
          {/* Sticky opaque header */}
          <div style={{ position: 'sticky', top: 72, zIndex: 5, background: 'var(--bg-card)',
            borderBottom: '1px solid var(--border)', padding: 12 }}>
            <div style={{ display: 'flex', gap: 3, marginBottom: 10, background: 'var(--bg-primary)',
              border: '1px solid var(--border)', borderRadius: 8, padding: 3, flexWrap: 'wrap' }}>
              {TYPE_TABS.map(t => (
                <button key={t.id} onClick={() => setTypeFilter(t.id)}
                  style={{ flex: 1, minWidth: 60, padding: '5px 8px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontSize: 'var(--text-xs)', fontWeight: typeFilter === t.id ? 700 : 500,
                    background: typeFilter === t.id ? 'var(--primary)' : 'transparent',
                    color: typeFilter === t.id ? '#fff' : 'var(--text-muted)', transition: 'all 0.12s' }}>
                  {t.label}
                </button>
              ))}
            </div>
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search entities…"
              style={{ width: '100%', boxSizing: 'border-box', padding: '7px 10px', borderRadius: 6,
                border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text-primary)',
                fontSize: 'var(--text-sm)' }} />
          </div>

          {/* List body */}
          <div>
            {listLoading ? (
              <TableSkeleton rows={8} cols={2} />
            ) : listError ? (
              <EmptyState title="Could not load entities" message="The entity list request failed. Refresh to retry." />
            ) : visibleRows.length === 0 ? (
              <EmptyState
                title={search ? 'No matching entities' : 'No entities yet'}
                message={search
                  ? 'No entity matches your search. Try a different term or type filter.'
                  : 'No entity risk scores yet — populates as events are scored (within minutes of deploy).'} />
            ) : (
              visibleRows.map((r, i) => {
                const active = !!selected && selected.type === r.entity_type && selected.value === r.entity_value;
                return (
                  <EntityListItem
                    key={`${r.entity_type}:${r.entity_value}:${i}`}
                    row={r}
                    active={active}
                    onSelect={() => setSelected({ type: r.entity_type, value: r.entity_value })} />
                );
              })
            )}
          </div>
        </div>

        {/* ── Profile pane (right) ── */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {!selected ? (
            <div style={CARD}>
              <EmptyState
                title="Select an entity"
                message="Pick a device, user, or source IP from the list to see its risk breakdown, activity trend, and recent anomalies." />
            </div>
          ) : (
            <ProfilePane
              entity={selected}
              profile={profile}
              trend={trend}
              loading={profileLoading}
              trendLoading={trendLoading}
              error={profileError}
              openExplorer={openExplorer} />
          )}
        </div>
      </div>
    </div>
  );
}
