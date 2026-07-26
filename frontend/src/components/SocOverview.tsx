'use client';

// ════════════════════════════════════════════════════════════════════════════
// SocOverview — Phase 4 SOC single-pane security overview.
//
// A read-only "exec briefing" view that stitches together the deterministic
// narrative digest (GET /api/soc/digest) and the numeric overview snapshot
// (GET /api/soc/overview) into one screen: a narrative panel, a KPI row, a
// severity chart, top countries, riskiest entities, a security-signals grid and
// the active-incident list. Clicking an incident opens the KillChainTimeline
// modal. All widgets follow the suite design tokens (dark-mode safe) and reuse
// the shared primitives; every helper/subcomponent lives at module scope.
// ════════════════════════════════════════════════════════════════════════════

import { useCallback, useEffect, useState } from 'react';
import { PageHeader, CardSkeleton, EmptyState } from './ui';
import TimeRangePicker from './TimeRangePicker';
import SeverityChart from './SeverityChart';
import { RiskBadge } from './palette';
import { MitreBadges } from './mitre';
import { countryFlag, GLOBE } from './ThreatIntel';
import { TopSecurityEvents } from './DashboardWidgets';
import { KillChainTimeline } from './KillChainTimeline';
// `import type` is erased at build time, so this does NOT create a runtime
// circular import even though page.tsx imports this module (mirrors LogExplorer /
// DashboardWidgets, which import the same type the same way).
import type { ExplorerFilter } from '@/app/page';

// ── Shared card style (matches DashboardWidgets/SeverityChart) ────────────────
const CARD = {
  background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
  padding: '16px 20px', boxShadow: 'var(--shadow-sm)',
} as const;
const TITLE = { fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 } as const;
const SUB   = { fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 } as const;

// ── Digest section severity → adaptive tint tokens ────────────────────────────
type DigestSev = 'critical' | 'warning' | 'info' | 'ok';
const DIGEST_TINT: Record<DigestSev, { bg: string; fg: string }> = {
  critical: { bg: 'var(--tint-danger)',  fg: 'var(--tint-danger-fg)' },
  warning:  { bg: 'var(--tint-warn)',    fg: 'var(--tint-warn-fg)' },
  info:     { bg: 'var(--tint-info)',    fg: 'var(--tint-info-fg)' },
  ok:       { bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)' },
};
function digestTint(sev: string): { bg: string; fg: string } {
  return DIGEST_TINT[(sev as DigestSev)] || DIGEST_TINT.info;
}

// ── Response shapes ───────────────────────────────────────────────────────────
interface DigestSection { id: string; title: string; severity: string; sentences: string[]; }
interface DigestData {
  hours: number; generated_at: string; headline: string; sections: DigestSection[];
}
interface SevRow { severity: number | string; severity_label: string; log_count: number | string; }
interface OverviewTotals {
  logs: number; alerts_unacked: number; alerts_24h: number;
  anomalies_unacked: number; anomalies_24h: number; known_bad_active: number;
}
interface TopEntity {
  entity_type: string; entity_value: string; risk_score: number;
  anomaly_count: number; event_count: number;
}
interface TopCountry { country: string; country_code: string; count: number; prev_count: number; }
interface ActiveIncident {
  id: number; rule_id: number; rule_name: string; techniques: string[];
  source_host: string; source_ip: string; match_count: number;
  fired_at: string; acknowledged: boolean;
}
interface SecuritySignals {
  auth_fail: number; deny: number; vpn: number; ips: number;
  after_hours: number; brute_force: number;
}
interface OverviewData {
  hours: number; generated_at: string; severity: SevRow[]; totals: OverviewTotals;
  top_entities: TopEntity[]; top_countries: TopCountry[];
  active_incidents: ActiveIncident[]; security: SecuritySignals;
}

// ── Number/time helpers ───────────────────────────────────────────────────────
function num(v: unknown): number {
  const n = typeof v === 'string' ? parseInt(v, 10) : (v as number);
  return typeof n === 'number' && !isNaN(n) ? n : 0;
}
function fmt(v: unknown): string { return num(v).toLocaleString(); }
function fmtRelative(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (isNaN(t)) return '—';
  const diff = Date.now() - t;
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Inline error strip ────────────────────────────────────────────────────────
function ErrorStrip({ message }: { message: string }) {
  return (
    <div style={{ ...CARD, borderColor: 'var(--tint-danger)', background: 'var(--tint-danger)',
      color: 'var(--tint-danger-fg)', fontSize: 'var(--text-sm)', fontWeight: 600 }}>
      {message}
    </div>
  );
}

// ── Narrative digest panel ────────────────────────────────────────────────────
function DigestSectionRow({ section }: { section: DigestSection }) {
  const tint = digestTint(section.severity);
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'stretch' }}>
      <div style={{ width: 4, borderRadius: 3, background: tint.fg, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0, background: tint.bg, borderRadius: 8, padding: '10px 12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: tint.fg, flexShrink: 0 }} />
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--text-primary)',
            textTransform: 'uppercase', letterSpacing: '0.4px' }}>{section.title}</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {(section.sentences || []).map((s, i) => (
            <span key={i} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {s}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function DigestPanel({ digest, loading, error }:
  { digest: DigestData | null; loading: boolean; error: boolean }) {
  return (
    <div style={{ ...CARD, background: 'var(--bg-card)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--tint-info-fg)',
          background: 'var(--tint-info)', borderRadius: 4, padding: '2px 8px',
          textTransform: 'uppercase', letterSpacing: '0.5px' }}>Briefing</span>
        {digest?.generated_at && (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            generated {fmtRelative(digest.generated_at)}
          </span>
        )}
      </div>
      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div className="skeleton" style={{ height: 24, width: '70%', borderRadius: 6 }} />
          <div className="skeleton" style={{ height: 44, width: '100%', borderRadius: 8 }} />
          <div className="skeleton" style={{ height: 44, width: '100%', borderRadius: 8 }} />
        </div>
      ) : error ? (
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--tint-danger-fg)' }}>
          Could not load the security briefing.
        </div>
      ) : !digest ? (
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>No briefing available.</div>
      ) : (
        <>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)',
            lineHeight: 1.4, marginBottom: (digest.sections?.length ? 14 : 0) }}>
            {digest.headline}
          </div>
          {digest.sections?.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {digest.sections.map(s => <DigestSectionRow key={s.id} section={s} />)}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── KPI tile ──────────────────────────────────────────────────────────────────
function KpiTile({ label, value, tone, onClick, hint }:
  { label: string; value: number; tone: 'neutral' | 'danger' | 'warn'; onClick?: () => void; hint?: string }) {
  const active = tone !== 'neutral' && value > 0;
  const bg = active ? (tone === 'danger' ? 'var(--tint-danger)' : 'var(--tint-warn)') : 'var(--bg-primary)';
  const fg = active ? (tone === 'danger' ? 'var(--tint-danger-fg)' : 'var(--tint-warn-fg)') : 'var(--text-primary)';
  const border = active ? (tone === 'danger' ? 'var(--tint-danger)' : 'var(--tint-warn)') : 'var(--border)';
  return (
    <div onClick={onClick} title={hint}
      style={{ background: bg, border: `1px solid ${border}`, borderRadius: 10, padding: '14px 16px',
        cursor: onClick ? 'pointer' : 'default', transition: 'box-shadow 0.15s' }}
      onMouseEnter={e => { if (onClick) (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: fg, lineHeight: 1.1 }}>
        {value.toLocaleString()}
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.3px', marginTop: 4 }}>{label}</div>
    </div>
  );
}

// ── Top Countries ─────────────────────────────────────────────────────────────
function CountryDelta({ delta }: { delta: number }) {
  if (delta === 0) return <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>→ 0</span>;
  const up = delta > 0;
  // More activity from a country reads as "up/worse" (red), less as "down/better" (green).
  const color = up ? 'var(--tint-danger-fg)' : 'var(--tint-success-fg)';
  return (
    <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color }}>
      {up ? '↑' : '↓'} {Math.abs(delta).toLocaleString()}
    </span>
  );
}

function TopCountriesCard({ rows, onDrill }:
  { rows: TopCountry[]; onDrill?: (row: TopCountry) => void }) {
  return (
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={TITLE}>Top Countries</div>
      <div style={SUB}>Source countries by event volume · vs previous window</div>
      {rows.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>No country data</div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 4, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {rows.map((r, i) => {
            const flag = countryFlag(r.country_code) || GLOBE;
            const delta = num(r.count) - num(r.prev_count);
            return (
              <div key={r.country_code || i} onClick={() => onDrill?.(r)}
                title={`${r.country || r.country_code} — ${fmt(r.count)} events`}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                  padding: '6px 8px', background: 'var(--surface-subtle)', borderRadius: 6,
                  cursor: onDrill ? 'pointer' : 'default' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                  <span style={{ flexShrink: 0 }}>{flag}</span>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 500,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.country || r.country_code || '—'}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
                  <CountryDelta delta={delta} />
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--text-primary)',
                    minWidth: 44, textAlign: 'right' }}>{fmt(r.count)}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Security signals mini-grid ────────────────────────────────────────────────
interface SignalDef { key: keyof SecuritySignals; label: string; bg: string; fg: string; filter?: ExplorerFilter; }
const SIGNALS: SignalDef[] = [
  { key: 'auth_fail',   label: 'Auth Failures', bg: 'var(--tint-warn)',   fg: 'var(--tint-warn-fg)',   filter: { category: 'authentication' } },
  { key: 'deny',        label: 'Denied',        bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', filter: { category: 'firewall' } },
  { key: 'vpn',         label: 'VPN',           bg: 'var(--tint-info)',   fg: 'var(--tint-info-fg)',   filter: { category: 'vpn' } },
  { key: 'ips',         label: 'IPS/IDS',       bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', filter: { category: 'security' } },
  { key: 'after_hours', label: 'After-Hours',   bg: 'var(--tint-purple)', fg: 'var(--tint-purple-fg)' },
  { key: 'brute_force', label: 'Brute Force',   bg: 'var(--tint-purple)', fg: 'var(--tint-purple-fg)', filter: { technique: 'T1110' } },
];

function SecuritySignalsCard({ signals, openExplorer }:
  { signals: SecuritySignals | null; openExplorer: (f: ExplorerFilter) => void }) {
  return (
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box' }}>
      <div style={TITLE}>Security Signals</div>
      <div style={SUB}>Key security counts in this window · Click to investigate</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
        {SIGNALS.map(sig => {
          const value = num(signals?.[sig.key]);
          const clickable = !!sig.filter;
          return (
            <div key={sig.key}
              onClick={() => { if (sig.filter) openExplorer(sig.filter); }}
              title={clickable ? `${sig.label} — click to investigate` : sig.label}
              style={{ background: sig.bg, borderRadius: 8, padding: '10px 8px', textAlign: 'center',
                cursor: clickable ? 'pointer' : 'default' }}>
              <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: sig.fg }}>{value.toLocaleString()}</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600, marginTop: 2 }}>
                {sig.label}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Riskiest entities (from overview.top_entities) ───────────────────────────
function RiskiestEntitiesCard({ rows, openExplorer }:
  { rows: TopEntity[]; openExplorer: (f: ExplorerFilter) => void }) {
  const drill = (row: TopEntity) => {
    const value = row.entity_value;
    if (!value) return;
    const type = (row.entity_type || '').toLowerCase();
    if (type === 'device' || type === 'srcip' || type === 'host') openExplorer({ host: value });
    else openExplorer({ q: value });
  };
  return (
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={TITLE}>Riskiest Entities</div>
      <div style={SUB}>Highest behavioural risk in this window · Click an entity to investigate</div>
      {rows.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 'var(--text-sm)', textAlign: 'center', padding: '0 12px' }}>
          No entity risk in this window.
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 4, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {rows.map((row, i) => {
            const score = num(row.risk_score);
            const value = row.entity_value || '—';
            const type = row.entity_type || 'entity';
            const events = num(row.event_count);
            const anomalies = num(row.anomaly_count);
            return (
              <div key={`${value}-${i}`} onClick={() => drill(row)}
                title={`${type}: ${value} — risk ${score} · ${events.toLocaleString()} events · ${anomalies.toLocaleString()} anomalies`}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                  padding: '7px 8px', background: 'var(--surface-subtle)', borderRadius: 6,
                  cursor: row.entity_value ? 'pointer' : 'default' }}>
                <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 600,
                    fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {value}
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    <span style={{ textTransform: 'capitalize' }}>{type}</span> · {events.toLocaleString()} events · {anomalies.toLocaleString()} anomalies
                  </span>
                </div>
                <RiskBadge score={score} />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Active incident row ───────────────────────────────────────────────────────
function IncidentRow({ incident, onOpen }: { incident: ActiveIncident; onOpen: (id: number) => void }) {
  const sourceDisplay = (incident.source_ip || '').replace('/32', '') || incident.source_host || '—';
  const showDevice = incident.source_host && incident.source_host !== sourceDisplay;
  const acked = incident.acknowledged;
  return (
    <div onClick={() => onOpen(incident.id)}
      title="Open kill-chain timeline"
      style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px',
        background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8,
        cursor: 'pointer', transition: 'background 0.12s' }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-primary)'; }}>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--text-primary)' }}>
            {incident.rule_name || 'Incident'}
          </span>
          <span style={{ padding: '1px 8px', borderRadius: 12, fontSize: 'var(--text-xs)', fontWeight: 700,
            background: acked ? 'var(--tint-success)' : 'var(--tint-danger)',
            color: acked ? 'var(--tint-success-fg)' : 'var(--tint-danger-fg)' }}>
            {acked ? 'Acknowledged' : 'Active'}
          </span>
          <MitreBadges ids={incident.techniques} compact />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
            {sourceDisplay}
          </span>
          {showDevice && (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              via {incident.source_host}
            </span>
          )}
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            {fmt(incident.match_count)} matches
          </span>
        </div>
      </div>
      <div style={{ flexShrink: 0, textAlign: 'right' }}>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{fmtRelative(incident.fired_at)}</div>
        <svg width="14" height="14" viewBox="0 0 12 12" fill="none" style={{ marginTop: 4 }}>
          <polyline points="4,2 8,6 4,10" stroke="var(--text-muted)" strokeWidth="1.2"
            strokeLinecap="round" strokeLinejoin="round" fill="none" />
        </svg>
      </div>
    </div>
  );
}

function ActiveIncidentsCard({ incidents, onOpen }:
  { incidents: ActiveIncident[]; onOpen: (id: number) => void }) {
  return (
    <div style={CARD}>
      <div style={TITLE}>Active Incidents</div>
      <div style={SUB}>Correlated multi-event incidents in this window · Click for the kill-chain</div>
      {incidents.length === 0 ? (
        <EmptyState
          title="No active incidents in this window"
          message="Correlated incidents will appear here as alert rules fire."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {incidents.map(inc => <IncidentRow key={inc.id} incident={inc} onOpen={onOpen} />)}
        </div>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Main component
// ════════════════════════════════════════════════════════════════════════════
export default function SocOverview({ hours, openExplorer, openAlerts }: {
  hours: number;
  openExplorer: (filter: ExplorerFilter) => void;
  openAlerts?: (technique?: string) => void;
}) {
  // SOC view keeps its own time-range state (seeded from the global range).
  const [localHours, setLocalHours] = useState<number>(hours);
  const [refreshInterval, setRefreshInterval] = useState<number>(60);
  const [tick, setTick] = useState(0);

  const [digest, setDigest] = useState<DigestData | null>(null);
  const [digestLoading, setDigestLoading] = useState(true);
  const [digestError, setDigestError] = useState(false);

  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [ovLoading, setOvLoading] = useState(true);
  const [ovError, setOvError] = useState(false);

  const [openIncidentId, setOpenIncidentId] = useState<number | null>(null);

  // Follow the global range when the parent changes it.
  useEffect(() => { setLocalHours(hours); }, [hours]);

  const refreshNow = useCallback(() => setTick(t => t + 1), []);

  // Narrative digest.
  useEffect(() => {
    let active = true;
    setDigestLoading(true);
    setDigestError(false);
    fetch(`/api/soc/digest?hours=${localHours}`)
      .then(r => { if (!r.ok) throw new Error('digest'); return r.json(); })
      .then(d => { if (active) { setDigest(d || null); setDigestLoading(false); } })
      .catch(() => { if (active) { setDigestError(true); setDigestLoading(false); } });
    return () => { active = false; };
  }, [localHours, tick]);

  // Numeric overview snapshot.
  useEffect(() => {
    let active = true;
    setOvLoading(true);
    setOvError(false);
    fetch(`/api/soc/overview?hours=${localHours}`)
      .then(r => { if (!r.ok) throw new Error('overview'); return r.json(); })
      .then(d => { if (active) { setOverview(d || null); setOvLoading(false); } })
      .catch(() => { if (active) { setOvError(true); setOvLoading(false); } });
    return () => { active = false; };
  }, [localHours, tick]);

  const totals = overview?.totals;
  const severity = Array.isArray(overview?.severity) ? overview!.severity : [];
  const topEntities = Array.isArray(overview?.top_entities) ? overview!.top_entities : [];
  const topCountries = Array.isArray(overview?.top_countries) ? overview!.top_countries : [];
  const incidents = Array.isArray(overview?.active_incidents) ? overview!.active_incidents : [];

  return (
    <div>
      <PageHeader title="Security Overview"
        subtitle="Single-pane SOC briefing — narrative digest, key signals and active incidents">
        <TimeRangePicker
          hours={localHours}
          onHoursChange={setLocalHours}
          refreshInterval={refreshInterval}
          onRefreshChange={setRefreshInterval}
          onRefreshNow={refreshNow}
        />
      </PageHeader>

      {/* 1 — Narrative digest */}
      <div style={{ marginBottom: 16 }}>
        <DigestPanel digest={digest} loading={digestLoading} error={digestError} />
      </div>

      {/* 2 — KPI row */}
      {ovError && (
        <div style={{ marginBottom: 16 }}>
          <ErrorStrip message="Could not load the security overview snapshot." />
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 16 }}>
        {ovLoading ? (
          <CardSkeleton count={4} height={72} />
        ) : (
          <>
            <KpiTile label="Logs" value={num(totals?.logs)} tone="neutral" hint="Total log entries in this window" />
            <KpiTile label="Unacked Alerts" value={num(totals?.alerts_unacked)} tone="danger"
              onClick={openAlerts ? () => openAlerts() : undefined}
              hint="Unacknowledged alerts — click to open the Alerts tab" />
            <KpiTile label="Unacked Anomalies" value={num(totals?.anomalies_unacked)} tone="warn"
              hint="Unacknowledged UEBA anomalies" />
            <KpiTile label="Known-Bad Active" value={num(totals?.known_bad_active)} tone="danger"
              hint="Active known-bad external sources" />
          </>
        )}
      </div>

      {/* 3 — Severity / Countries / Signals */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16, marginBottom: 16 }}>
        <div style={{ minHeight: 220 }}>
          {ovLoading ? <CardSkeleton count={1} height={220} /> : <SeverityChart summary={severity} />}
        </div>
        {ovLoading ? <CardSkeleton count={1} height={220} /> : (
          <TopCountriesCard rows={topCountries}
            onDrill={(r) => openExplorer({ q: r.country || r.country_code })} />
        )}
        {ovLoading ? <CardSkeleton count={1} height={220} /> : (
          <SecuritySignalsCard signals={overview?.security ?? null} openExplorer={openExplorer} />
        )}
      </div>

      {/* 4 — Riskiest entities / Top security events */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginBottom: 16 }}>
        {ovLoading ? <CardSkeleton count={1} height={240} /> : (
          <RiskiestEntitiesCard rows={topEntities} openExplorer={openExplorer} />
        )}
        <TopSecurityEvents hours={localHours} onNavigate={() => openExplorer({ category: 'security' })} />
      </div>

      {/* 5 — Active incidents */}
      {ovLoading ? (
        <CardSkeleton count={1} height={160} />
      ) : (
        <ActiveIncidentsCard incidents={incidents} onOpen={setOpenIncidentId} />
      )}

      {/* Kill-chain modal */}
      {openIncidentId != null && (
        <KillChainTimeline alertId={openIncidentId} onClose={() => setOpenIncidentId(null)} />
      )}
    </div>
  );
}
