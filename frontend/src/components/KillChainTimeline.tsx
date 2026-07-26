'use client';

// ════════════════════════════════════════════════════════════════════════════
// KillChainTimeline — modal overlay that reconstructs an incident's MITRE
// ATT&CK kill chain from its underlying events.
//
// Fetches GET /api/soc/killchain/<alertId>, maps each event's technique(s) to
// their ATT&CK tactic(s) (via mitre.tsx), buckets the events into tactic phases
// ordered by MITRE_TACTIC_ORDER, and renders them as an ordered vertical
// sequence. Dismissable via backdrop click, an X button, or Esc. Surface uses
// var(--bg-card) over a semi-transparent overlay, dark-mode safe.
//
// Every helper/subcomponent is declared at module scope (never nested).
// ════════════════════════════════════════════════════════════════════════════

import { useEffect, useState } from 'react';
import { MITRE_TACTIC_ORDER, mitreInfo, MitreBadges } from './mitre';
import { SevBadge, sevLabel } from './severity';
import { useEscape } from './ui';

// ── Response shapes ───────────────────────────────────────────────────────────
interface KillChainAlert {
  id: number; rule_id: number; rule_name: string; description: string;
  techniques: string[]; source_host: string; source_ip: string;
  match_count: number; sample_message: string; fired_at: string; acknowledged: boolean;
}
interface KillChainEvent {
  ts: string; severity: number | string; severity_label: string;
  source_host: string; srcip: string; category: string;
  message: string; techniques: string[];
}
interface KillChainData {
  alert: KillChainAlert; events: KillChainEvent[]; events_total: number;
}

// A resolved tactic phase: the tactic name, the union of techniques seen in it,
// and its events in chronological order.
interface Phase { tactic: string; techniques: string[]; events: KillChainEvent[]; }

const ACTIVITY_LANE = 'Activity';

// ── Helpers ───────────────────────────────────────────────────────────────────
function eventTime(iso?: string | null): number {
  const t = iso ? new Date(iso).getTime() : NaN;
  return isNaN(t) ? 0 : t;
}
function fmtTime(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

// Map a list of technique IDs → the set of resolvable tactics they belong to
// (skipping the 'Other' catch-all mitreInfo returns for unknown IDs), keyed by
// tactic with the contributing technique IDs collected per tactic.
function tacticsForTechniques(ids: string[] | null | undefined): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  if (!Array.isArray(ids)) return out;
  for (const id of ids) {
    const tactic = mitreInfo(id).tactic;
    if (!tactic || tactic === 'Other') continue;
    if (!out.has(tactic)) out.set(tactic, new Set());
    out.get(tactic)!.add(id);
  }
  return out;
}

// Build the ordered phases from the incident's events. Technique→tactic mapping
// rules (per the task spec):
//   1. An event maps to the tactic(s) of its own techniques[].
//   2. If none of the event's techniques resolve (or it has no techniques),
//      fall back to the tactic(s) of the ALERT's own techniques.
//   3. If that still resolves to nothing, bucket the event under an "Activity" lane.
// An event may appear under more than one tactic when its techniques span tactics.
function buildPhases(alert: KillChainAlert, events: KillChainEvent[]): Phase[] {
  const map = new Map<string, { techniques: Set<string>; events: KillChainEvent[] }>();
  const ensure = (tactic: string) => {
    if (!map.has(tactic)) map.set(tactic, { techniques: new Set(), events: [] });
    return map.get(tactic)!;
  };
  const alertTactics = tacticsForTechniques(alert?.techniques);

  for (const ev of events) {
    let tactics = tacticsForTechniques(ev.techniques);
    if (tactics.size === 0) tactics = alertTactics; // fall back to alert techniques
    if (tactics.size === 0) {
      ensure(ACTIVITY_LANE).events.push(ev);
      continue;
    }
    for (const [tactic, techIds] of tactics) {
      const p = ensure(tactic);
      techIds.forEach(t => p.techniques.add(t));
      p.events.push(ev);
    }
  }

  // Order by the ATT&CK kill-chain order; unknown tactics (only "Activity"
  // in practice) sink to the end. Sort each phase's events chronologically.
  const ordered: Phase[] = [];
  const pushPhase = (tactic: string) => {
    const bucket = map.get(tactic);
    if (!bucket) return;
    ordered.push({
      tactic,
      techniques: Array.from(bucket.techniques),
      events: bucket.events.slice().sort((a, b) => eventTime(a.ts) - eventTime(b.ts)),
    });
    map.delete(tactic);
  };
  for (const tactic of MITRE_TACTIC_ORDER) pushPhase(tactic);
  // Any remaining (Activity or unexpected tactics) preserve insertion order.
  for (const tactic of Array.from(map.keys())) pushPhase(tactic);
  return ordered;
}

// ── Event line ────────────────────────────────────────────────────────────────
function EventLine({ ev }: { ev: KillChainEvent }) {
  const source = (ev.srcip || '').replace('/32', '') || ev.source_host || '—';
  return (
    <div style={{ display: 'flex', gap: 10, padding: '8px 10px', background: 'var(--bg-primary)',
      border: '1px solid var(--border)', borderRadius: 8 }}>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
        whiteSpace: 'nowrap', flexShrink: 0, paddingTop: 1, minWidth: 66 }}>
        {ev.ts ? new Date(ev.ts).toLocaleTimeString() : '—'}
      </span>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3, flexWrap: 'wrap' }}>
          <SevBadge label={ev.severity_label || sevLabel(ev.severity)} />
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
            {source}
          </span>
          {ev.category && (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{ev.category}</span>
          )}
        </div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', lineHeight: 1.5,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          title={ev.message}>
          {ev.message || '—'}
        </div>
      </div>
    </div>
  );
}

// ── Phase (one tactic lane) ─────────────────────────────────────────────────────
function PhaseBlock({ phase, index, isLast }: { phase: Phase; index: number; isLast: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 14 }}>
      {/* Rail: numbered node + connector line */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
        <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--tint-purple)',
          color: 'var(--tint-purple-fg)', border: '1px solid var(--tint-purple-fg)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 'var(--text-sm)', fontWeight: 700 }}>
          {index + 1}
        </div>
        {!isLast && <div style={{ flex: 1, width: 2, background: 'var(--border)', marginTop: 4, minHeight: 12 }} />}
      </div>

      {/* Phase content */}
      <div style={{ flex: 1, minWidth: 0, paddingBottom: isLast ? 0 : 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <span style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--text-primary)' }}>
            {phase.tactic}
          </span>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            {phase.events.length} {phase.events.length === 1 ? 'event' : 'events'}
          </span>
          <MitreBadges ids={phase.techniques} compact />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {phase.events.map((ev, i) => <EventLine key={`${ev.ts}-${i}`} ev={ev} />)}
        </div>
      </div>
    </div>
  );
}

// ── Modal ───────────────────────────────────────────────────────────────────────
export function KillChainTimeline({ alertId, onClose }: { alertId: number; onClose: () => void }) {
  const [data, setData] = useState<KillChainData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEscape(onClose);

  // Lock body scroll while the modal is open.
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(false);
    fetch(`/api/soc/killchain/${alertId}`)
      .then(r => { if (!r.ok) throw new Error('killchain'); return r.json(); })
      .then(d => { if (active) { setData(d || null); setLoading(false); } })
      .catch(() => { if (active) { setError(true); setLoading(false); } });
    return () => { active = false; };
  }, [alertId]);

  const alert = data?.alert;
  const events = Array.isArray(data?.events) ? data!.events : [];
  const phases = alert ? buildPhases(alert, events) : [];
  const sourceDisplay = alert
    ? ((alert.source_ip || '').replace('/32', '') || alert.source_host || '—')
    : '—';
  const showDevice = !!alert && alert.source_host && alert.source_host !== sourceDisplay;

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose}
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)', zIndex: 300,
          animation: 'fadeIn 0.18s ease' }} />

      {/* Surface */}
      <div role="dialog" aria-modal="true"
        style={{ position: 'fixed', top: '4vh', left: '50%', transform: 'translateX(-50%)',
          width: 'min(860px, 94vw)', maxHeight: '92vh', background: 'var(--bg-card)',
          border: '1px solid var(--border)', borderRadius: 12, boxShadow: '0 12px 40px rgba(0,0,0,0.28)',
          zIndex: 301, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', background: '#1a2744',
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexShrink: 0 }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#cbd5e1',
                textTransform: 'uppercase', letterSpacing: '0.5px' }}>Kill Chain</span>
              <span style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#fff' }}>
                {alert?.rule_name || (loading ? 'Loading incident…' : 'Incident')}
              </span>
              {alert && (
                <span style={{ padding: '2px 9px', borderRadius: 16, fontSize: 'var(--text-xs)', fontWeight: 700,
                  background: alert.acknowledged ? 'var(--tint-success)' : 'var(--tint-danger)',
                  color: alert.acknowledged ? 'var(--tint-success-fg)' : 'var(--tint-danger-fg)' }}>
                  {alert.acknowledged ? 'Acknowledged' : 'Active'}
                </span>
              )}
            </div>
            {alert && (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginTop: 6 }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: '#cbd5e1', fontFamily: 'var(--font-mono)' }}>
                    {sourceDisplay}
                  </span>
                  {showDevice && (
                    <span style={{ fontSize: 'var(--text-xs)', color: '#94a3b8' }}>via {alert.source_host}</span>
                  )}
                  <span style={{ fontSize: 'var(--text-xs)', color: '#94a3b8' }}>
                    {Number(alert.match_count || 0).toLocaleString()} matches
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                    {fmtTime(alert.fired_at)}
                  </span>
                </div>
                {alert.techniques?.length > 0 && (
                  <div style={{ marginTop: 8 }}><MitreBadges ids={alert.techniques} /></div>
                )}
              </>
            )}
          </div>
          <button onClick={onClose} aria-label="Close"
            style={{ background: 'rgba(255,255,255,0.1)', border: 'none', cursor: 'pointer',
              color: '#94a3b8', fontSize: 'var(--text-lg)', width: 28, height: 28, borderRadius: 6,
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            ×
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {loading ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12 }}>Loading kill chain…</div>
          ) : error ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--tint-danger-fg)',
              background: 'var(--tint-danger)', border: '1px solid var(--tint-danger)',
              borderRadius: 8, padding: 12 }}>
              Could not load this incident&apos;s kill chain.
            </div>
          ) : (
            <>
              {/* Sample message */}
              {alert?.sample_message && (
                <div style={{ marginBottom: 20 }}>
                  <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                    textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Sample Message</div>
                  <div style={{ padding: 12, background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    borderRadius: 8, fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.6,
                    wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    {alert.sample_message}
                  </div>
                </div>
              )}

              {/* Description */}
              {alert?.description && (
                <div style={{ marginBottom: 20, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {alert.description}
                </div>
              )}

              {/* Timeline */}
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 14 }}>
                Kill-Chain Timeline{typeof data?.events_total === 'number' ? ` · ${data.events_total.toLocaleString()} events` : ''}
              </div>

              {phases.length === 0 ? (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 14,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8, textAlign: 'center' }}>
                  No underlying events retained for this incident&apos;s window.
                  {alert?.techniques?.length ? (
                    <div style={{ marginTop: 10, display: 'flex', justifyContent: 'center' }}>
                      <MitreBadges ids={alert.techniques} />
                    </div>
                  ) : null}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  {phases.map((phase, i) => (
                    <PhaseBlock key={phase.tactic} phase={phase} index={i} isLast={i === phases.length - 1} />
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
