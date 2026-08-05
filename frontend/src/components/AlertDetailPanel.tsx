'use client';
import { useEffect, useState } from 'react';
import { MitreBadges, mitreInfo } from './mitre';
import LogDetailPanel from './LogDetailPanel';
import { sevStyle } from './severity';

// Mirrors the AlertEvent interface from AlertEvents.tsx (kept loose where the
// backend may add fields like acknowledged_by / mitre_techniques on the event).
interface AlertEvent {
  id: number;
  fired_at: string;
  rule_name: string;
  source_host: string;
  source_ip: string;
  match_count: number;
  sample_message: string;
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
  mitre_techniques?: string[] | null;
}

// Shape returned by GET /api/alerts/events/:id/logs → alert sub-object.
interface AlertDetail {
  id: number;
  rule_name?: string;
  fired_at?: string;
  source_host?: string;
  source_ip?: string;
  match_count?: number;
  sample_message?: string;
  acknowledged?: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
  mitre_techniques?: string[] | null;
}

interface Props {
  alert: AlertEvent;
  onClose: () => void;
  onAcknowledge: (id: number) => void;
}

const CORRELATION_NAMES = new Set([
  'Brute Force Login Success', 'Port Scan Detected', 'Interface Flapping Detected',
  'Network Loop Detected', 'After-Hours Configuration Change', 'STP Instability Detected',
  'Repeated IPS Triggers', 'VPN Brute Force Attempt',
]);

// Field row — same styling as LogDetailPanel's Field, with optional copy.
function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '6px 0',
      borderBottom: '1px solid var(--border-light)' }}>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 500,
        minWidth: 110, flexShrink: 0, paddingTop: 1 }}>{label}</span>
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', flex: 1, wordBreak: 'break-all',
        fontFamily: mono ? 'var(--font-mono)' : 'inherit' }}>{value || '—'}</span>
      <button onClick={copy} title="Copy"
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#16a34a' : 'var(--text-muted)',
          fontSize: 'var(--text-xs)', padding: '2px 4px', flexShrink: 0 }}>
        {copied ? '✓' : '⎘'}
      </button>
    </div>
  );
}

export default function AlertDetailPanel({ alert, onClose, onAcknowledge }: Props) {
  const [detail, setDetail]   = useState<AlertDetail | null>(null);
  const [logs, setLogs]       = useState<any[]>([]);
  const [windowMin, setWindowMin] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedLog, setSelectedLog] = useState<any | null>(null);
  // Local ack mirror so the panel updates immediately after acknowledging.
  const [acked, setAcked]     = useState<boolean>(alert.acknowledged);

  // Fetch the alert's full context + the triggering logs on open.
  useEffect(() => {
    if (!alert) return;
    setLoading(true);
    setDetail(null);
    setLogs([]);
    setWindowMin(null);
    fetch(`/api/alerts/events/${alert.id}/logs`)
      .then(r => r.json())
      .then(d => {
        setDetail(d.alert || null);
        setLogs(Array.isArray(d.logs) ? d.logs : []);
        setWindowMin(typeof d.window_minutes === 'number' ? d.window_minutes : null);
        if (d.alert && typeof d.alert.acknowledged === 'boolean') setAcked(d.alert.acknowledged);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [alert?.id]);

  // Keep local ack in sync if the parent prop flips.
  useEffect(() => { setAcked(alert.acknowledged); }, [alert.acknowledged]);

  // Close on Escape (but if a log is open, let that panel close first).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (selectedLog) { setSelectedLog(null); return; }
      onClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose, selectedLog]);

  // Prefer the richer backend detail, fall back to the event we were handed.
  const ruleName     = detail?.rule_name     ?? alert.rule_name;
  const firedAt      = detail?.fired_at      ?? alert.fired_at;
  const sourceHost   = detail?.source_host   ?? alert.source_host;
  const sourceIp     = detail?.source_ip     ?? alert.source_ip;
  const matchCount   = detail?.match_count   ?? alert.match_count;
  const sampleMsg    = detail?.sample_message ?? alert.sample_message;
  const ackedAt      = detail?.acknowledged_at ?? alert.acknowledged_at;
  const ackedBy      = detail?.acknowledged_by ?? alert.acknowledged_by;
  const mitre        = (detail?.mitre_techniques && detail.mitre_techniques.length)
    ? detail.mitre_techniques : (alert.mitre_techniques || null);

  const isCorrelation = CORRELATION_NAMES.has(ruleName);
  const cleanIp       = (sourceIp || '').replace('/32', '');

  // Severity tint derived from the rule name (consistent with AlertEvents grouping).
  const rn = (ruleName || '').toLowerCase();
  const headerTint =
    rn.includes('brute') || rn.includes('loop') || rn.includes('ips') || rn.includes('critical')
      ? { color: 'var(--tint-danger-fg)', bg: 'var(--tint-danger)' }
      : rn.includes('vpn') || rn.includes('error')
        ? { color: 'var(--tint-warn-fg)', bg: 'var(--tint-warn)' }
        : { color: 'var(--tint-info-fg)', bg: 'var(--tint-info)' };

  // source_ip carries the real actor (attacker srcip for security rules, device IP
  // for operational rules); source_host is the reporting/relay device. Show the
  // actor as "Source" and the device separately, so a relayed alert no longer reads
  // as "FGT200E_TUS · <attacker>" (implying the firewall is the actor).
  const sourceDisplay = cleanIp || sourceHost || '—';
  const showReportingDevice = sourceHost && sourceHost !== cleanIp;

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose}
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.3)', zIndex: 200,
          animation: 'fadeIn 0.2s ease' }} />

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
              <span style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#fff' }}>
                {ruleName || 'Alert'}
              </span>
              {isCorrelation && (
                <span style={{ fontSize: 'var(--text-xs)', padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                  background: 'var(--tint-info)', color: 'var(--tint-info-fg)',
                  border: '1px solid var(--tint-info)', fontWeight: 600 }}>CORR</span>
              )}
              <span style={{ padding: '2px 9px', borderRadius: 'var(--radius-pill)', fontSize: 'var(--text-xs)', fontWeight: 700,
                background: headerTint.bg, color: headerTint.color }}>
                {acked ? 'Acknowledged' : 'Active'}
              </span>
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: '#64748b', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
              {firedAt ? new Date(firedAt).toLocaleString() : '—'}
            </div>
            {mitre && mitre.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <MitreBadges ids={mitre} />
              </div>
            )}
            {/* Technique names (not just IDs) */}
            {mitre && mitre.length > 0 && (
              <div style={{ fontSize: 'var(--text-xs)', color: '#94a3b8', marginTop: 6, lineHeight: 1.5 }}>
                {mitre.map(id => mitreInfo(id).name).join(' · ')}
              </div>
            )}
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

          {/* Summary fields */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Summary</div>
            <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius)', padding: '0 12px' }}>
              <Field label="Fired at"   value={firedAt ? new Date(firedAt).toLocaleString() : ''} />
              <Field label="Source"     value={sourceDisplay} mono />
              {showReportingDevice && <Field label="Reporting device" value={sourceHost} mono />}
              <Field label="Match count" value={String(matchCount ?? '—')} />
              <Field label="Window"
                value={windowMin != null ? `${windowMin} min` : '—'} />
              <Field label="Status"     value={acked ? 'Acknowledged' : 'Active'} />
              {acked && ackedBy && <Field label="Acked by" value={ackedBy} mono />}
              {acked && ackedAt && <Field label="Acked at" value={new Date(ackedAt).toLocaleString()} />}
            </div>
          </div>

          {/* Full sample message */}
          {sampleMsg && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Sample Message</div>
              <div style={{ padding: 12, background: 'var(--bg-primary)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius)', fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.6,
                wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                {sampleMsg}
              </div>
            </div>
          )}

          {/* Triggering logs */}
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
              Triggering Logs{!loading ? ` (${logs.length})` : ''}
            </div>
            {loading ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12 }}>Loading...</div>
            ) : logs.length === 0 ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12,
                background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                No matching logs found in the window
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {logs.map((lg, i) => {
                  const sev = sevStyle(lg?.severity_label);
                  return (
                    <div key={lg?.id ?? i} onClick={() => setSelectedLog(lg)}
                      title="Open log detail"
                      style={{ padding: '8px 12px', background: 'var(--bg-primary)', cursor: 'pointer',
                        border: '1px solid var(--border)', borderRadius: 'var(--radius)', transition: 'background 0.12s' }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-subtle)'; }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-primary)'; }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3, flexWrap: 'wrap' }}>
                        {lg?.severity_label && (
                          <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase',
                            padding: '0 6px', borderRadius: 'var(--radius-sm)', color: sev.color, background: sev.bg }}>
                            {lg.severity_label}
                          </span>
                        )}
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)' }}>
                          {lg?.received_at ? new Date(lg.received_at).toLocaleTimeString() : ''}
                        </span>
                        {lg?.category && (
                          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                            {lg.category}
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {lg?.message || '—'}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Actions footer */}
        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          {acked ? (
            <span style={{ fontSize: 'var(--text-sm)', color: '#16a34a', fontWeight: 600 }}>✓ Acknowledged</span>
          ) : (
            <>
              <button onClick={() => { onAcknowledge(alert.id); setAcked(true); }}
                style={{ padding: '8px 16px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                  background: 'var(--primary)', color: '#fff', fontSize: 'var(--text-sm)', fontWeight: 600 }}>
                Acknowledge
              </button>
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                Marks this alert as reviewed.
              </span>
            </>
          )}
        </div>
      </div>

      {/* Drill-in: reuse the existing LogDetailPanel for an underlying log.
          Filter callbacks are no-ops here (this is an alert context, not the
          Log Explorer) — closing just returns to the alert panel. */}
      {selectedLog && (
        <LogDetailPanel
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
          onFilterIP={() => setSelectedLog(null)}
          onFilterVendor={() => setSelectedLog(null)}
          onFilterSeverity={() => setSelectedLog(null)}
        />
      )}

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
      `}</style>
    </>
  );
}
