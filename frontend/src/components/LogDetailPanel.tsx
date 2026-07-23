'use client';
import { useEffect, useState } from 'react';
import { MitreBadges } from './mitre';
import { sevStyle } from './severity';
import { riskBand } from './palette';

interface LogRow {
  id:              number;
  received_at:     string;
  log_timestamp:   string;
  source_ip:       string;
  source_host:     string;
  severity_label:  string;
  severity:        number;
  facility_label:  string;
  vendor:          string;
  program:         string;
  message:         string;
  structured_data: Record<string, any>;
  is_parsed:       boolean;
  category:        string;
  risk_score:      number;
}

interface Props {
  log:          LogRow | null;
  onClose:      () => void;
  onFilterIP:   (ip: string) => void;
  onFilterVendor: (vendor: string) => void;
  onFilterSeverity: (severity: string) => void;
}

interface RiskFactor { label: string; points: number; }

// Parse structured_data.risk_factors (CONTRACT: array of { label, points },
// already sorted desc by the collector). Guards every field; returns [] when
// absent or malformed (older logs simply get no breakdown).
function parseRiskFactors(sd: Record<string, any>): RiskFactor[] {
  const raw = sd?.risk_factors;
  if (!Array.isArray(raw)) return [];
  return raw
    .map((f: any) => ({ label: String(f?.label ?? ''), points: Number(f?.points) || 0 }))
    .filter(f => f.label !== '' && f.points > 0);
}

function RiskFactorBreakdown({ factors, score }: { factors: RiskFactor[]; score: number }) {
  const [open, setOpen] = useState(false);
  if (factors.length === 0) return null;

  const max = Math.max(...factors.map(f => f.points), 1);
  const top = factors.slice(0, 2).map(f => f.label);
  const summary = top.length === 1
    ? `Driven mainly by ${top[0]}.`
    : `Driven mainly by ${top[0]} and ${top[1]}.`;

  return (
    <div style={{ marginBottom: 20 }}>
      <button onClick={() => setOpen(o => !o)}
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%',
          background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginBottom: 8 }}>
        <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
          textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Why This Score? · {score}/100
        </span>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {open ? '▾ Hide' : `▸ ${factors.length} factor${factors.length === 1 ? '' : 's'}`}
        </span>
      </button>
      <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '10px 12px' }}>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.5,
          marginBottom: open ? 10 : 0 }}>
          {summary}
        </div>
        {open && factors.map((f, i) => (
          <div key={i} style={{ padding: '6px 0', borderTop: '1px solid var(--border-light)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', wordBreak: 'break-word' }}>
                {f.label}
              </span>
              <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--tint-warn-fg)',
                flexShrink: 0 }}>
                +{f.points}
              </span>
            </div>
            <div style={{ marginTop: 4, height: 4, borderRadius: 2, background: 'var(--surface-subtle)',
              overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${Math.round((f.points / max) * 100)}%`,
                background: 'var(--primary)', borderRadius: 2 }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

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

export default function LogDetailPanel({ log, onClose, onFilterIP, onFilterVendor, onFilterSeverity }: Props) {
  const [related, setRelated]   = useState<LogRow[]>([]);
  const [loadingRel, setLoadingRel] = useState(false);

  // Fetch related logs when panel opens
  useEffect(() => {
    if (!log) { setRelated([]); return; }
    setLoadingRel(true);
    const ip = log.source_ip?.replace('/32', '');
    fetch(`/api/logs?hours=0.083&host=${encodeURIComponent(ip)}&limit=6`)
      .then(r => r.json())
      .then(d => {
        // Exclude the current log
        setRelated((d.data || []).filter((r: LogRow) => r.id !== log.id).slice(0, 5));
      })
      .catch(() => {})
      .finally(() => setLoadingRel(false));
  }, [log?.id]);

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!log) return null;

  const sevSt     = sevStyle(log.severity_label);
  const risk      = riskBand(log.risk_score || 0);
  const cleanIP   = log.source_ip?.replace('/32', '');
  const sdEntries = log.structured_data
    ? Object.entries(log.structured_data).filter(([k, v]) => v !== null && v !== '' && k !== 'risk_factors')
    : [];
  const riskFactors = parseRiskFactors(log.structured_data || {});

  // For auth/vpn events the syslog sender is the firewall; the real source is the remote
  // client (remip / structured_data.srcip). Surface it prominently when present and it
  // differs from the device's own IP — otherwise this block is hidden (behaviour unchanged).
  const sd          = log.structured_data || {};
  const isAuthVpn   = log.category === 'authentication' || log.category === 'vpn';
  const remoteIP    = isAuthVpn ? String(sd.remip || sd.srcip || '').replace('/32', '') : '';
  const remoteUser  = isAuthVpn ? (sd.user || '') : '';
  const remoteCty   = isAuthVpn ? (sd.srccountry || '') : '';
  const showRemote  = Boolean(remoteIP && remoteIP !== cleanIP);
  // Many VPN events are pre-auth probes: the firewall reports a remote IP/country but
  // user is missing, empty, or the literal 'N/A' (no credentials submitted yet).
  const hasRealUser = Boolean(remoteUser) && String(remoteUser).trim().toLowerCase() !== 'n/a';

  const SEVERITIES: Record<number, string> = { 0: '0,1,2', 1: '0,1,2', 2: '0,1,2', 3: '3', 4: '4', 5: '5', 6: '6' };

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
          background: '#1a2744', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#fff' }}>
              {log.source_host || cleanIP}
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: '#64748b', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
              {cleanIP} · {new Date(log.received_at).toLocaleString()}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {typeof log.risk_score === 'number' && (
              <span title={`Risk score: ${log.risk_score}/100`}
                style={{ padding: '3px 10px', borderRadius: 16, fontSize: 'var(--text-xs)', fontWeight: 700,
                  background: risk.bg, color: risk.fg }}>
                {risk.label} Risk · {log.risk_score}
              </span>
            )}
            <span style={{ padding: '3px 10px', borderRadius: 16, fontSize: 'var(--text-xs)', fontWeight: 700,
              background: sevSt.bg, color: sevSt.color, textTransform: 'uppercase' }}>
              {log.severity_label}
            </span>
            <button onClick={onClose}
              style={{ background: 'rgba(255,255,255,0.1)', border: 'none', cursor: 'pointer',
                color: '#94a3b8', fontSize: 'var(--text-lg)', width: 28, height: 28, borderRadius: 6,
                display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              ×
            </button>
          </div>
        </div>

        {/* Scrollable content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>

          {/* Message */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Message</div>
            <div style={{ padding: 12, background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 8, fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.6,
              wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
              {log.message}
            </div>
          </div>

          {/* Why this score? — risk factor breakdown (newer logs only) */}
          <RiskFactorBreakdown factors={riskFactors} score={log.risk_score || 0} />

          {/* Remote source — real client for auth/vpn events */}
          {showRemote && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Remote Source</div>
              <div style={{ background: 'var(--tint-danger)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '0 12px' }}>
                <Field label="Remote IP"   value={remoteIP}   mono />
                {hasRealUser && <Field label="User"    value={remoteUser} mono />}
                {!hasRealUser && (
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                    padding: '6px 0', borderBottom: '1px solid var(--border-light)', lineHeight: 1.5 }}>
                    No username — pre-authentication probe (no credentials submitted)
                  </div>
                )}
                {remoteCty  && <Field label="Country" value={remoteCty} />}
              </div>
            </div>
          )}

          {/* Core fields */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Details</div>
            <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 8, padding: '0 12px' }}>
              <Field label={showRemote ? 'Reporting device' : 'Source IP'} value={cleanIP} mono />
              <Field label="Hostname"     value={log.source_host}     mono />
              <Field label="Vendor"       value={log.vendor} />
              <Field label="Category"     value={log.category} />
              {Array.isArray(log.structured_data?.mitre) && log.structured_data.mitre.length > 0 && (
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '9px 0', borderBottom: '1px solid var(--border-light)', gap: 12 }}>
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', flexShrink: 0 }}>MITRE ATT&amp;CK</span>
                  <MitreBadges ids={log.structured_data.mitre} />
                </div>
              )}
              <Field label="Program"      value={log.program} />
              <Field label="Severity"     value={log.severity_label} />
              <Field label="Facility"     value={log.facility_label} />
              <Field label="Received"     value={new Date(log.received_at).toLocaleString()} />
              {log.log_timestamp && (
                <Field label="Device time" value={new Date(log.log_timestamp).toLocaleString()} />
              )}
              <Field label="Parsed"       value={log.is_parsed ? 'Yes' : 'No (generic)'} />
            </div>
          </div>

          {/* Parsed fields */}
          {sdEntries.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                Parsed Fields ({sdEntries.length})
              </div>
              <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '0 12px' }}>
                {sdEntries.map(([k, v]) => (
                  <Field key={k} label={k} value={String(v)} mono />
                ))}
              </div>
            </div>
          )}

          {/* Quick actions */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Quick Actions</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              <button onClick={() => { onFilterIP(cleanIP); onClose(); }}
                style={{ padding: '7px 14px', borderRadius: 6, border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: 'var(--text-sm)', background: 'var(--bg-card)', color: 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', gap: 5 }}>
                📍 Filter by IP
              </button>
              <button onClick={() => { onFilterVendor(log.vendor); onClose(); }}
                style={{ padding: '7px 14px', borderRadius: 6, border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: 'var(--text-sm)', background: 'var(--bg-card)', color: 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', gap: 5 }}>
                🏷️ Filter by Vendor
              </button>
              <button onClick={() => { onFilterSeverity(SEVERITIES[log.severity] || ''); onClose(); }}
                style={{ padding: '7px 14px', borderRadius: 6, border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: 'var(--text-sm)', background: 'var(--bg-card)', color: 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', gap: 5 }}>
                🔴 Filter by Severity
              </button>
              <button onClick={() => navigator.clipboard.writeText(log.message)}
                style={{ padding: '7px 14px', borderRadius: 6, border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: 'var(--text-sm)', background: 'var(--bg-card)', color: 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', gap: 5 }}>
                ⎘ Copy Message
              </button>
              <button onClick={() => navigator.clipboard.writeText(JSON.stringify(log, null, 2))}
                style={{ padding: '7px 14px', borderRadius: 6, border: '1px solid var(--border)',
                  cursor: 'pointer', fontSize: 'var(--text-sm)', background: 'var(--bg-card)', color: 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', gap: 5 }}>
                ⎘ Copy Raw JSON
              </button>
            </div>
          </div>

          {/* Related logs */}
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
              Related Logs — Same IP, Last 5 Minutes
            </div>
            {loadingRel ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12 }}>Loading...</div>
            ) : related.length === 0 ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', padding: 12,
                background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8 }}>
                No other logs from this IP in the last 5 minutes
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {related.map((r, i) => {
                  const rs = sevStyle(r.severity_label);
                  return (
                    <div key={i} style={{ padding: '8px 12px', background: 'var(--bg-primary)',
                      border: '1px solid var(--border)', borderRadius: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                        <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase',
                          color: rs.color }}>{r.severity_label}</span>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)' }}>
                          {new Date(r.received_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.message}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
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
