'use client';
import { useEffect, useState } from 'react';
import { MitreBadges } from './mitre';

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

function riskBadge(score: number): { label: string; color: string; bg: string } {
  if (score >= 81) return { label: 'Critical Risk', color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)' };
  if (score >= 61) return { label: 'High Risk',     color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)' };
  if (score >= 31) return { label: 'Medium Risk',   color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)' };
  return { label: 'Low Risk', color: 'var(--tint-success-fg)', bg: 'var(--tint-success)' };
}

interface Props {
  log:          LogRow | null;
  onClose:      () => void;
  onFilterIP:   (ip: string) => void;
  onFilterVendor: (vendor: string) => void;
  onFilterSeverity: (severity: string) => void;
}

const SEV_COLORS: Record<string, { color: string; bg: string }> = {
  emergency: { color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)' },
  alert:     { color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)' },
  critical:  { color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)' },
  error:     { color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)' },
  warning:   { color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)' },
  notice:    { color: 'var(--tint-info-fg)',    bg: 'var(--tint-info)' },
  info:      { color: 'var(--tint-success-fg)', bg: 'var(--tint-success)' },
  debug:     { color: 'var(--text-muted)',      bg: 'var(--surface-subtle)' },
};

const VENDOR_COLORS: Record<string, string> = {
  fortinet: '#ee4d2d', cisco: '#1ba0d7', paloalto: '#fa582d',
  aruba: '#f47920', sangfor: '#005bac', generic: '#6b7280',
  forcepoint: '#003087', checkpoint: '#E31937', juniper: '#84BD00',
  windows: '#0078D4', sonicwall: '#FF6600',
};

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

  const sevStyle  = SEV_COLORS[log.severity_label] || { color: 'var(--text-muted)', bg: 'var(--surface-subtle)' };
  const risk      = riskBadge(log.risk_score || 0);
  const cleanIP   = log.source_ip?.replace('/32', '');
  const sdEntries = log.structured_data ? Object.entries(log.structured_data).filter(([, v]) => v !== null && v !== '') : [];

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
                  background: risk.bg, color: risk.color }}>
                {risk.label} · {log.risk_score}
              </span>
            )}
            <span style={{ padding: '3px 10px', borderRadius: 16, fontSize: 'var(--text-xs)', fontWeight: 700,
              background: sevStyle.bg, color: sevStyle.color, textTransform: 'uppercase' }}>
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

          {/* Core fields */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Details</div>
            <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 8, padding: '0 12px' }}>
              <Field label="Source IP"    value={cleanIP}             mono />
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
                  const rs = SEV_COLORS[r.severity_label] || { color: 'var(--text-muted)', bg: 'var(--surface-subtle)' };
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
