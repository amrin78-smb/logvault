'use client';
import { useEffect, useState } from 'react';

function formatInterval(val: any): string {
  if (!val) return '-';
  if (typeof val === 'string') return val;
  if (typeof val === 'object') {
    const parts = [];
    if (val.hours)   parts.push(`${val.hours}h`);
    if (val.minutes) parts.push(`${val.minutes}m`);
    if (val.seconds) parts.push(`${val.seconds}s`);
    return parts.length ? parts.join(' ') : JSON.stringify(val);
  }
  return String(val);
}

const CARD = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20, marginBottom: 16 };
const TH   = { padding: '8px 12px', textAlign: 'left' as const, color: '#718096', fontWeight: 600, fontSize: 11 };
const TD   = { padding: '9px 12px' };

// Hardcoded correlation rules for display (mirrors correlationEngine.js)
const CORRELATION_RULES = [
  { name: 'Brute Force Login Success',       description: '3+ failed logins from same IP followed by success within 10 min',    severity: 'critical', window: '10 min' },
  { name: 'Port Scan Detected',              description: 'Same source IP hitting 8+ unique destinations denied within 3 min',   severity: 'warning',  window: '3 min'  },
  { name: 'Interface Flapping Detected',     description: 'Same interface changed state 4+ times within 10 min',                 severity: 'warning',  window: '10 min' },
  { name: 'Network Loop Detected',           description: 'MAC address flapping 2+ times from same switch within 2 min',         severity: 'critical', window: '2 min'  },
  { name: 'After-Hours Configuration Change',description: 'Any config change between 10PM and 6AM',                              severity: 'warning',  window: '1 min'  },
  { name: 'STP Instability Detected',        description: '3+ STP topology changes from same device within 5 min',               severity: 'warning',  window: '5 min'  },
  { name: 'Repeated IPS Triggers',           description: 'Same source IP triggering 5+ IPS events within 5 min',                severity: 'critical', window: '5 min'  },
  { name: 'VPN Brute Force Attempt',         description: '5+ VPN login failures from same source within 5 min',                 severity: 'error',    window: '5 min'  },
];

const SEV_STYLE: Record<string, { bg: string; color: string }> = {
  critical: { bg: '#fef2f2', color: '#dc2626' },
  error:    { bg: '#fff7ed', color: '#ea580c' },
  warning:  { bg: '#fefce8', color: '#ca8a04' },
};

export default function AlertEvents() {
  const [events,   setEvents]   = useState<any[]>([]);
  const [rules,    setRules]    = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<'threshold' | 'correlation' | 'history'>('history');

  useEffect(() => {
    fetch('/api/alerts/events').then(r => r.json()).then(d => setEvents(d.data || [])).catch(() => {});
    fetch('/api/alerts/rules').then(r  => r.json()).then(d => setRules(d.data  || [])).catch(() => {});
  }, []);

  const acknowledge = async (id: number) => {
    await fetch(`/api/alerts/events/${id}/acknowledge`, { method: 'PATCH' });
    setEvents(prev => prev.map(e => e.id === id ? { ...e, acknowledged: true } : e));
  };

  const toggleRule = async (id: number, enabled: boolean) => {
    await fetch(`/api/alerts/rules/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_enabled: enabled }),
    });
    setRules(prev => prev.map(r => r.id === id ? { ...r, is_enabled: enabled } : r));
  };

  const unacked = events.filter(e => !e.acknowledged).length;

  // Filter out correlation rules from threshold rules display
  const correlationNames = new Set(CORRELATION_RULES.map(r => r.name));
  const thresholdRules   = rules.filter(r => !correlationNames.has(r.name));

  return (
    <div>
      {/* Tab switcher */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: '#fff',
        border: '1px solid #e2e6ea', borderRadius: 10, padding: 6 }}>
        {[
          { id: 'history',     label: `Alert History${unacked > 0 ? ` (${unacked})` : ''}` },
          { id: 'threshold',   label: 'Threshold Rules' },
          { id: 'correlation', label: 'Correlation Rules' },
        ].map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as any)}
            style={{ padding: '6px 16px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: activeTab === t.id ? 600 : 400,
              background: activeTab === t.id ? '#1a202c' : 'transparent',
              color: activeTab === t.id ? '#fff' : '#6b7280', transition: 'all 0.15s' }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── ALERT HISTORY ── */}
      {activeTab === 'history' && (
        <div style={CARD}>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>
            Alert History
            {unacked > 0 && (
              <span style={{ marginLeft: 8, padding: '2px 8px', borderRadius: 10, background: '#fef2f2',
                color: '#dc2626', fontSize: 11, fontWeight: 700, border: '1px solid #fecaca' }}>
                {unacked} unacknowledged
              </span>
            )}
          </div>
          <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
            Fired alerts from both threshold rules and correlation engine
          </div>
          {events.length === 0 ? (
            <div style={{ padding: '40px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>
              ✓ No alerts fired
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                  {['Fired At','Rule','Host','Matches','Sample Message',''].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {events.map((evt, i) => {
                  const isCorrelation = correlationNames.has(evt.rule_name);
                  return (
                    <tr key={evt.id} style={{ borderBottom: '1px solid #f0f2f5',
                      background: evt.acknowledged ? (i % 2 === 0 ? '#fafbfc' : '#fff') : '#fffbeb' }}>
                      <td style={{ ...TD, color: '#9ca3af', whiteSpace: 'nowrap',
                        fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                        {new Date(evt.fired_at).toLocaleString()}
                      </td>
                      <td style={{ ...TD }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {isCorrelation && (
                            <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 4, background: '#eff6ff',
                              color: '#2563eb', border: '1px solid #bfdbfe', fontWeight: 600 }}>
                              CORR
                            </span>
                          )}
                          <span style={{ color: '#dc2626', fontWeight: 600, fontSize: 12 }}>{evt.rule_name}</span>
                        </div>
                      </td>
                      <td style={{ ...TD, color: '#1a202c', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                        {evt.source_host || evt.source_ip || '-'}
                      </td>
                      <td style={{ ...TD, color: '#4a5568', fontWeight: 600 }}>{evt.match_count}</td>
                      <td style={{ ...TD, color: '#4a5568', maxWidth: 350, overflow: 'hidden',
                        textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {evt.sample_message || '-'}
                      </td>
                      <td style={TD}>
                        {!evt.acknowledged ? (
                          <button onClick={() => acknowledge(evt.id)}
                            style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #e2e6ea',
                              cursor: 'pointer', fontSize: 11, background: '#f8f9fb', color: '#4a5568', fontWeight: 500 }}>
                            Acknowledge
                          </button>
                        ) : (
                          <span style={{ color: '#16a34a', fontSize: 11, fontWeight: 600 }}>✓ Acked</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── THRESHOLD RULES ── */}
      {activeTab === 'threshold' && (
        <div style={CARD}>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Threshold Alert Rules</div>
          <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
            Single-event rules that fire when a count threshold is reached within a time window
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                {['Status','Rule','Description','Threshold','Window'].map(h => <th key={h} style={TH}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {thresholdRules.map((rule, i) => (
                <tr key={rule.id} style={{ borderBottom: '1px solid #f0f2f5',
                  background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                  <td style={TD}>
                    <button onClick={() => toggleRule(rule.id, !rule.is_enabled)}
                      style={{ padding: '3px 12px', borderRadius: 12, border: 'none', cursor: 'pointer',
                        fontSize: 11, fontWeight: 600,
                        background: rule.is_enabled ? '#dcfce7' : '#f3f4f6',
                        color: rule.is_enabled ? '#16a34a' : '#9ca3af' }}>
                      {rule.is_enabled ? 'Active' : 'Disabled'}
                    </button>
                  </td>
                  <td style={{ ...TD, color: '#1a202c', fontWeight: 600 }}>{rule.name}</td>
                  <td style={{ ...TD, color: '#4a5568' }}>{rule.description || '-'}</td>
                  <td style={{ ...TD, color: '#4a5568' }}>{rule.threshold_count} events</td>
                  <td style={{ ...TD, color: '#4a5568' }}>{formatInterval(rule.threshold_window)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── CORRELATION RULES ── */}
      {activeTab === 'correlation' && (
        <div style={CARD}>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Correlation Engine Rules</div>
          <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
            Multi-event pattern rules evaluated in real time as logs arrive. These detect complex attack patterns
            and network issues that single-event rules cannot catch.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {CORRELATION_RULES.map((rule, i) => {
              const sev = SEV_STYLE[rule.severity] || SEV_STYLE.warning;
              // Check if this rule has fired in the alert history
              const firedCount = events.filter(e => e.rule_name === rule.name).length;
              return (
                <div key={i} style={{ background: '#f8f9fb', border: '1px solid #e2e6ea',
                  borderRadius: 8, padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 8, background: sev.bg,
                    border: `1px solid ${sev.color}33`, display: 'flex', alignItems: 'center',
                    justifyContent: 'center', flexShrink: 0 }}>
                    <span style={{ fontSize: 16 }}>
                      {rule.severity === 'critical' ? '🚨' : rule.severity === 'error' ? '⚠️' : '🔍'}
                    </span>
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                      <span style={{ fontSize: 13, fontWeight: 600, color: '#1a202c' }}>{rule.name}</span>
                      <span style={{ padding: '1px 7px', borderRadius: 10, fontSize: 10, fontWeight: 600,
                        background: sev.bg, color: sev.color, border: `1px solid ${sev.color}44`,
                        textTransform: 'uppercase' }}>
                        {rule.severity}
                      </span>
                      <span style={{ padding: '1px 7px', borderRadius: 10, fontSize: 10,
                        background: '#eff6ff', color: '#2563eb', border: '1px solid #bfdbfe' }}>
                        window: {rule.window}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: '#4a5568' }}>{rule.description}</div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    {firedCount > 0 ? (
                      <div style={{ background: '#fef2f2', border: '1px solid #fecaca',
                        borderRadius: 8, padding: '4px 10px', textAlign: 'center' }}>
                        <div style={{ fontSize: 16, fontWeight: 700, color: '#dc2626' }}>{firedCount}</div>
                        <div style={{ fontSize: 10, color: '#9ca3af' }}>fired</div>
                      </div>
                    ) : (
                      <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0',
                        borderRadius: 8, padding: '4px 10px', textAlign: 'center' }}>
                        <div style={{ fontSize: 12, color: '#16a34a', fontWeight: 600 }}>✓ Clear</div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
