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

export default function AlertEvents() {
  const [events, setEvents] = useState<any[]>([]);
  const [rules,  setRules]  = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/alerts/events').then(r => r.json()).then(d => setEvents(d.data || [])).catch(() => {});
    fetch('/api/alerts/rules').then(r => r.json()).then(d => setRules(d.data || [])).catch(() => {});
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

  return (
    <div>
      <div style={CARD}>
        <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Alert Rules</div>
        <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Configure when alerts should fire</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #f0f2f5' }}>
              {['Status','Rule','Description','Threshold','Window'].map(h => <th key={h} style={TH}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, i) => (
              <tr key={rule.id} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                <td style={TD}>
                  <button onClick={() => toggleRule(rule.id, !rule.is_enabled)}
                    style={{ padding: '3px 12px', borderRadius: 12, border: 'none', cursor: 'pointer', fontSize: 11, fontWeight: 600,
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

      <div style={CARD}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 2 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: '#1a202c' }}>Alert History</span>
          {unacked > 0 && (
            <span style={{ padding: '2px 8px', borderRadius: 10, background: '#fef2f2',
              color: '#dc2626', fontSize: 11, fontWeight: 700, border: '1px solid #fecaca' }}>
              {unacked} unacknowledged
            </span>
          )}
        </div>
        <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Fired alert events</div>

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
              {events.map((evt, i) => (
                <tr key={evt.id} style={{ borderBottom: '1px solid #f0f2f5',
                  background: evt.acknowledged ? (i % 2 === 0 ? '#fafbfc' : '#fff') : '#fffbeb' }}>
                  <td style={{ ...TD, color: '#9ca3af', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                    {new Date(evt.fired_at).toLocaleString()}
                  </td>
                  <td style={{ ...TD, color: '#dc2626', fontWeight: 600 }}>{evt.rule_name}</td>
                  <td style={{ ...TD, color: '#1a202c', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                    {evt.source_host || evt.source_ip || '-'}
                  </td>
                  <td style={{ ...TD, color: '#4a5568', fontWeight: 600 }}>{evt.match_count}</td>
                  <td style={{ ...TD, color: '#4a5568', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
