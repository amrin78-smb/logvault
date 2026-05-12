'use client';

import { useEffect, useState } from 'react';

function formatInterval(val: any): string {
  if (!val) return '-';
  if (typeof val === 'string') return val;
  // PostgreSQL returns interval as object e.g. { minutes: 5 } or { hours: 1 }
  if (typeof val === 'object') {
    const parts = [];
    if (val.hours)   parts.push(`${val.hours}h`);
    if (val.minutes) parts.push(`${val.minutes}m`);
    if (val.seconds) parts.push(`${val.seconds}s`);
    return parts.length ? parts.join(' ') : JSON.stringify(val);
  }
  return String(val);
}

export default function AlertEvents() {
  const [events, setEvents] = useState<any[]>([]);
  const [rules,  setRules]  = useState<any[]>([]);
  const [error,  setError]  = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/alerts/events')
      .then(r => r.json())
      .then(d => setEvents(d.data || []))
      .catch(e => setError(e.message));

    fetch('/api/alerts/rules')
      .then(r => r.json())
      .then(d => setRules(d.data || []))
      .catch(e => setError(e.message));
  }, []);

  const acknowledge = async (id: number) => {
    await fetch(`/api/alerts/events/${id}/acknowledge`, { method: 'PATCH' });
    setEvents(prev => prev.map(e => e.id === id ? { ...e, acknowledged: true } : e));
  };

  const toggleRule = async (id: number, enabled: boolean) => {
    await fetch(`/api/alerts/rules/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_enabled: enabled }),
    });
    setRules(prev => prev.map(r => r.id === id ? { ...r, is_enabled: enabled } : r));
  };

  const CARD = { background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20, marginBottom: 16 };

  if (error) {
    return (
      <div style={{ ...CARD, color: '#ef4444' }}>
        Failed to load alerts: {error}
      </div>
    );
  }

  return (
    <div>
      {/* Alert Rules */}
      <div style={CARD}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Alert Rules</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e2d40' }}>
              {['Status','Rule','Description','Threshold','Window'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#64748b', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rules.map(rule => (
              <tr key={rule.id} style={{ borderBottom: '1px solid #0f1117' }}>
                <td style={{ padding: '8px 12px' }}>
                  <button onClick={() => toggleRule(rule.id, !rule.is_enabled)}
                    style={{ padding: '3px 10px', borderRadius: 12, border: 'none', cursor: 'pointer',
                      fontSize: 11, fontWeight: 600,
                      background: rule.is_enabled ? '#14532d' : '#1e293b',
                      color: rule.is_enabled ? '#22c55e' : '#475569' }}>
                    {rule.is_enabled ? 'Active' : 'Disabled'}
                  </button>
                </td>
                <td style={{ padding: '8px 12px', color: '#e2e8f0', fontWeight: 500 }}>{rule.name}</td>
                <td style={{ padding: '8px 12px', color: '#64748b' }}>{rule.description || '-'}</td>
                <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{rule.threshold_count} events</td>
                <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{formatInterval(rule.threshold_window)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Alert Events */}
      <div style={CARD}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>
          Alert History
          {events.filter(e => !e.acknowledged).length > 0 && (
            <span style={{ marginLeft: 8, padding: '2px 8px', borderRadius: 10, background: '#7f1d1d',
              color: '#fca5a5', fontSize: 11 }}>
              {events.filter(e => !e.acknowledged).length} unacknowledged
            </span>
          )}
        </div>

        {events.length === 0 ? (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#22c55e', fontSize: 13 }}>
            No alerts fired
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e2d40' }}>
                {['Fired At','Rule','Host','Matches','Sample Message',''].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: '#64748b', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map(evt => (
                <tr key={evt.id} style={{ borderBottom: '1px solid #0f1117',
                  background: evt.acknowledged ? 'transparent' : '#180f0f' }}>
                  <td style={{ padding: '8px 12px', color: '#64748b', whiteSpace: 'nowrap' }}>
                    {new Date(evt.fired_at).toLocaleString()}
                  </td>
                  <td style={{ padding: '8px 12px', color: '#fca5a5', fontWeight: 500 }}>{evt.rule_name}</td>
                  <td style={{ padding: '8px 12px', color: '#94a3b8' }}>{evt.source_host || evt.source_ip || '-'}</td>
                  <td style={{ padding: '8px 12px', color: '#e2e8f0' }}>{evt.match_count}</td>
                  <td style={{ padding: '8px 12px', color: '#64748b', maxWidth: 300,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {evt.sample_message || '-'}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    {!evt.acknowledged && (
                      <button onClick={() => acknowledge(evt.id)}
                        style={{ padding: '3px 10px', borderRadius: 4, border: '1px solid #1e2d40',
                          cursor: 'pointer', fontSize: 11, background: '#161b27', color: '#94a3b8' }}>
                        Ack
                      </button>
                    )}
                    {evt.acknowledged && <span style={{ color: '#22c55e', fontSize: 11 }}>✓ Acked</span>}
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
