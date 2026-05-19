'use client';
import { useEffect, useState, useCallback } from 'react';
import { useToast } from '@/components/Toast';

function formatInterval(val: any): string {
  if (!val) return '-';
  if (typeof val === 'string') return val;
  if (typeof val === 'object') {
    const parts = [];
    if (val.hours)   parts.push(`${val.hours}h`);
    if (val.minutes) parts.push(`${val.minutes}m`);
    if (val.seconds) parts.push(`${val.seconds}s`);
    return parts.join(' ') || JSON.stringify(val);
  }
  return String(val);
}

const CARD = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20, marginBottom: 16 };
const TH   = { padding: '8px 12px', textAlign: 'left' as const, color: '#718096', fontWeight: 600, fontSize: 11 };
const TD   = { padding: '9px 12px' };

const CORRELATION_RULES = [
  { name: 'Brute Force Login Success',        description: '3+ failed logins from same IP followed by success within 10 min',   severity: 'critical', window: '10 min' },
  { name: 'Port Scan Detected',               description: 'Same source IP hitting 8+ unique destinations denied within 3 min',  severity: 'warning',  window: '3 min'  },
  { name: 'Interface Flapping Detected',      description: 'Same interface changed state 4+ times within 10 min',                severity: 'warning',  window: '10 min' },
  { name: 'Network Loop Detected',            description: 'MAC address flapping 2+ times from same switch within 2 min',        severity: 'critical', window: '2 min'  },
  { name: 'After-Hours Configuration Change', description: 'Any config change between 10PM and 6AM',                             severity: 'warning',  window: '1 min'  },
  { name: 'STP Instability Detected',         description: '3+ STP topology changes from same device within 5 min',              severity: 'warning',  window: '5 min'  },
  { name: 'Repeated IPS Triggers',            description: 'Same source IP triggering 5+ IPS events within 5 min',               severity: 'critical', window: '5 min'  },
  { name: 'VPN Brute Force Attempt',          description: '5+ VPN login failures from same source within 5 min',                severity: 'error',    window: '5 min'  },
];

const SEV_STYLE: Record<string, { bg: string; color: string }> = {
  critical: { bg: '#fef2f2', color: '#dc2626' },
  error:    { bg: '#fff7ed', color: '#ea580c' },
  warning:  { bg: '#fefce8', color: '#ca8a04' },
};

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
}

interface GroupedRule {
  rule_name: string;
  events: AlertEvent[];
  unacked_count: number;
  total_count: number;
  latest: string;
  is_correlation: boolean;
}

export default function AlertEvents() {
  const { toast } = useToast();
  const [events,      setEvents]      = useState<AlertEvent[]>([]);
  const [rules,       setRules]       = useState<any[]>([]);
  const [activeTab,   setActiveTab]   = useState<'active' | 'history' | 'threshold' | 'correlation'>('active');
  const [showAcked,   setShowAcked]   = useState(false);
  const [expanded,    setExpanded]    = useState<Set<string>>(new Set());
  const [selected,    setSelected]    = useState<Set<number>>(new Set());
  const [loading,     setLoading]     = useState(false);

  const correlationNames = new Set(CORRELATION_RULES.map(r => r.name));

  const fetchData = useCallback(() => {
    fetch('/api/alerts/events').then(r => r.json()).then(d => setEvents(d.data || [])).catch(() => {});
    fetch('/api/alerts/rules').then(r  => r.json()).then(d => setRules(d.data  || [])).catch(() => {});
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Group events by rule name
  const grouped: GroupedRule[] = [];
  const ruleMap = new Map<string, AlertEvent[]>();
  for (const e of events) {
    if (!ruleMap.has(e.rule_name)) ruleMap.set(e.rule_name, []);
    ruleMap.get(e.rule_name)!.push(e);
  }
  for (const [rule_name, evts] of ruleMap.entries()) {
    const unacked = evts.filter(e => !e.acknowledged).length;
    grouped.push({
      rule_name,
      events:        evts.sort((a, b) => new Date(b.fired_at).getTime() - new Date(a.fired_at).getTime()),
      unacked_count: unacked,
      total_count:   evts.length,
      latest:        evts[0]?.fired_at,
      is_correlation: correlationNames.has(rule_name),
    });
  }
  grouped.sort((a, b) => b.unacked_count - a.unacked_count || new Date(b.latest).getTime() - new Date(a.latest).getTime());

  const activeGroups  = grouped.filter(g => g.unacked_count > 0);
  const historyGroups = grouped;

  const totalUnacked = events.filter(e => !e.acknowledged).length;

  // Acknowledge single
  const acknowledge = async (id: number) => {
    await fetch(`/api/alerts/events/${id}/acknowledge`, { method: 'PATCH' });
    setEvents(prev => prev.map(e => e.id === id ? { ...e, acknowledged: true } : e));
    setSelected(prev => { const s = new Set(prev); s.delete(id); return s; });
    toast('Alert acknowledged', 'success');
  };

  // Acknowledge multiple
  const acknowledgeSelected = async () => {
    if (selected.size === 0) return;
    setLoading(true);
    await Promise.all([...selected].map(id => fetch(`/api/alerts/events/${id}/acknowledge`, { method: 'PATCH' })));
    setEvents(prev => prev.map(e => selected.has(e.id) ? { ...e, acknowledged: true } : e));
    toast(`${selected.size} alert(s) acknowledged`, 'success');
    setSelected(new Set());
    setLoading(false);
  };

  // Acknowledge all in a group
  const acknowledgeGroup = async (rule_name: string) => {
    setLoading(true);
    const ids = events.filter(e => e.rule_name === rule_name && !e.acknowledged).map(e => e.id);
    await Promise.all(ids.map(id => fetch(`/api/alerts/events/${id}/acknowledge`, { method: 'PATCH' })));
    setEvents(prev => prev.map(e => e.rule_name === rule_name ? { ...e, acknowledged: true } : e));
    toast(`All "${rule_name}" alerts acknowledged`, 'success');
    setLoading(false);
  };

  // Acknowledge ALL
  const acknowledgeAll = async () => {
    setLoading(true);
    const ids = events.filter(e => !e.acknowledged).map(e => e.id);
    await Promise.all(ids.map(id => fetch(`/api/alerts/events/${id}/acknowledge`, { method: 'PATCH' })));
    setEvents(prev => prev.map(e => ({ ...e, acknowledged: true })));
    toast(`All ${ids.length} alerts acknowledged`, 'success');
    setSelected(new Set());
    setLoading(false);
  };

  const toggleExpand = (rule: string) => {
    setExpanded(prev => {
      const s = new Set(prev);
      s.has(rule) ? s.delete(rule) : s.add(rule);
      return s;
    });
  };

  const toggleSelect = (id: number) => {
    setSelected(prev => {
      const s = new Set(prev);
      s.has(id) ? s.delete(id) : s.add(id);
      return s;
    });
  };

  const toggleSelectAll = (evts: AlertEvent[]) => {
    const unacked = evts.filter(e => !e.acknowledged).map(e => e.id);
    const allSelected = unacked.every(id => selected.has(id));
    setSelected(prev => {
      const s = new Set(prev);
      if (allSelected) { unacked.forEach(id => s.delete(id)); }
      else { unacked.forEach(id => s.add(id)); }
      return s;
    });
  };

  const thresholdRules = rules.filter(r => !correlationNames.has(r.name));

  const renderGroups = (groups: GroupedRule[]) => (
    <div>
      {/* Bulk actions bar */}
      {selected.size > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
          background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 13, color: '#1e40af', fontWeight: 500 }}>{selected.size} alert(s) selected</span>
          <button onClick={acknowledgeSelected} disabled={loading}
            style={{ padding: '5px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
              background: '#2563eb', color: '#fff', fontSize: 12, fontWeight: 600 }}>
            {loading ? 'Processing...' : 'Acknowledge Selected'}
          </button>
          <button onClick={() => setSelected(new Set())}
            style={{ padding: '5px 12px', borderRadius: 6, border: '1px solid #bfdbfe', cursor: 'pointer',
              background: '#fff', color: '#2563eb', fontSize: 12 }}>
            Clear Selection
          </button>
        </div>
      )}

      {groups.length === 0 ? (
        <div style={{ padding: '48px 0', textAlign: 'center', color: '#16a34a', fontSize: 14, fontWeight: 500 }}>
          ✓ No active alerts
        </div>
      ) : groups.map(group => {
        const isExpanded = expanded.has(group.rule_name);
        const displayEvents = showAcked ? group.events : group.events.filter(e => !e.acknowledged);
        if (displayEvents.length === 0 && !showAcked) return null;

        const sevColor = group.rule_name.toLowerCase().includes('brute') || group.rule_name.toLowerCase().includes('loop') || group.rule_name.toLowerCase().includes('ips') ? '#dc2626'
          : group.rule_name.toLowerCase().includes('vpn') ? '#ea580c' : '#ca8a04';

        return (
          <div key={group.rule_name} style={{ marginBottom: 8, border: '1px solid #e2e6ea', borderRadius: 10, overflow: 'hidden' }}>
            {/* Group header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px',
              background: group.unacked_count > 0 ? '#fffbeb' : '#f8f9fb', cursor: 'pointer',
              borderBottom: isExpanded ? '1px solid #e2e6ea' : 'none' }}
              onClick={() => toggleExpand(group.rule_name)}>

              {/* Expand arrow */}
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none"
                style={{ transform: isExpanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s', flexShrink: 0 }}>
                <polyline points="3,2 9,6 3,10" stroke="#9ca3af" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
              </svg>

              {/* CORR badge */}
              {group.is_correlation && (
                <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 4, background: '#eff6ff',
                  color: '#2563eb', border: '1px solid #bfdbfe', fontWeight: 600, flexShrink: 0 }}>CORR</span>
              )}

              {/* Rule name */}
              <span style={{ fontSize: 13, fontWeight: 700, color: sevColor, flex: 1 }}>{group.rule_name}</span>

              {/* Stats */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {group.unacked_count > 0 && (
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#dc2626', background: '#fef2f2',
                    border: '1px solid #fecaca', padding: '2px 8px', borderRadius: 10 }}>
                    {group.unacked_count} unacked
                  </span>
                )}
                <span style={{ fontSize: 11, color: '#9ca3af' }}>{group.total_count} total</span>
                <span style={{ fontSize: 11, color: '#9ca3af', fontFamily: 'JetBrains Mono, monospace' }}>
                  Last: {new Date(group.latest).toLocaleTimeString()}
                </span>

                {/* Acknowledge group button */}
                {group.unacked_count > 0 && (
                  <button onClick={(e) => { e.stopPropagation(); acknowledgeGroup(group.rule_name); }}
                    disabled={loading}
                    style={{ padding: '3px 10px', borderRadius: 5, border: '1px solid #fde68a',
                      cursor: 'pointer', fontSize: 11, fontWeight: 600, background: '#fefce8',
                      color: '#ca8a04', flexShrink: 0 }}>
                    Ack All ({group.unacked_count})
                  </button>
                )}
              </div>
            </div>

            {/* Expanded rows */}
            {isExpanded && (
              <div>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: '#f8f9fb', borderBottom: '1px solid #f0f2f5' }}>
                      <th style={{ ...TH, width: 36 }}>
                        <input type="checkbox"
                          checked={displayEvents.filter(e => !e.acknowledged).every(e => selected.has(e.id)) && displayEvents.some(e => !e.acknowledged)}
                          onChange={() => toggleSelectAll(displayEvents)}
                          style={{ cursor: 'pointer' }} />
                      </th>
                      {['Time','Host','Matches','Message',''].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {displayEvents.map((evt, i) => (
                      <tr key={evt.id} style={{ borderBottom: '1px solid #f0f2f5',
                        background: evt.acknowledged ? '#fafbfc' : i % 2 === 0 ? '#fff' : '#fffef8',
                        opacity: evt.acknowledged ? 0.6 : 1 }}>
                        <td style={{ ...TD, width: 36 }}>
                          {!evt.acknowledged && (
                            <input type="checkbox" checked={selected.has(evt.id)}
                              onChange={() => toggleSelect(evt.id)} style={{ cursor: 'pointer' }} />
                          )}
                        </td>
                        <td style={{ ...TD, fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#9ca3af', whiteSpace: 'nowrap' }}>
                          {new Date(evt.fired_at).toLocaleString()}
                        </td>
                        <td style={{ ...TD, fontFamily: 'JetBrains Mono, monospace', color: '#1a202c', fontWeight: 500 }}>
                          {evt.source_host || evt.source_ip || '—'}
                        </td>
                        <td style={{ ...TD, fontWeight: 600, color: '#4a5568' }}>{evt.match_count}</td>
                        <td style={{ ...TD, color: '#4a5568', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {evt.sample_message}
                        </td>
                        <td style={{ ...TD, whiteSpace: 'nowrap' }}>
                          {evt.acknowledged ? (
                            <span style={{ color: '#16a34a', fontSize: 11, fontWeight: 600 }}>✓ Acked</span>
                          ) : (
                            <button onClick={() => acknowledge(evt.id)}
                              style={{ padding: '3px 10px', borderRadius: 5, border: '1px solid #e2e6ea',
                                cursor: 'pointer', fontSize: 11, background: '#f8f9fb', color: '#4a5568', fontWeight: 500 }}>
                              Acknowledge
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );

  const TABS = [
    { id: 'active',      label: `Active Alerts${totalUnacked > 0 ? ` (${totalUnacked})` : ''}` },
    { id: 'history',     label: 'All History' },
    { id: 'threshold',   label: 'Threshold Rules' },
    { id: 'correlation', label: 'Correlation Rules' },
  ];

  return (
    <div>
      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: '#fff',
        border: '1px solid #e2e6ea', borderRadius: 10, padding: 6, alignItems: 'center' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as any)}
            style={{ padding: '6px 16px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: activeTab === t.id ? 600 : 400,
              background: activeTab === t.id ? '#1a202c' : 'transparent',
              color: activeTab === t.id ? '#fff' : '#6b7280', transition: 'all 0.15s' }}>
            {t.label}
          </button>
        ))}

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* Show acked toggle — only on active/history */}
        {(activeTab === 'active' || activeTab === 'history') && (
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#718096', cursor: 'pointer', marginRight: 8 }}>
            <input type="checkbox" checked={showAcked} onChange={e => setShowAcked(e.target.checked)} style={{ cursor: 'pointer' }} />
            Show acknowledged
          </label>
        )}

        {/* Acknowledge all button */}
        {activeTab === 'active' && totalUnacked > 0 && (
          <button onClick={acknowledgeAll} disabled={loading}
            style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid #fecaca',
              cursor: 'pointer', fontSize: 12, fontWeight: 600, background: '#fef2f2',
              color: '#dc2626', transition: 'all 0.15s' }}>
            {loading ? 'Processing...' : `Acknowledge All (${totalUnacked})`}
          </button>
        )}
      </div>

      {/* ── ACTIVE ALERTS ── */}
      {activeTab === 'active' && (
        <div style={CARD}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c' }}>Active Alerts</div>
              <div style={{ fontSize: 11, color: '#718096', marginTop: 2 }}>
                Grouped by rule — expand to see individual events
              </div>
            </div>
            {totalUnacked === 0 && (
              <span style={{ fontSize: 13, color: '#16a34a', fontWeight: 600 }}>✓ All clear</span>
            )}
          </div>
          {renderGroups(activeGroups)}
        </div>
      )}

      {/* ── ALL HISTORY ── */}
      {activeTab === 'history' && (
        <div style={CARD}>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Alert History</div>
          <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>All alerts — grouped by rule</div>
          {renderGroups(historyGroups)}
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
                <tr key={rule.id} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                  <td style={TD}>
                    <span style={{ padding: '3px 12px', borderRadius: 12, fontSize: 11, fontWeight: 600,
                      background: rule.is_enabled ? '#dcfce7' : '#f3f4f6',
                      color: rule.is_enabled ? '#16a34a' : '#9ca3af' }}>
                      {rule.is_enabled ? 'Active' : 'Disabled'}
                    </span>
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
            Multi-event pattern rules evaluated in real time as logs arrive
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {CORRELATION_RULES.map((rule, i) => {
              const sev = SEV_STYLE[rule.severity] || SEV_STYLE.warning;
              const firedCount = events.filter(e => e.rule_name === rule.name).length;
              const unackedCount = events.filter(e => e.rule_name === rule.name && !e.acknowledged).length;
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
                        background: sev.bg, color: sev.color, textTransform: 'uppercase' }}>
                        {rule.severity}
                      </span>
                      <span style={{ padding: '1px 7px', borderRadius: 10, fontSize: 10,
                        background: '#eff6ff', color: '#2563eb' }}>
                        window: {rule.window}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: '#4a5568' }}>{rule.description}</div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    {firedCount > 0 ? (
                      <div style={{ background: unackedCount > 0 ? '#fef2f2' : '#f0fdf4',
                        border: `1px solid ${unackedCount > 0 ? '#fecaca' : '#bbf7d0'}`,
                        borderRadius: 8, padding: '6px 12px', textAlign: 'center' }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: unackedCount > 0 ? '#dc2626' : '#16a34a' }}>
                          {unackedCount > 0 ? unackedCount : firedCount}
                        </div>
                        <div style={{ fontSize: 9, color: '#9ca3af' }}>
                          {unackedCount > 0 ? 'unacked' : 'all acked'}
                        </div>
                      </div>
                    ) : (
                      <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0',
                        borderRadius: 8, padding: '6px 12px', textAlign: 'center' }}>
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
