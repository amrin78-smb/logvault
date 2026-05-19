'use client';

import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const CARD  = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: '14px 16px' };
const TITLE = { fontSize: 13, fontWeight: 600, color: '#1a202c', marginBottom: 2 };
const SUB   = { fontSize: 11, color: '#9ca3af', marginBottom: 10 };

// ── Custom tooltip for bar charts ─────────────────────────────
const CustomTooltip = ({ active, payload, label, unit = 'events' }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 8,
      padding: '8px 12px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)', fontSize: 12 }}>
      <div style={{ fontWeight: 600, color: '#1a202c', marginBottom: 4 }}>{label}</div>
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, color: p.color }}>
          <div style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
          <span style={{ color: '#4a5568' }}>{parseInt(p.value).toLocaleString()} {unit}</span>
        </div>
      ))}
    </div>
  );
};

// ── Top Security Events ───────────────────────────────────────
export function TopSecurityEvents({ hours, onNavigate }: { hours: number; onNavigate?: () => void }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-security-events?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const COLORS = ['#dc2626','#ea580c','#ca8a04','#7c3aed','#0891b2','#16a34a','#475569'];
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Security Events</div>
      <div style={SUB}>Most frequent error/warning types — {hours}h · Click bar to investigate</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>
      ) : (
        <ResponsiveContainer width="100%" height={140}>
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 36, left: 0, bottom: 0 }}
            onClick={(d) => { if (d?.activePayload && onNavigate) onNavigate(); }}>
            <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="event_type" width={115} tick={{ fontSize: 11, fill: '#4a5568' }} axisLine={false} tickLine={false} />
            <Tooltip content={<CustomTooltip unit="events" />} />
            <Bar dataKey="count" radius={[0, 3, 3, 0]} cursor={onNavigate ? 'pointer' : 'default'}>
              {data.map((_: any, i: number) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ── Top Denied ────────────────────────────────────────────────
export function TopBlockedDestinations({ hours, onNavigate }: { hours: number; onNavigate?: () => void }) {
  const [denied, setDenied] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-blocked?hours=${hours}`)
      .then(r => r.json()).then(d => setDenied(d.data || [])).catch(() => {});
  }, [hours]);
  const max = denied[0] ? parseInt(denied[0].deny_count) : 1;
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Denied Destinations</div>
      <div style={SUB}>Firewall policy blocks — {hours}h{onNavigate ? ' · Click to investigate' : ''}</div>
      {denied.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#16a34a', fontSize: 12, fontWeight: 500 }}>✓ No policy denies</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {denied.slice(0, 5).map((row, i) => {
            const pct = Math.round((parseInt(row.deny_count) / max) * 100);
            return (
              <div key={i} onClick={() => onNavigate?.()} title={`${row.dst_ip} — ${parseInt(row.deny_count).toLocaleString()} denies`}
                style={{ cursor: onNavigate ? 'pointer' : 'default' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 11, color: '#dc2626', fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 150 }}>
                    {row.dst_ip || '—'}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#dc2626', flexShrink: 0 }}>
                    {parseInt(row.deny_count).toLocaleString()}
                  </span>
                </div>
                <div style={{ height: 5, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: '#dc2626', borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Top Connection Failures ───────────────────────────────────
export function TopConnectionFailures({ hours, onNavigate }: { hours: number; onNavigate?: () => void }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-failures?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const max = data[0] ? parseInt(data[0].fail_count) : 1;
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Connection Failures</div>
      <div style={SUB}>Network unreachable destinations — {hours}h · Hover for details</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#16a34a', fontSize: 12, fontWeight: 500 }}>✓ No failures</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {data.slice(0, 5).map((row, i) => {
            const pct = Math.round((parseInt(row.fail_count) / max) * 100);
            return (
              <div key={i} title={`${row.dst_ip}${row.service ? ` (${row.service})` : ''} — ${parseInt(row.fail_count).toLocaleString()} failures`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
                    <span style={{ fontSize: 11, color: '#ea580c', fontFamily: 'JetBrains Mono, monospace',
                      fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 120 }}>
                      {row.dst_ip || '—'}
                    </span>
                    {row.service && (
                      <span style={{ fontSize: 9, color: '#9ca3af', background: '#f0f2f5',
                        padding: '1px 5px', borderRadius: 4, flexShrink: 0 }}>
                        {row.service}
                      </span>
                    )}
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#ea580c', flexShrink: 0 }}>
                    {parseInt(row.fail_count).toLocaleString()}
                  </span>
                </div>
                <div style={{ height: 5, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: '#ea580c', borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── VPN Status ────────────────────────────────────────────────
export function VPNStatus({ hours, onNavigate }: { hours: number; onNavigate?: () => void }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    fetch(`/api/stats/vpn-summary?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d)).catch(() => {});
  }, [hours]);
  const successRate = data
    ? Math.round((parseInt(data.successes || 0) / Math.max(parseInt(data.total || 1), 1)) * 100)
    : 0;
  return (
    <div style={{ ...CARD, cursor: onNavigate ? 'pointer' : 'default' }}
      onClick={() => onNavigate?.()}
      title="Click to view VPN events in Security tab"
      onMouseEnter={e => { if (onNavigate) (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={TITLE}>VPN Status</div>
      <div style={SUB}>SSL VPN & IPSec — {hours}h · Click to drill down</div>
      {!data ? (
        <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No VPN data</div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 12 }}>
            {[
              { label: 'Total',      value: parseInt(data.total      || 0), color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe', tip: 'Total VPN events' },
              { label: 'Failures',   value: parseInt(data.failures   || 0), color: '#dc2626', bg: '#fef2f2', border: '#fecaca', tip: 'Failed VPN logins' },
              { label: 'SSL Alerts', value: parseInt(data.ssl_alerts || 0), color: '#ea580c', bg: '#fff7ed', border: '#fed7aa', tip: 'SSL handshake errors' },
            ].map(s => (
              <div key={s.label} title={s.tip}
                style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 6, padding: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 700, color: s.color }}>{s.value.toLocaleString()}</div>
                <div style={{ fontSize: 10, color: '#718096', fontWeight: 500, marginTop: 2 }}>{s.label}</div>
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
            <span style={{ fontSize: 12, color: '#4a5568', fontWeight: 500 }}>Success Rate</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: successRate >= 80 ? '#16a34a' : '#dc2626' }}>{successRate}%</span>
          </div>
          <div style={{ height: 6, background: '#f0f2f5', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${successRate}%`, borderRadius: 3,
              background: successRate >= 80 ? '#16a34a' : '#dc2626', transition: 'width 0.5s' }} />
          </div>
          {parseInt(data.ssl_alerts || 0) > 10 && (
            <div style={{ marginTop: 10, padding: '6px 10px', background: '#fff7ed', border: '1px solid #fed7aa',
              borderRadius: 6, fontSize: 11, color: '#92400e' }}>
              ⚠️ High SSL alerts — possible cert/protocol issue
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Active Alerts ─────────────────────────────────────────────
export function ActiveAlertsSummary({ onNavigate }: { onNavigate: () => void }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    fetch('/api/stats/alerts-summary').then(r => r.json()).then(d => setData(d)).catch(() => {});
    const t = setInterval(() => {
      fetch('/api/stats/alerts-summary').then(r => r.json()).then(d => setData(d)).catch(() => {});
    }, 30000);
    return () => clearInterval(t);
  }, []);
  return (
    <div style={{ ...CARD, cursor: 'pointer' }} onClick={onNavigate}
      title="Click to manage alerts"
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={TITLE}>Active Alerts</div>
        <svg width="13" height="13" viewBox="0 0 12 12" fill="none">
          <path d="M6 1L1 10h10L6 1z" stroke="#718096" strokeWidth="1.2" strokeLinejoin="round" fill="none"/>
          <line x1="6" y1="5" x2="6" y2="7.5" stroke="#718096" strokeWidth="1.2" strokeLinecap="round"/>
          <circle cx="6" cy="9" r="0.6" fill="#718096"/>
        </svg>
      </div>
      <div style={{ ...SUB, marginBottom: 10 }}>Click to manage in Alerts tab</div>
      {!data ? <div style={{ color: '#9ca3af', fontSize: 12 }}>Loading...</div> : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div title={`${data.unacknowledged} alerts need attention`}
              style={{ background: data.unacknowledged > 0 ? '#fef2f2' : '#f0fdf4',
                border: `1px solid ${data.unacknowledged > 0 ? '#fecaca' : '#bbf7d0'}`,
                borderRadius: 6, padding: '10px 8px', textAlign: 'center' }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: data.unacknowledged > 0 ? '#dc2626' : '#16a34a' }}>
                {data.unacknowledged}
              </div>
              <div style={{ fontSize: 10, color: '#718096', fontWeight: 600 }}>UNACKED</div>
            </div>
            <div title="Alerts fired in last 24 hours"
              style={{ background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6, padding: '10px 8px', textAlign: 'center' }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#4a5568' }}>{data.total_24h}</div>
              <div style={{ fontSize: 10, color: '#718096', fontWeight: 600 }}>FIRED 24H</div>
            </div>
          </div>
          {data.recent?.map((r: any, i: number) => (
            <div key={i} title={`Fired at ${new Date(r.fired_at).toLocaleString()}`}
              style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderTop: '1px solid #f0f2f5' }}>
              <span style={{ fontSize: 11, color: '#dc2626', fontWeight: 500 }}>{r.rule_name}</span>
              <span style={{ fontSize: 10, color: '#9ca3af', fontFamily: 'JetBrains Mono, monospace' }}>
                {new Date(r.fired_at).toLocaleTimeString()}
              </span>
            </div>
          ))}
          {data.unacknowledged === 0 && data.total_24h === 0 && (
            <div style={{ textAlign: 'center', color: '#16a34a', fontSize: 12, fontWeight: 500 }}>✓ All clear</div>
          )}
        </>
      )}
    </div>
  );
}

// ── Firewall Actions ──────────────────────────────────────────
export function FirewallActions({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/firewall-actions?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const total = data.reduce((s, r) => s + parseInt(r.count), 0) || 1;
  const ACTION_COLORS: Record<string, string> = {
    accept: '#16a34a', deny: '#dc2626', drop: '#dc2626',
    'client-rst': '#ea580c', 'server-rst': '#ea580c',
    close: '#9ca3af', timeout: '#ca8a04', passthrough: '#2563eb',
    'ip-conn': '#7c3aed', dns: '#0891b2', blocked: '#dc2626',
  };
  const ACTION_TIPS: Record<string, string> = {
    'ip-conn':    'TCP connection failed — host unreachable',
    dns:          'DNS resolution failure',
    'ssl-alert':  'SSL/TLS handshake error',
    blocked:      'Blocked by policy',
    deny:         'Explicitly denied by firewall rule',
    accept:       'Allowed through',
    timeout:      'Connection timed out',
    'client-rst': 'Client sent TCP RST',
    'server-rst': 'Server sent TCP RST',
  };
  return (
    <div style={CARD}>
      <div style={TITLE}>Firewall Actions</div>
      <div style={SUB}>Traffic disposition breakdown — {hours}h · Hover for meaning</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
          {data.slice(0, 7).map((row, i) => {
            const pct   = Math.round((parseInt(row.count) / total) * 100);
            const color = ACTION_COLORS[row.action?.toLowerCase()] || '#9ca3af';
            const tip   = ACTION_TIPS[row.action?.toLowerCase()] || row.action;
            return (
              <div key={i} title={`${tip} — ${parseInt(row.count).toLocaleString()} events (${pct}%)`}
                style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                <span style={{ fontSize: 12, color: '#4a5568', fontWeight: 500, minWidth: 85 }}>{row.action}</span>
                <div style={{ flex: 1, height: 5, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
                <span style={{ fontSize: 11, color: '#718096', minWidth: 32, textAlign: 'right' }}>{pct}%</span>
                <span style={{ fontSize: 11, color: '#9ca3af', minWidth: 48, textAlign: 'right' }}>{parseInt(row.count).toLocaleString()}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Interface Events Summary ──────────────────────────────────
export function InterfaceEventsSummary({ hours, onNavigate }: { hours: number; onNavigate: () => void }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    fetch(`/api/health/summary?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d)).catch(() => {});
  }, [hours]);
  const ITEMS = [
    { key: 'interface_events', label: 'Interface Events', warn: 5,  danger: 20, icon: '⇅', tip: 'Link up/down state changes' },
    { key: 'stp_loop_events',  label: 'STP / Loop Events',warn: 1,  danger: 3,  icon: '🔁', tip: 'Spanning tree topology changes — indicates possible loop' },
    { key: 'mac_flap_events',  label: 'MAC Flapping',     warn: 1,  danger: 1,  icon: '⚠️', tip: 'MAC address seen on multiple ports — definitive loop indicator' },
    { key: 'config_changes',   label: 'Config Changes',   warn: 1,  danger: 10, icon: '🔧', tip: 'Device configuration was modified' },
    { key: 'routing_events',   label: 'Routing Events',   warn: 1,  danger: 5,  icon: '⇄',  tip: 'OSPF/BGP/EIGRP neighbor state changes' },
  ];
  return (
    <div style={{ ...CARD, cursor: 'pointer' }} onClick={onNavigate}
      title="Click to open Network Health tab"
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={TITLE}>Network Health</div>
        <svg width="13" height="13" viewBox="0 0 12 12" fill="none">
          <polyline points="1,6 3,3 5,7.5 7,2 9,6 10,4.5 11,6" stroke="#718096" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
        </svg>
      </div>
      <div style={{ ...SUB, marginBottom: 10 }}>Click → Network Health tab · Hover for details</div>
      {!data ? <div style={{ color: '#9ca3af', fontSize: 12 }}>Loading...</div> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {ITEMS.map(item => {
            const value = data[item.key] || 0;
            const color = value >= item.danger ? '#dc2626' : value >= item.warn ? '#ca8a04' : '#16a34a';
            const bg    = value >= item.danger ? '#fef2f2' : value >= item.warn ? '#fefce8' : '#f0fdf4';
            return (
              <div key={item.key} title={item.tip}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '5px 8px', background: bg, borderRadius: 6 }}>
                <span style={{ fontSize: 12, color: '#4a5568' }}>{item.icon} {item.label}</span>
                <span style={{ fontSize: 13, fontWeight: 700, color }}>{value}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
