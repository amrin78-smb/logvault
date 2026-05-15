'use client';

import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const CARD  = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: '14px 16px' };
const TITLE = { fontSize: 13, fontWeight: 600, color: '#1a202c', marginBottom: 2 };
const SUB   = { fontSize: 11, color: '#9ca3af', marginBottom: 10 };

// ── Top Security Events ───────────────────────────────────────
export function TopSecurityEvents({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-security-events?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const COLORS = ['#dc2626','#ea580c','#ca8a04','#7c3aed','#0891b2','#16a34a','#475569'];
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Security Events</div>
      <div style={SUB}>Most frequent error/warning types — {hours}h</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>
      ) : (
        <ResponsiveContainer width="100%" height={140}>
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 36, left: 0, bottom: 0 }}>
            <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="event_type" width={115} tick={{ fontSize: 11, fill: '#4a5568' }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6, fontSize: 12 }}
              formatter={(v: any) => [v.toLocaleString(), 'Count']} />
            <Bar dataKey="count" radius={[0, 3, 3, 0]}>
              {data.map((_: any, i: number) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ── Top Blocked Destinations ──────────────────────────────────
export function TopBlockedDestinations({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-blocked?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const max = data[0] ? parseInt(data[0].deny_count) : 1;
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Blocked Destinations</div>
      <div style={SUB}>Most denied IPs/services — {hours}h</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No blocked traffic</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
          {data.slice(0, 5).map((row, i) => {
            const pct = Math.round((parseInt(row.deny_count) / max) * 100);
            return (
              <div key={i}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 11, color: '#dc2626', fontFamily: 'JetBrains Mono, monospace', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 150 }}>
                    {row.dst_ip || '—'}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#ea580c', flexShrink: 0 }}>{parseInt(row.deny_count).toLocaleString()}</span>
                </div>
                <div style={{ height: 5, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: '#dc2626', borderRadius: 2 }} />
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
export function VPNStatus({ hours }: { hours: number }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    fetch(`/api/stats/vpn-summary?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d)).catch(() => {});
  }, [hours]);
  const successRate = data
    ? Math.round((parseInt(data.successes || 0) / Math.max(parseInt(data.total || 1), 1)) * 100)
    : 0;
  return (
    <div style={CARD}>
      <div style={TITLE}>VPN Status</div>
      <div style={SUB}>SSL VPN & IPSec activity — {hours}h</div>
      {!data ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No VPN data</div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 12 }}>
            {[
              { label: 'Total',     value: parseInt(data.total      || 0).toLocaleString(), color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe' },
              { label: 'Failures',  value: parseInt(data.failures   || 0).toLocaleString(), color: '#dc2626', bg: '#fef2f2', border: '#fecaca' },
              { label: 'SSL Alerts',value: parseInt(data.ssl_alerts || 0).toLocaleString(), color: '#ea580c', bg: '#fff7ed', border: '#fed7aa' },
            ].map(s => (
              <div key={s.label} style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 6, padding: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 700, color: s.color }}>{s.value}</div>
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
              background: successRate >= 80 ? '#16a34a' : '#dc2626' }} />
          </div>
          {parseInt(data.ssl_alerts || 0) > 10 && (
            <div style={{ marginTop: 10, padding: '6px 10px', background: '#fff7ed', border: '1px solid #fed7aa',
              borderRadius: 6, fontSize: 11, color: '#92400e' }}>
              ⚠️ High SSL alerts — possible cert issue
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
      <div style={{ ...SUB, marginBottom: 10 }}>Click → Alerts tab</div>
      {!data ? <div style={{ color: '#9ca3af', fontSize: 12 }}>Loading...</div> : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div style={{ background: data.unacknowledged > 0 ? '#fef2f2' : '#f0fdf4',
              border: `1px solid ${data.unacknowledged > 0 ? '#fecaca' : '#bbf7d0'}`,
              borderRadius: 6, padding: '10px 8px', textAlign: 'center' }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: data.unacknowledged > 0 ? '#dc2626' : '#16a34a' }}>
                {data.unacknowledged}
              </div>
              <div style={{ fontSize: 10, color: '#718096', fontWeight: 600 }}>UNACKED</div>
            </div>
            <div style={{ background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 6, padding: '10px 8px', textAlign: 'center' }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#4a5568' }}>{data.total_24h}</div>
              <div style={{ fontSize: 10, color: '#718096', fontWeight: 600 }}>FIRED 24H</div>
            </div>
          </div>
          {data.recent?.map((r: any, i: number) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderTop: '1px solid #f0f2f5' }}>
              <span style={{ fontSize: 11, color: '#dc2626', fontWeight: 500 }}>{r.rule_name}</span>
              <span style={{ fontSize: 10, color: '#9ca3af', fontFamily: 'JetBrains Mono, monospace' }}>
                {new Date(r.fired_at).toLocaleTimeString()}
              </span>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ── Top Services ──────────────────────────────────────────────
export function TopServices({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);
  useEffect(() => {
    fetch(`/api/stats/top-services?hours=${hours}`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);
  const COLORS = ['#2563eb','#7c3aed','#0891b2','#16a34a','#ca8a04','#ea580c','#9ca3af'];
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Services</div>
      <div style={SUB}>Most active protocols — {hours}h</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {data.slice(0, 6).map((row, i) => {
            const max = parseInt(data[0].count);
            const pct = Math.round((parseInt(row.count) / max) * 100);
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 12, color: '#4a5568', fontWeight: 500, minWidth: 105, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {row.service}
                </span>
                <div style={{ flex: 1, height: 5, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: COLORS[i % COLORS.length], borderRadius: 2 }} />
                </div>
                <span style={{ fontSize: 12, color: '#718096', fontWeight: 600, minWidth: 45, textAlign: 'right' }}>
                  {parseInt(row.count).toLocaleString()}
                </span>
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
  return (
    <div style={{ ...CARD, cursor: 'pointer' }} onClick={onNavigate}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={TITLE}>Network Health</div>
        <svg width="13" height="13" viewBox="0 0 12 12" fill="none">
          <polyline points="1,6 3,3 5,7.5 7,2 9,6 10,4.5 11,6" stroke="#718096" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
        </svg>
      </div>
      <div style={{ ...SUB, marginBottom: 10 }}>Click → Network Health tab</div>
      {!data ? <div style={{ color: '#9ca3af', fontSize: 12 }}>Loading...</div> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {[
            { label: 'Interface Events', value: data.interface_events, warn: 5,  danger: 20, icon: '⇅' },
            { label: 'STP / Loop Events',value: data.stp_loop_events,  warn: 1,  danger: 3,  icon: '🔁' },
            { label: 'MAC Flapping',     value: data.mac_flap_events,   warn: 1,  danger: 1,  icon: '⚠️' },
            { label: 'Config Changes',   value: data.config_changes,    warn: 1,  danger: 10, icon: '🔧' },
            { label: 'Routing Events',   value: data.routing_events,    warn: 1,  danger: 5,  icon: '⇄' },
          ].map(item => {
            const color = item.value >= item.danger ? '#dc2626' : item.value >= item.warn ? '#ca8a04' : '#16a34a';
            const bg    = item.value >= item.danger ? '#fef2f2' : item.value >= item.warn ? '#fefce8' : '#f0fdf4';
            return (
              <div key={item.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '6px 10px', background: bg, borderRadius: 6 }}>
                <span style={{ fontSize: 12, color: '#4a5568' }}>{item.icon} {item.label}</span>
                <span style={{ fontSize: 13, fontWeight: 700, color }}>{item.value}</span>
              </div>
            );
          })}
        </div>
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
  return (
    <div style={CARD}>
      <div style={TITLE}>Firewall Actions</div>
      <div style={SUB}>Traffic disposition — {hours}h</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>No data</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
          {data.slice(0, 7).map((row, i) => {
            const pct   = Math.round((parseInt(row.count) / total) * 100);
            const color = ACTION_COLORS[row.action?.toLowerCase()] || '#9ca3af';
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                <span style={{ fontSize: 12, color: '#4a5568', fontWeight: 500, minWidth: 85 }}>{row.action}</span>
                <div style={{ flex: 1, height: 5, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }} />
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
