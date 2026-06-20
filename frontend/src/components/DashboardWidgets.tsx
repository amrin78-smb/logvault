'use client';

import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { GeoInline, KnownBadBadge } from '@/components/ThreatIntel';
import { Trend } from '@/components/Trend';
import type { ExplorerFilter } from '@/app/page';
// `import type` is erased at build time, so this does NOT create a runtime
// circular import even though page.tsx imports this module (mirrors LogExplorer).

const CARD  = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: '16px 20px', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' };
const TITLE = { fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 };
const SUB   = { fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 10 };

// ── Custom tooltip for bar charts ─────────────────────────────
const CustomTooltip = ({ active, payload, label, unit = 'events' }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '8px 12px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)', fontSize: 'var(--text-sm)' }}>
      <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{label}</div>
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, color: p.color }}>
          <div style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
          <span style={{ color: 'var(--text-secondary)' }}>{parseInt(p.value).toLocaleString()} {unit}</span>
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
  const max = data[0] ? parseInt(data[0].count) : 1;
  return (
    <div style={CARD}>
      <div style={TITLE}>Top Security Events</div>
      <div style={SUB}>Most frequent error/warning types — {hours}h · Click to investigate</div>
      {data.length === 0 ? (
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>No data</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {data.slice(0, 6).map((row, i) => {
            const pct   = Math.round((parseInt(row.count) / max) * 100);
            const color = COLORS[i % COLORS.length];
            return (
              <div key={i} onClick={() => onNavigate?.()}
                style={{ cursor: onNavigate ? 'pointer' : 'default' }}
                title={`${row.event_type} — ${parseInt(row.count).toLocaleString()} events`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 500,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>
                    {row.event_type}
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color, flexShrink: 0, marginLeft: 8 }}>
                    {parseInt(row.count).toLocaleString()}
                  </span>
                </div>
                <div style={{ height: 5, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
        </div>
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
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ ...TITLE, flexShrink: 0 }}>Top Blocked Destinations</div>
      <div style={{ ...SUB, flexShrink: 0 }}>Policy denies + UTM/SSL blocks — {hours}h{onNavigate ? ' · Click to investigate' : ''}</div>
      {denied.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#16a34a', fontSize: 'var(--text-sm)', fontWeight: 500 }}>✓ No blocks</div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {denied.slice(0, 5).map((row, i) => {
            const pct = Math.round((parseInt(row.deny_count) / max) * 100);
            return (
              <div key={i} onClick={() => onNavigate?.()}
                title={`${row.dst_ip}${row.service ? ` (${row.service})` : ''} — ${parseInt(row.deny_count).toLocaleString()} blocks`}
                style={{ cursor: onNavigate ? 'pointer' : 'default' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden', minWidth: 0 }}>
                    <span style={{ fontSize: 'var(--text-xs)', color: '#dc2626', fontFamily: 'var(--font-mono)',
                      fontWeight: 500, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 120 }}>
                      {row.dst_ip || '—'}
                    </span>
                    {row.is_known_bad && <KnownBadBadge score={row.abuse_score} compact />}
                    {/* Geo (flag · country · ASN) inline on the same row as the IP to save vertical space */}
                    <GeoInline row={row} />
                    {row.vendor && (
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', background: 'var(--border-light)',
                        padding: '1px 4px', borderRadius: 4, flexShrink: 0, textTransform: 'capitalize' }}>
                        {row.vendor}
                      </span>
                    )}
                  </div>
                  <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#dc2626', flexShrink: 0 }}>
                    {parseInt(row.deny_count).toLocaleString()}
                  </span>
                </div>
                <div style={{ height: 5, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
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
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ ...TITLE, flexShrink: 0 }}>Top Connection Failures</div>
      <div style={{ ...SUB, flexShrink: 0 }}>Network unreachable destinations — {hours}h · Hover for details</div>
      {data.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#16a34a', fontSize: 'var(--text-sm)', fontWeight: 500 }}>✓ No failures</div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {data.slice(0, 5).map((row, i) => {
            const pct = Math.round((parseInt(row.fail_count) / max) * 100);
            return (
              <div key={i} title={`${row.dst_ip}${row.service ? ` (${row.service})` : ''} — ${parseInt(row.fail_count).toLocaleString()} failures`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden', minWidth: 0 }}>
                    <span style={{ fontSize: 'var(--text-xs)', color: '#ea580c', fontFamily: 'var(--font-mono)',
                      fontWeight: 500, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 120 }}>
                      {row.dst_ip || '—'}
                    </span>
                    {/* Geo (flag · country · ASN) inline — shows for external destinations like 8.8.8.8 */}
                    <GeoInline row={row} />
                    {row.service && (
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', background: 'var(--border-light)',
                        padding: '1px 5px', borderRadius: 4, flexShrink: 0 }}>
                        {row.service}
                      </span>
                    )}
                  </div>
                  <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: '#ea580c', flexShrink: 0 }}>
                    {parseInt(row.fail_count).toLocaleString()}
                  </span>
                </div>
                <div style={{ height: 5, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
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
        <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>No VPN data</div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 12 }}>
            {[
              { label: 'Total',      value: parseInt(data.total      || 0), color: 'var(--tint-info-fg)',    bg: 'var(--tint-info)',    border: 'var(--tint-info)',    tip: 'Total VPN events' },
              { label: 'Failures',   value: parseInt(data.failures   || 0), color: 'var(--tint-danger-fg)',  bg: 'var(--tint-danger)',  border: 'var(--tint-danger)',  tip: 'Failed VPN logins' },
              { label: 'SSL Alerts', value: parseInt(data.ssl_alerts || 0), color: 'var(--tint-warn-fg)',    bg: 'var(--tint-warn)',    border: 'var(--tint-warn)',    tip: 'SSL handshake errors' },
            ].map(s => (
              <div key={s.label} title={s.tip}
                style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 6, padding: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: s.color }}>{s.value.toLocaleString()}</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 500, marginTop: 2 }}>{s.label}</div>
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontWeight: 500 }}>Success Rate</span>
            <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: successRate >= 80 ? '#16a34a' : '#dc2626' }}>{successRate}%</span>
          </div>
          <div style={{ height: 6, background: 'var(--border-light)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${successRate}%`, borderRadius: 3,
              background: successRate >= 80 ? '#16a34a' : '#dc2626', transition: 'width 0.5s' }} />
          </div>
          {parseInt(data.ssl_alerts || 0) > 10 && (
            <div style={{ marginTop: 10, padding: '6px 10px', background: 'var(--tint-warn)', border: '1px solid var(--tint-warn)',
              borderRadius: 6, fontSize: 'var(--text-xs)', color: 'var(--tint-warn-fg)' }}>
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
    <div style={{ ...CARD, cursor: 'pointer', height: '100%', boxSizing: 'border-box' }} onClick={onNavigate}
      title="Click to manage alerts"
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={TITLE}>Active Alerts</div>
        <svg width="13" height="13" viewBox="0 0 12 12" fill="none">
          <path d="M6 1L1 10h10L6 1z" stroke="var(--text-muted)" strokeWidth="1.2" strokeLinejoin="round" fill="none"/>
          <line x1="6" y1="5" x2="6" y2="7.5" stroke="var(--text-muted)" strokeWidth="1.2" strokeLinecap="round"/>
          <circle cx="6" cy="9" r="0.6" fill="var(--text-muted)"/>
        </svg>
      </div>
      <div style={{ ...SUB, marginBottom: 10 }}>Click to manage in Alerts tab</div>
      {!data ? <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>Loading...</div> : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div title={`${data.unacknowledged} alerts need attention`}
              style={{ background: data.unacknowledged > 0 ? 'var(--tint-danger)' : 'var(--tint-success)',
                border: `1px solid ${data.unacknowledged > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'}`,
                borderRadius: 6, padding: '10px 8px', textAlign: 'center' }}>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: data.unacknowledged > 0 ? 'var(--tint-danger-fg)' : 'var(--tint-success-fg)' }}>
                {data.unacknowledged}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600 }}>UNACKED</div>
            </div>
            <div title="Alerts fired in last 24 hours"
              style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 8px', textAlign: 'center' }}>
              <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--text-primary)' }}>{data.total_24h}</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600 }}>FIRED 24H</div>
            </div>
          </div>
          {data.recent?.map((r: any, i: number) => (
            <div key={i} title={`Fired at ${new Date(r.fired_at).toLocaleString()}`}
              style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderTop: '1px solid var(--border-light)' }}>
              <span style={{ fontSize: 'var(--text-xs)', color: '#dc2626', fontWeight: 500 }}>{r.rule_name}</span>
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {new Date(r.fired_at).toLocaleTimeString()}
              </span>
            </div>
          ))}
          {data.unacknowledged === 0 && data.total_24h === 0 && (
            <div style={{ textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-sm)', fontWeight: 500 }}>✓ All clear</div>
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
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>No data</div>
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
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontWeight: 500, minWidth: 85 }}>{row.action}</span>
                <div style={{ flex: 1, height: 5, background: 'var(--border-light)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', minWidth: 32, textAlign: 'right' }}>{pct}%</span>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', minWidth: 48, textAlign: 'right' }}>{parseInt(row.count).toLocaleString()}</span>
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
    <div style={{ ...CARD, cursor: 'pointer', height: '100%', boxSizing: 'border-box' }} onClick={onNavigate}
      title="Click to open Network Health tab"
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={TITLE}>Network Health</div>
        <svg width="13" height="13" viewBox="0 0 12 12" fill="none">
          <polyline points="1,6 3,3 5,7.5 7,2 9,6 10,4.5 11,6" stroke="var(--text-muted)" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
        </svg>
      </div>
      <div style={{ ...SUB, marginBottom: 10 }}>Click → Network Health tab · Hover for details</div>
      {!data ? <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>Loading...</div> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {ITEMS.map(item => {
            const value = data[item.key] || 0;
            const color = value >= item.danger ? '#dc2626' : value >= item.warn ? '#ca8a04' : '#16a34a';
            // Semi-transparent status tints layer correctly over both the light
            // (#fff) and dark (#1a2235) card surfaces, so the row stays readable
            // in dark mode. Healthy (0) rows use a neutral adaptive surface.
            const bg    = value >= item.danger ? 'rgba(220,38,38,0.12)'
                        : value >= item.warn  ? 'rgba(202,138,4,0.12)'
                        : 'var(--bg-primary)';
            return (
              <div key={item.key} title={item.tip}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '5px 8px', background: bg, borderRadius: 6 }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{item.icon} {item.label}</span>
                <span style={{ fontSize: 'var(--text-base)', fontWeight: 700, color }}>{value}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Capacity & Ingestion Health ───────────────────────────────
// Reads /api/stats/forecast — surfaces volume trend, today's ingestion vs the
// daily average (with a spike flag), and "silent" devices that have stopped
// logging. Forecast numbers are real JS numbers, so we Number()-guard rather
// than parseInt (which would silently mangle non-string input).
interface ForecastVolume {
  daily?: { date: string; count: number }[];
  slope?: number;
  projected_next_30d_total?: number;
  status?: 'growing' | 'steady' | 'declining';
  confidence?: 'low' | 'medium' | 'high';
}
interface ForecastIngestion { today?: number; avg_daily?: number; spike?: boolean; }
interface SilentDevice { source_host?: string; source_ip?: string; prior_count?: number; last_seen?: string; }
interface ForecastData { volume?: ForecastVolume; ingestion?: ForecastIngestion; silent?: SilentDevice[]; }

const STATUS_META: Record<string, { label: string; bg: string; fg: string }> = {
  growing:   { label: 'Growing',   bg: 'var(--tint-info)',      fg: 'var(--tint-info-fg)' },
  steady:    { label: 'Steady',    bg: 'var(--surface-subtle)', fg: 'var(--text-secondary)' },
  declining: { label: 'Declining', bg: 'var(--tint-warn)',      fg: 'var(--tint-warn-fg)' },
};

// Tiny inline-SVG sparkline from the daily volume series. Returns null when
// there's not enough data to draw a line.
function Sparkline({ points }: { points: number[] }) {
  if (!points || points.length < 2) return null;
  const w = 120, h = 28;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const coords = points.map((v, i) => {
    const x = (i / (points.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <polyline points={coords} fill="none" stroke="var(--tint-info-fg)" strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function CapacityIngestionHealth({ openExplorer }: { openExplorer?: (filter: ExplorerFilter) => void }) {
  const [data, setData] = useState<ForecastData | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch('/api/stats/forecast?days=30')
      .then(r => r.json())
      .then(d => { setData(d || null); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const ingestion = data?.ingestion || {};
  const volume = data?.volume || {};
  const silent = Array.isArray(data?.silent) ? data!.silent : [];
  const today = Number(ingestion.today) || 0;
  const avgDaily = Number(ingestion.avg_daily) || 0;
  const spike = Boolean(ingestion.spike);
  const projected = Number(volume.projected_next_30d_total) || 0;
  const statusKey = volume.status && STATUS_META[volume.status] ? volume.status : 'steady';
  const statusMeta = STATUS_META[statusKey];
  const sparkPoints = Array.isArray(volume.daily) ? volume.daily.map(d => Number(d?.count) || 0) : [];

  return (
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ ...TITLE, flexShrink: 0 }}>Capacity & Ingestion Health</div>
      <div style={{ ...SUB, flexShrink: 0 }}>Volume forecast, ingestion rate & silent devices</div>
      {loading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>Loading...</div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 4, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Headline: today vs avg + spike badge */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.1 }}>
                  {today.toLocaleString()}
                </span>
                <Trend value={today} prev={avgDaily} invert />
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
                logs today · avg {avgDaily.toLocaleString()}/day
              </div>
            </div>
            {spike && (
              <span style={{ flexShrink: 0, fontSize: 'var(--text-xs)', fontWeight: 700, padding: '3px 8px',
                borderRadius: 6, background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' }}>
                ⚠ Ingestion spike
              </span>
            )}
          </div>

          {/* Volume trend: status + confidence + 30d projection + sparkline */}
          <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontWeight: 600 }}>Volume trend</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, padding: '2px 7px', borderRadius: 5,
                  background: statusMeta.bg, color: statusMeta.fg }}>{statusMeta.label}</span>
                {volume.confidence && (
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                    {volume.confidence} confidence
                  </span>
                )}
              </span>
            </div>
            {sparkPoints.length >= 2 && <Sparkline points={sparkPoints} />}
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 6 }}>
              Projected next 30d: <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{projected.toLocaleString()}</span> logs
            </div>
          </div>

          {/* Silent devices — high-value: devices that historically logged but went quiet */}
          <div>
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--tint-warn-fg)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
              Silent devices (stopped logging)
            </div>
            {silent.length === 0 ? (
              <div style={{ fontSize: 'var(--text-sm)', color: '#16a34a', fontWeight: 500 }}>✓ All known devices are logging</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {silent.slice(0, 8).map((d, i) => {
                  const label = d.source_host || d.source_ip || '—';
                  const drill = d.source_ip || d.source_host;
                  const prior = Number(d.prior_count) || 0;
                  return (
                    <div key={i} onClick={() => { if (openExplorer && drill) openExplorer({ host: drill }); }}
                      title={`${label} — normally ${prior.toLocaleString()} logs · last seen ${d.last_seen || 'unknown'}`}
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                        padding: '5px 8px', background: 'rgba(217,119,6,0.12)', borderRadius: 6,
                        cursor: openExplorer && drill ? 'pointer' : 'default' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontWeight: 600,
                          fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {label}
                        </span>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          last seen {d.last_seen || 'unknown'}
                        </span>
                      </div>
                      <span style={{ flexShrink: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                        normally {prior.toLocaleString()}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── What's New / Changed ──────────────────────────────────────
// Reads /api/stats/whats-changed — values seen in the last day but NOT in the
// prior 30 days, grouped into four compact sections. Drillable into the Log
// Explorer (new source → host filter; users/services/countries → free-text q).
interface ChangeRow { value: string; count: number; }
interface WhatsChangedData {
  window_days?: number;
  new_countries?: ChangeRow[];
  new_users?: ChangeRow[];
  new_sources?: ChangeRow[];
  new_services?: ChangeRow[];
}

function ChangeSection({ title, rows, drill }:
  { title: string; rows: ChangeRow[]; drill?: (value: string) => void }) {
  const list = Array.isArray(rows) ? rows : [];
  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
        {title}
      </div>
      {list.length === 0 ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontStyle: 'italic' }}>nothing new</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {list.slice(0, 8).map((row, i) => {
            const value = row?.value ?? '—';
            const count = Number(row?.count) || 0;
            return (
              <div key={i} onClick={() => { if (drill && row?.value) drill(row.value); }}
                title={`${value} — ${count.toLocaleString()} events`}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                  padding: '3px 6px', background: 'var(--surface-subtle)', borderRadius: 5,
                  cursor: drill && row?.value ? 'pointer' : 'default' }}>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontWeight: 500,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
                  {value}
                </span>
                <span style={{ flexShrink: 0, fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--tint-info-fg)' }}>
                  {count.toLocaleString()}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function WhatsChanged({ openExplorer }: { openExplorer?: (filter: ExplorerFilter) => void }) {
  const [data, setData] = useState<WhatsChangedData | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch('/api/stats/whats-changed?days=1')
      .then(r => r.json())
      .then(d => { setData(d || null); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const windowDays = Number(data?.window_days) || 1;
  return (
    <div style={{ ...CARD, height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ ...TITLE, flexShrink: 0 }}>What&apos;s New / Changed</div>
      <div style={{ ...SUB, flexShrink: 0 }}>First seen in the last {windowDays}d (not in the prior 30d) · Click to investigate</div>
      {loading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>Loading...</div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 4,
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px 16px', alignContent: 'start' }}>
          <ChangeSection title="New Countries" rows={data?.new_countries || []}
            drill={openExplorer ? (v) => openExplorer({ q: v }) : undefined} />
          <ChangeSection title="New Accounts" rows={data?.new_users || []}
            drill={openExplorer ? (v) => openExplorer({ q: v }) : undefined} />
          <ChangeSection title="New Sources" rows={data?.new_sources || []}
            drill={openExplorer ? (v) => openExplorer({ host: v }) : undefined} />
          <ChangeSection title="New Services" rows={data?.new_services || []}
            drill={openExplorer ? (v) => openExplorer({ q: v }) : undefined} />
        </div>
      )}
    </div>
  );
}
