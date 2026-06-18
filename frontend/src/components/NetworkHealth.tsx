'use client';

import { useEffect, useState, useCallback } from 'react';
import { PageHeader, TableSkeleton, CardSkeleton, EmptyState } from './ui';

// ── Shared styles ─────────────────────────────────────────────
const CARD  = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 16 };
const TH    = { padding: '8px 12px', textAlign: 'left' as const, color: 'var(--text-muted)', fontWeight: 600, fontSize: 'var(--text-xs)' };
const TD    = { padding: '9px 12px', fontSize: 'var(--text-sm)' };
const MONO  = { fontFamily: 'var(--font-mono)' };

// ── Severity badge ────────────────────────────────────────────
function SevBadge({ label }: { label: string }) {
  const s: Record<string, { bg: string; color: string; border: string }> = {
    emergency: { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
    alert:     { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
    critical:  { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
    error:     { bg: '#fff7ed', color: '#ea580c', border: '#fed7aa' },
    warning:   { bg: '#fefce8', color: '#ca8a04', border: '#fde68a' },
    notice:    { bg: '#eff6ff', color: '#2563eb', border: '#bfdbfe' },
    info:      { bg: '#f0fdf4', color: '#16a34a', border: '#bbf7d0' },
  };
  const style = s[label] || s.info;
  return (
    <span style={{ padding: '2px 7px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 700,
      background: style.bg, color: style.color, border: `1px solid ${style.border}`,
      textTransform: 'uppercase', letterSpacing: '0.4px' }}>
      {label}
    </span>
  );
}

// ── Status pill ───────────────────────────────────────────────
function StatusPill({ value, label, warn = 1, danger = 5, inverse = false }: {
  value: number; label: string; warn?: number; danger?: number; inverse?: boolean;
}) {
  let bg = '#f0fdf4'; let color = '#16a34a'; let border = '#bbf7d0';
  if (!inverse) {
    if (value >= danger) { bg = '#fef2f2'; color = '#dc2626'; border = '#fecaca'; }
    else if (value >= warn) { bg = '#fefce8'; color = '#ca8a04'; border = '#fde68a'; }
  }
  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 8,
      padding: '14px 16px', textAlign: 'center' as const }}>
      <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
    </div>
  );
}

// ── Link state badge ──────────────────────────────────────────
function LinkBadge({ state }: { state: string }) {
  if (state === 'up')   return <span style={{ color: '#16a34a', fontWeight: 700, fontSize: 'var(--text-xs)' }}>▲ UP</span>;
  if (state === 'down') return <span style={{ color: '#dc2626', fontWeight: 700, fontSize: 'var(--text-xs)' }}>▼ DOWN</span>;
  return <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>{state || '—'}</span>;
}

// ── Subcategory badge ─────────────────────────────────────────
function SubcatBadge({ sub }: { sub: string }) {
  const map: Record<string, { color: string; bg: string; label: string }> = {
    mac_flap:        { color: '#dc2626', bg: '#fef2f2', label: '⚠ MAC Flap' },
    storm_control:   { color: '#dc2626', bg: '#fef2f2', label: '⚡ Storm' },
    storm_shutdown:  { color: '#7c3aed', bg: '#f5f3ff', label: '🛑 Shutdown' },
    topology_change: { color: '#ea580c', bg: '#fff7ed', label: '🔄 Topology' },
    root_change:     { color: '#ea580c', bg: '#fff7ed', label: '👑 Root Change' },
    loop_detected:   { color: '#dc2626', bg: '#fef2f2', label: '🔁 Loop' },
    port_removed:    { color: '#ca8a04', bg: '#fefce8', label: 'Port Removed' },
    role_change:     { color: '#2563eb', bg: '#eff6ff', label: 'Role Change' },
    port_blocked:    { color: '#ca8a04', bg: '#fefce8', label: 'Port Blocked' },
    ospf_neighbor:   { color: '#7c3aed', bg: '#f5f3ff', label: 'OSPF' },
    bgp_neighbor:    { color: '#7c3aed', bg: '#f5f3ff', label: 'BGP' },
    eigrp_neighbor:  { color: '#7c3aed', bg: '#f5f3ff', label: 'EIGRP' },
  };
  const s = map[sub] || { color: '#718096', bg: '#f8f9fb', label: sub };
  return (
    <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)', fontWeight: 600,
      color: s.color, background: s.bg, border: `1px solid ${s.color}33` }}>
      {s.label}
    </span>
  );
}

// ── Main Component ────────────────────────────────────────────
export default function NetworkHealth({ hours }: { hours: number }) {
  const [summary,       setSummary]       = useState<any>(null);
  const [deviceStatus,  setDeviceStatus]  = useState<any[]>([]);
  const [flaps,         setFlaps]         = useState<any[]>([]);
  const [stpEvents,     setStpEvents]     = useState<any[]>([]);
  const [macFlaps,      setMacFlaps]      = useState<any[]>([]);
  const [configChanges, setConfigChanges] = useState<any[]>([]);
  const [routing,       setRouting]       = useState<any[]>([]);
  const [interfaces,    setInterfaces]    = useState<any[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [activeSection, setActiveSection] = useState<string>('overview');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, d, f, stp, mac, cfg, rt, iface] = await Promise.all([
        fetch(`/api/health/summary?hours=${hours}`).then(r => r.json()),
        fetch(`/api/health/device-status`).then(r => r.json()),
        fetch(`/api/health/flaps?hours=${hours}`).then(r => r.json()),
        fetch(`/api/health/stp?hours=${hours}`).then(r => r.json()),
        fetch(`/api/health/macflaps?hours=${hours}`).then(r => r.json()),
        fetch(`/api/health/config-changes?hours=${hours}`).then(r => r.json()),
        fetch(`/api/health/routing?hours=${hours}`).then(r => r.json()),
        fetch(`/api/health/interfaces?hours=${hours}`).then(r => r.json()),
      ]);
      setSummary(s);
      setDeviceStatus(d.data || []);
      setFlaps(f.data || []);
      setStpEvents(stp.data || []);
      setMacFlaps(mac.data || []);
      setConfigChanges(cfg.data || []);
      setRouting(rt.data || []);
      setInterfaces(iface.data || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [hours]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const SECTIONS = [
    { id: 'overview',   label: 'Overview',          alert: false },
    { id: 'devices',    label: 'Device Status',      alert: deviceStatus.some(d => parseFloat(d.minutes_since_last_log) > 60) },
    { id: 'interfaces', label: 'Interface Events',   alert: (summary?.interface_events || 0) > 0 },
    { id: 'stp',        label: 'STP / Loop',         alert: (summary?.stp_loop_events || 0) > 0 },
    { id: 'macflaps',   label: 'MAC Flapping',       alert: (summary?.mac_flap_events || 0) > 0 },
    { id: 'routing',    label: 'Routing Events',     alert: (summary?.routing_events || 0) > 0 },
    { id: 'config',     label: 'Config Changes',     alert: (summary?.config_changes || 0) > 0 },
  ];

  return (
    <div>
      <PageHeader title="Network Health" subtitle="Interface events, link state and device connectivity" />

      {/* Section nav */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: 8, padding: 6, flexWrap: 'wrap' }}>
        {SECTIONS.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            style={{ padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 'var(--text-sm)', fontWeight: activeSection === s.id ? 600 : 400,
              background: activeSection === s.id ? '#1a202c' : 'transparent',
              color: activeSection === s.id ? '#fff' : 'var(--text-muted)',
              display: 'flex', alignItems: 'center', gap: 5, transition: 'all 0.15s' }}>
            {s.alert && activeSection !== s.id && (
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#dc2626',
                display: 'inline-block', boxShadow: '0 0 4px #dc2626' }} />
            )}
            {s.label}
          </button>
        ))}
        <button onClick={fetchAll} style={{ marginLeft: 'auto', padding: '6px 12px', borderRadius: 6,
          border: '1px solid var(--border)', cursor: 'pointer', fontSize: 'var(--text-xs)', background: '#f8f9fb', color: 'var(--text-muted)' }}>
          ↻ Refresh
        </button>
      </div>

      {loading ? (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            <CardSkeleton count={4} />
          </div>
          <div style={CARD}>
            <TableSkeleton rows={8} cols={5} />
          </div>
        </>
      ) : (
        <>
          {/* ── OVERVIEW ── */}
          {activeSection === 'overview' && summary && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 20 }}>
                <StatusPill value={summary.interface_events} label="Interface Events" warn={1} danger={10} />
                <StatusPill value={summary.stp_loop_events}  label="STP / Loop Events" warn={1} danger={3} />
                <StatusPill value={summary.mac_flap_events}  label="MAC Flap Events" warn={1} danger={1} />
                <StatusPill value={summary.config_changes}   label="Config Changes" warn={1} danger={10} />
                <StatusPill value={summary.routing_events}   label="Routing Events" warn={1} danger={5} />
              </div>

              {/* Loop/STP warning banner */}
              {(summary.mac_flap_events > 0 || summary.stp_loop_events > 0) && (
                <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8,
                  padding: '14px 20px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 'var(--text-xl)' }}>⚠️</span>
                  <div>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#dc2626' }}>
                      Possible Network Loop Detected
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: '#991b1b', marginTop: 2 }}>
                      {summary.mac_flap_events > 0 && `${summary.mac_flap_events} MAC flapping event(s) detected. `}
                      {summary.stp_loop_events > 0  && `${summary.stp_loop_events} STP/loop event(s) detected. `}
                      Check the STP/Loop and MAC Flapping sections immediately.
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('stp')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid #fecaca',
                      cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600, background: '#fff', color: '#dc2626' }}>
                    Investigate →
                  </button>
                </div>
              )}

              {/* Config changes warning */}
              {summary.config_changes > 0 && (
                <div style={{ background: '#fefce8', border: '1px solid #fde68a', borderRadius: 8,
                  padding: '14px 20px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 'var(--text-xl)' }}>🔧</span>
                  <div>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: '#ca8a04' }}>
                      {summary.config_changes} Configuration Change(s) in Last {hours}h
                    </div>
                    <div style={{ fontSize: 'var(--text-sm)', color: '#92400e', marginTop: 2 }}>
                      Network device configurations were modified. Review the Config Changes section.
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('config')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid #fde68a',
                      cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600, background: '#fff', color: '#ca8a04' }}>
                    Review →
                  </button>
                </div>
              )}

              {/* Quick device status */}
              <div style={CARD}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Device Status at a Glance</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>Devices that have sent logs in the last 24 hours</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
                  {deviceStatus.slice(0, 12).map((d, i) => {
                    const mins    = parseFloat(d.minutes_since_last_log);
                    const silent  = mins > 60;
                    const warning = mins > 15 && mins <= 60;
                    const bg      = silent ? '#fef2f2' : warning ? '#fefce8' : '#f0fdf4';
                    const border  = silent ? '#fecaca' : warning ? '#fde68a' : '#bbf7d0';
                    const dot     = silent ? '#dc2626'  : warning ? '#ca8a04'  : '#16a34a';
                    return (
                      <div key={i} style={{ background: bg, border: `1px solid ${border}`,
                        borderRadius: 8, padding: '10px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
                          <div style={{ width: 8, height: 8, borderRadius: '50%', background: dot,
                            boxShadow: silent ? 'none' : `0 0 5px ${dot}`, flexShrink: 0 }} />
                          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)',
                            ...MONO, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {d.host}
                          </span>
                        </div>
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ textTransform: 'capitalize' }}>{d.known_vendor || d.vendor}</span>
                          <span>{mins < 1 ? 'Just now' : mins < 60 ? `${Math.round(mins)}m ago` : `${Math.round(mins/60)}h ago`}</span>
                        </div>
                        {(parseInt(d.critical_24h) > 0 || parseInt(d.error_24h) > 0) && (
                          <div style={{ marginTop: 6, display: 'flex', gap: 4 }}>
                            {parseInt(d.critical_24h) > 0 && (
                              <span style={{ fontSize: 'var(--text-xs)', color: '#dc2626', background: '#fef2f2', padding: '1px 5px', borderRadius: 8 }}>
                                {d.critical_24h} crit
                              </span>
                            )}
                            {parseInt(d.error_24h) > 0 && (
                              <span style={{ fontSize: 'var(--text-xs)', color: '#ea580c', background: '#fff7ed', padding: '1px 5px', borderRadius: 8 }}>
                                {d.error_24h} err
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* ── DEVICE STATUS ── */}
          {activeSection === 'devices' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Device Status</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Last log received per device — red = silent &gt;60min, yellow = silent &gt;15min
              </div>
              {deviceStatus.length === 0 ? (
                <EmptyState title="No data" message="No network health events for the selected time range." />
              ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                    {['Status','Device','Vendor','Last Seen','Logs 1h','Logs 24h','Crit 24h','Err 24h'].map(h => (
                      <th key={h} style={TH}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {deviceStatus.map((d, i) => {
                    const mins   = parseFloat(d.minutes_since_last_log);
                    const silent = mins > 60;
                    const warn   = mins > 15 && !silent;
                    const dot    = silent ? '#dc2626' : warn ? '#ca8a04' : '#16a34a';
                    return (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-light)',
                        background: silent ? '#fff8f8' : warn ? '#fffef0' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)' }}>
                        <td style={TD}>
                          <div style={{ width: 10, height: 10, borderRadius: '50%', background: dot,
                            boxShadow: silent ? 'none' : `0 0 5px ${dot}` }} />
                        </td>
                        <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{d.host}</td>
                        <td style={{ ...TD, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{d.known_vendor || d.vendor}</td>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: silent ? '#dc2626' : 'var(--text-muted)' }}>
                          {new Date(d.last_seen).toLocaleString()}
                        </td>
                        <td style={{ ...TD, color: 'var(--text-secondary)', fontWeight: 600 }}>{d.logs_1h}</td>
                        <td style={{ ...TD, color: 'var(--text-secondary)' }}>{d.logs_24h}</td>
                        <td style={{ ...TD, color: parseInt(d.critical_24h) > 0 ? '#dc2626' : 'var(--text-muted)', fontWeight: 600 }}>{d.critical_24h}</td>
                        <td style={{ ...TD, color: parseInt(d.error_24h) > 0 ? '#ea580c' : 'var(--text-muted)' }}>{d.error_24h}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              )}
            </div>
          )}

          {/* ── INTERFACE EVENTS ── */}
          {activeSection === 'interfaces' && (
            <>
              {/* Flap summary */}
              {flaps.length > 0 && (
                <div style={CARD}>
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Interface Flap Summary</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                    Interfaces that changed state multiple times — high flap count indicates physical layer issues
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                        {['Device','Interface','Total Events','↓ Down','↑ Up','First Seen','Last Seen'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {flaps.map((f, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--border-light)',
                          background: parseInt(f.event_count) >= 6 ? '#fff8f8' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)' }}>
                          <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{f.host}</td>
                          <td style={{ ...TD, ...MONO, color: '#2563eb' }}>{f.interface || '—'}</td>
                          <td style={{ ...TD }}>
                            <span style={{ fontWeight: 700, color: parseInt(f.event_count) >= 6 ? '#dc2626' : 'var(--text-secondary)',
                              background: parseInt(f.event_count) >= 6 ? '#fef2f2' : 'var(--border-light)',
                              padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)' }}>
                              {f.event_count}
                            </span>
                          </td>
                          <td style={{ ...TD, color: '#dc2626', fontWeight: 600 }}>{f.down_count}</td>
                          <td style={{ ...TD, color: '#16a34a', fontWeight: 600 }}>{f.up_count}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(f.first_seen).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(f.last_seen).toLocaleTimeString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* All interface events */}
              <div style={CARD}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Interface Event Log</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>All interface state changes</div>
                {interfaces.length === 0 ? (
                  <EmptyState title="No data" message="No network health events for the selected time range." />
                ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                      {['Time','Device','Interface','State','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {interfaces.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-light)', background: i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)' }}>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                        <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{r.source_host || r.source_ip}</td>
                        <td style={{ ...TD, ...MONO, color: '#2563eb' }}>{r.interface || '—'}</td>
                        <td style={TD}><LinkBadge state={r.link_state} /></td>
                        <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                )}
              </div>
            </>
          )}

          {/* ── STP / LOOP ── */}
          {activeSection === 'stp' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>STP &amp; Loop Events</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Spanning Tree topology changes, root bridge changes, loop detection, storm control events
              </div>

              {stpEvents.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>
                  ✓ No STP or loop events detected in this period
                </div>
              ) : (
                <>
                  <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8,
                    padding: '12px 16px', marginBottom: 16, fontSize: 'var(--text-sm)', color: '#991b1b' }}>
                    <strong>⚠️ {stpEvents.length} STP/loop event(s) detected.</strong> Topology changes can cause temporary network outages.
                    MAC flapping (if present) indicates an active loop. Isolate the affected switch port immediately.
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                        {['Time','Device','Severity','Event Type','Interface','MAC','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {stpEvents.map((r, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--border-light)',
                          background: ['mac_flap','storm_control','loop_detected'].includes(r.subcategory) ? '#fff8f8' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)' }}>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{r.source_host || r.source_ip}</td>
                          <td style={TD}><SevBadge label={r.severity_label} /></td>
                          <td style={TD}><SubcatBadge sub={r.subcategory} /></td>
                          <td style={{ ...TD, ...MONO, color: '#2563eb', fontSize: 'var(--text-xs)' }}>{r.interface || '—'}</td>
                          <td style={{ ...TD, ...MONO, color: '#7c3aed', fontSize: 'var(--text-xs)' }}>{r.mac_address || '—'}</td>
                          <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          )}

          {/* ── MAC FLAPPING ── */}
          {activeSection === 'macflaps' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>MAC Address Flapping</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                MAC addresses learned on multiple ports — definitive indicator of a network loop
              </div>

              {macFlaps.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>
                  ✓ No MAC flapping detected — no active loops
                </div>
              ) : (
                <>
                  <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8,
                    padding: '12px 16px', marginBottom: 16, fontSize: 'var(--text-sm)', color: '#991b1b' }}>
                    <strong>🔴 Active loop suspected.</strong> MAC flapping means the same MAC address is being seen on multiple switch ports simultaneously.
                    This happens when frames are looping through the network. Identify the affected switch and ports, then disable the offending port.
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                        {['Switch','MAC Address','Flap Count','Affected Ports','First Seen','Last Seen'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {macFlaps.map((r, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--border-light)', background: '#fff8f8' }}>
                          <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{r.host}</td>
                          <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 700 }}>{r.mac_address || '—'}</td>
                          <td style={TD}>
                            <span style={{ fontWeight: 700, color: '#dc2626', background: '#fef2f2',
                              padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-sm)' }}>
                              {r.flap_count}
                            </span>
                          </td>
                          <td style={{ ...TD, ...MONO, color: '#7c3aed', fontSize: 'var(--text-xs)' }}>{r.interfaces || '—'}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.first_seen).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.last_seen).toLocaleTimeString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          )}

          {/* ── ROUTING ── */}
          {activeSection === 'routing' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Routing Protocol Events</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>OSPF, BGP, and EIGRP neighbor state changes</div>
              {routing.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>
                  ✓ No routing protocol events in this period
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                      {['Time','Device','Protocol','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {routing.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-light)', background: i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)' }}>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                        <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{r.source_host || r.source_ip}</td>
                        <td style={TD}><SubcatBadge sub={r.protocol} /></td>
                        <td style={TD}><SevBadge label={r.severity_label} /></td>
                        <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── CONFIG CHANGES ── */}
          {activeSection === 'config' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Configuration Changes</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                All device configuration changes — who changed what and when
              </div>
              {configChanges.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>
                  ✓ No configuration changes in this period
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                      {['Time','Device','Vendor','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {configChanges.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-light)',
                        background: i % 2 === 0 ? '#fffef5' : 'var(--bg-card)' }}>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleString()}</td>
                        <td style={{ ...TD, ...MONO, fontWeight: 500, color: 'var(--text-primary)' }}>{r.source_host || r.source_ip}</td>
                        <td style={{ ...TD, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{r.vendor}</td>
                        <td style={{ ...TD, color: 'var(--text-secondary)' }}>{r.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
