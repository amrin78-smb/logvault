'use client';

import { useEffect, useState, useCallback } from 'react';
import { PageHeader, TableSkeleton, CardSkeleton, EmptyState } from './ui';

const CARD = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20, marginBottom: 16 };
const TH   = { padding: '8px 12px', textAlign: 'left' as const, color: '#718096', fontWeight: 600, fontSize: 11 };
const TD   = { padding: '9px 12px', fontSize: 12 };
const MONO = { fontFamily: 'JetBrains Mono, monospace' };

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
  const st = s[label] || s.info;
  return (
    <span style={{ padding: '2px 7px', borderRadius: 4, fontSize: 10, fontWeight: 700,
      background: st.bg, color: st.color, border: `1px solid ${st.border}`,
      textTransform: 'uppercase', letterSpacing: '0.4px' }}>
      {label}
    </span>
  );
}

function RiskBadge({ count, thresholds }: { count: number; thresholds: [number, number] }) {
  const [warn, danger] = thresholds;
  let bg = '#f0fdf4'; let color = '#16a34a'; let label = 'Low';
  if (count >= danger) { bg = '#fef2f2'; color = '#dc2626'; label = 'High'; }
  else if (count >= warn) { bg = '#fefce8'; color = '#ca8a04'; label = 'Med'; }
  return (
    <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontWeight: 700,
      background: bg, color }}>
      {label}
    </span>
  );
}

function StatCard({ value, label, color, bg, border, warn = false }: {
  value: number; label: string; color: string; bg: string; border: string; warn?: boolean;
}) {
  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 10, padding: '16px 18px',
      position: 'relative', overflow: 'hidden' }}>
      {warn && value > 0 && (
        <div style={{ position: 'absolute', top: 8, right: 10, fontSize: 16 }}>⚠️</div>
      )}
      <div style={{ fontSize: 10, color: '#718096', marginBottom: 6, fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.8px' }}>{label}</div>
      <div style={{ fontSize: 30, fontWeight: 700, color, lineHeight: 1 }}>{(value || 0).toLocaleString()}</div>
    </div>
  );
}

export default function SecurityAnalysis({ hours }: { hours: number }) {
  const [summary,      setSummary]      = useState<any>(null);
  const [authFails,    setAuthFails]    = useState<any[]>([]);
  const [bruteForce,   setBruteForce]   = useState<any[]>([]);
  const [fwDenies,     setFwDenies]     = useState<any>(null);
  const [vpnEvents,    setVpnEvents]    = useState<any[]>([]);
  const [ipsEvents,    setIpsEvents]    = useState<any>(null);
  const [afterHours,   setAfterHours]   = useState<any[]>([]);
  const [wirelessAuth, setWirelessAuth] = useState<any>(null);
  const [loading,      setLoading]      = useState(true);
  const [activeSection, setActiveSection] = useState('overview');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, af, bf, fw, vpn, ips, ah, wa] = await Promise.all([
        fetch(`/api/security/summary?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/auth-failures?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/brute-force?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/firewall-denies?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/vpn-events?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/ips-events?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/after-hours?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/wireless-auth?hours=${hours}`).then(r => r.json()),
      ]);
      setSummary(s ? {
        ...s,
        auth_failures:       parseInt(s.auth_failures       || 0),
        brute_force_success: parseInt(s.brute_force_success || 0),
        firewall_denies:     parseInt(s.firewall_denies     || 0),
        vpn_events:          parseInt(s.vpn_events          || 0),
        ips_events:          parseInt(s.ips_events          || 0),
        after_hours_events:  parseInt(s.after_hours_events  || 0),
      } : null);
      setAuthFails(af.data || []);
      setBruteForce(bf.data || []);
      setFwDenies(fw);
      setVpnEvents(vpn.data || []);
      setIpsEvents(ips);
      setAfterHours(ah.data || []);
      setWirelessAuth(wa);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [hours]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const SECTIONS = [
    { id: 'overview',   label: 'Overview' },
    { id: 'authfail',   label: 'Auth Failures',     alert: (summary?.auth_failures    || 0) > 0 },
    { id: 'brute',      label: 'Brute Force',        alert: (summary?.brute_force_success || 0) > 0 },
    { id: 'firewall',   label: 'Firewall Denies',    alert: (summary?.firewall_denies  || 0) > 10 },
    { id: 'vpn',        label: 'VPN Events',         alert: vpnEvents.some(v => v.event_type === 'failure') },
    { id: 'ips',        label: 'IPS / Threats',      alert: (summary?.ips_events       || 0) > 0 },
    { id: 'afterhours', label: 'After-Hours',        alert: (summary?.after_hours_events || 0) > 0 },
    { id: 'wireless',   label: 'Wireless Auth',      alert: (wirelessAuth?.summary?.failures || 0) > 5 },
  ];

  return (
    <div>
      <PageHeader title="Security" subtitle="Threat events, blocked traffic and VPN activity" />

      {/* Section nav */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: '#fff',
        border: '1px solid #e2e6ea', borderRadius: 10, padding: 6, flexWrap: 'wrap' }}>
        {SECTIONS.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            style={{ padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: activeSection === s.id ? 600 : 400,
              background: activeSection === s.id ? '#1a202c' : 'transparent',
              color: activeSection === s.id ? '#fff' : '#6b7280',
              display: 'flex', alignItems: 'center', gap: 5, transition: 'all 0.15s' }}>
            {(s as any).alert && activeSection !== s.id && (
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#dc2626',
                display: 'inline-block', boxShadow: '0 0 4px #dc2626' }} />
            )}
            {s.label}
          </button>
        ))}
        <button onClick={fetchAll} style={{ marginLeft: 'auto', padding: '6px 12px', borderRadius: 6,
          border: '1px solid #e2e6ea', cursor: 'pointer', fontSize: 11, background: '#f8f9fb', color: '#718096' }}>
          ↻ Refresh
        </button>
      </div>

      {loading ? (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 16 }}>
            <CardSkeleton count={6} />
          </div>
          <div style={CARD}>
            <TableSkeleton rows={8} cols={5} />
          </div>
        </>
      ) : (
        <>
          {/* ── OVERVIEW ── */}
          {activeSection === 'overview' && !summary && (
            <div style={CARD}>
              <EmptyState title="No security events" message="No security events for the selected time range." />
            </div>
          )}
          {activeSection === 'overview' && summary && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 16 }}>
                <StatCard value={summary.auth_failures}      label="Auth Failures"       color={summary.auth_failures > 0 ? '#dc2626' : '#16a34a'}  bg={summary.auth_failures > 0 ? '#fef2f2' : '#f0fdf4'} border={summary.auth_failures > 0 ? '#fecaca' : '#bbf7d0'} warn />
                <StatCard value={summary.brute_force_success} label="Brute Force Success" color={summary.brute_force_success > 0 ? '#7c3aed' : '#16a34a'} bg={summary.brute_force_success > 0 ? '#f5f3ff' : '#f0fdf4'} border={summary.brute_force_success > 0 ? '#ddd6fe' : '#bbf7d0'} warn />
                <StatCard value={summary.firewall_denies}    label="Firewall Denies"     color='#ea580c' bg='#fff7ed' border='#fed7aa' />
                <StatCard value={summary.vpn_events}         label="VPN Events"          color='#2563eb' bg='#eff6ff' border='#bfdbfe' />
                <StatCard value={summary.ips_events}         label="IPS / Threat Events" color={summary.ips_events > 0 ? '#dc2626' : '#16a34a'} bg={summary.ips_events > 0 ? '#fef2f2' : '#f0fdf4'} border={summary.ips_events > 0 ? '#fecaca' : '#bbf7d0'} warn />
                <StatCard value={summary.after_hours_events} label="After-Hours Activity" color={summary.after_hours_events > 0 ? '#ca8a04' : '#16a34a'} bg={summary.after_hours_events > 0 ? '#fefce8' : '#f0fdf4'} border={summary.after_hours_events > 0 ? '#fde68a' : '#bbf7d0'} warn />
              </div>

              {/* Critical banners */}
              {summary.brute_force_success > 0 && (
                <div style={{ background: '#f5f3ff', border: '1px solid #ddd6fe', borderRadius: 10,
                  padding: '14px 20px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 22 }}>🚨</span>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#7c3aed' }}>Possible Brute Force Success</div>
                    <div style={{ fontSize: 12, color: '#5b21b6', marginTop: 2 }}>
                      {summary.brute_force_success} source IP(s) had multiple failures followed by a successful login. Investigate immediately.
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('brute')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid #ddd6fe',
                      cursor: 'pointer', fontSize: 12, fontWeight: 600, background: '#fff', color: '#7c3aed' }}>
                    Investigate →
                  </button>
                </div>
              )}

              {summary.ips_events > 0 && (
                <div style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 10,
                  padding: '14px 20px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 22 }}>🛡️</span>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#dc2626' }}>IPS Threats Detected</div>
                    <div style={{ fontSize: 12, color: '#991b1b', marginTop: 2 }}>
                      {summary.ips_events} IPS/threat event(s) triggered. Review threat signatures and source IPs.
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('ips')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid #fecaca',
                      cursor: 'pointer', fontSize: 12, fontWeight: 600, background: '#fff', color: '#dc2626' }}>
                    Review →
                  </button>
                </div>
              )}

              {summary.after_hours_events > 0 && (
                <div style={{ background: '#fefce8', border: '1px solid #fde68a', borderRadius: 10,
                  padding: '14px 20px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 22 }}>🌙</span>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#ca8a04' }}>After-Hours Activity Detected</div>
                    <div style={{ fontSize: 12, color: '#92400e', marginTop: 2 }}>
                      {summary.after_hours_events} security event(s) occurred outside business hours (7AM–7PM).
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('afterhours')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid #fde68a',
                      cursor: 'pointer', fontSize: 12, fontWeight: 600, background: '#fff', color: '#ca8a04' }}>
                    Review →
                  </button>
                </div>
              )}

              {/* Auth failure top sources quick view */}
              {authFails.length > 0 && (
                <div style={CARD}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Top Auth Failure Sources</div>
                  <div style={{ fontSize: 11, color: '#718096', marginBottom: 12 }}>Click a row for details</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                      {['Source IP','Hostname','Vendor','Failures','First','Last','Risk'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {authFails.slice(0, 8).map((r, i) => (
                        <tr key={i} onClick={() => setActiveSection('authfail')}
                          style={{ borderBottom: '1px solid #f0f2f5', cursor: 'pointer',
                            background: i % 2 === 0 ? '#fafbfc' : '#fff' }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#f0f7ff'; }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? '#fafbfc' : '#fff'; }}>
                          <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 600 }}>{r.source_ip}</td>
                          <td style={{ ...TD, ...MONO, color: '#1a202c' }}>{r.source_host || '—'}</td>
                          <td style={{ ...TD, color: '#718096', textTransform: 'capitalize' }}>{r.vendor}</td>
                          <td style={TD}><span style={{ fontWeight: 700, color: '#dc2626', background: '#fef2f2', padding: '2px 8px', borderRadius: 10 }}>{r.failure_count}</span></td>
                          <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af' }}>{new Date(r.first_attempt).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af' }}>{new Date(r.last_attempt).toLocaleTimeString()}</td>
                          <td style={TD}><RiskBadge count={parseInt(r.failure_count)} thresholds={[5, 20]} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {/* ── AUTH FAILURES ── */}
          {activeSection === 'authfail' && (
            <div style={CARD}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Authentication Failures</div>
              <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
                Failed login attempts grouped by source — from Cisco, Fortinet, and Aruba devices
              </div>
              {authFails.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>✓ No authentication failures in this period</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                    {['Source IP','Hostname','Vendor','Failures','First Attempt','Last Attempt','Risk','Sample Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {authFails.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                        <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 600 }}>{r.source_ip}</td>
                        <td style={{ ...TD, ...MONO, color: '#1a202c' }}>{r.source_host || '—'}</td>
                        <td style={{ ...TD, color: '#718096', textTransform: 'capitalize' }}>{r.vendor}</td>
                        <td style={TD}><span style={{ fontWeight: 700, color: '#dc2626', background: '#fef2f2', padding: '2px 8px', borderRadius: 10, fontSize: 12 }}>{r.failure_count}</span></td>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af' }}>{new Date(r.first_attempt).toLocaleString()}</td>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af' }}>{new Date(r.last_attempt).toLocaleString()}</td>
                        <td style={TD}><RiskBadge count={parseInt(r.failure_count)} thresholds={[5, 20]} /></td>
                        <td style={{ ...TD, color: '#4a5568', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {Array.isArray(r.sample_messages) ? r.sample_messages[0] : r.sample_messages || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── BRUTE FORCE ── */}
          {activeSection === 'brute' && (
            <div style={CARD}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Brute Force Analysis</div>
              <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
                Source IPs with 3+ failures — purple highlight = failure followed by successful login (critical)
              </div>
              {bruteForce.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>✓ No brute force patterns detected</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                    {['Source IP','Host','Failures','First Fail','Last Fail','Success After?','Success Time'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {bruteForce.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #f0f2f5',
                        background: r.success_after_failure ? '#fdf4ff' : i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                        <td style={{ ...TD, ...MONO, color: r.success_after_failure ? '#7c3aed' : '#dc2626', fontWeight: 600 }}>{r.source_ip}</td>
                        <td style={{ ...TD, ...MONO, color: '#1a202c' }}>{r.host}</td>
                        <td style={TD}><span style={{ fontWeight: 700, color: '#dc2626', background: '#fef2f2', padding: '2px 8px', borderRadius: 10 }}>{r.fail_count}</span></td>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af' }}>{new Date(r.first_fail).toLocaleString()}</td>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af' }}>{new Date(r.last_fail).toLocaleString()}</td>
                        <td style={TD}>
                          {r.success_after_failure
                            ? <span style={{ color: '#7c3aed', fontWeight: 700, background: '#f5f3ff', padding: '2px 8px', borderRadius: 10, fontSize: 11 }}>🚨 YES</span>
                            : <span style={{ color: '#16a34a', fontSize: 11 }}>✓ No</span>}
                        </td>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: r.success_after_failure ? '#7c3aed' : '#9ca3af' }}>
                          {r.success_time ? new Date(r.success_time).toLocaleString() : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── FIREWALL DENIES ── */}
          {activeSection === 'firewall' && fwDenies && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
                {/* Top blocked sources */}
                <div style={CARD}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Top Blocked Sources</div>
                  <div style={{ fontSize: 11, color: '#718096', marginBottom: 12 }}>IPs generating the most denied traffic</div>
                  {fwDenies.by_source?.length === 0 ? (
                    <div style={{ padding: '24px 0', textAlign: 'center', color: '#9ca3af' }}>No deny data</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                      <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                        {['Source IP','Deny Count','Destinations'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {fwDenies.by_source?.map((r: any, i: number) => (
                          <tr key={i} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                            <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 600 }}>{r.src_ip}</td>
                            <td style={TD}><span style={{ fontWeight: 700, color: '#ea580c', background: '#fff7ed', padding: '2px 8px', borderRadius: 10 }}>{r.deny_count}</span></td>
                            <td style={{ ...TD, color: '#4a5568', fontSize: 11 }}>{Array.isArray(r.destinations) ? r.destinations.slice(0, 3).join(', ') : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>

                {/* Top blocked destinations */}
                <div style={CARD}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Top Blocked Destinations</div>
                  <div style={{ fontSize: 11, color: '#718096', marginBottom: 12 }}>Most targeted destinations being blocked</div>
                  {fwDenies.by_destination?.length === 0 ? (
                    <div style={{ padding: '24px 0', textAlign: 'center', color: '#9ca3af' }}>No deny data</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                      <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                        {['Destination IP','Deny Count','From Sources'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {fwDenies.by_destination?.map((r: any, i: number) => (
                          <tr key={i} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                            <td style={{ ...TD, ...MONO, color: '#2563eb', fontWeight: 600 }}>{r.dst_ip}</td>
                            <td style={TD}><span style={{ fontWeight: 700, color: '#ea580c', background: '#fff7ed', padding: '2px 8px', borderRadius: 10 }}>{r.deny_count}</span></td>
                            <td style={{ ...TD, color: '#4a5568', fontSize: 11 }}>{Array.isArray(r.sources) ? r.sources.slice(0, 3).join(', ') : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>

              {/* Top denied services */}
              <div style={CARD}>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 12 }}>Top Denied Services</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {fwDenies.by_service?.map((r: any, i: number) => {
                    const maxCount = fwDenies.by_service?.[0]?.deny_count || 1;
                    const pct = Math.round((r.deny_count / maxCount) * 100);
                    return (
                      <div key={i} style={{ background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 8,
                        padding: '10px 14px', minWidth: 120 }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: '#1a202c', marginBottom: 4 }}>{r.service}</div>
                        <div style={{ fontSize: 11, color: '#ea580c', fontWeight: 700, marginBottom: 6 }}>{r.deny_count} denies</div>
                        <div style={{ height: 4, background: '#f0f2f5', borderRadius: 2 }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: '#ea580c', borderRadius: 2 }} />
                        </div>
                      </div>
                    );
                  })}
                  {(!fwDenies.by_service || fwDenies.by_service.length === 0) && (
                    <div style={{ padding: '24px 0', color: '#9ca3af', textAlign: 'center', width: '100%' }}>No deny data for this period</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ── VPN EVENTS ── */}
          {activeSection === 'vpn' && (
            <div style={CARD}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>VPN Events</div>
              <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>SSL VPN and IPSec events from Fortinet</div>
              {vpnEvents.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>✓ No VPN events in this period</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                    {['Time','Firewall','VPN Source IP','Type','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {vpnEvents.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #f0f2f5',
                        background: r.event_type === 'failure' ? '#fff8f8' : i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                        <td style={{ ...TD, ...MONO, color: '#1a202c', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                        <td style={{ ...TD, ...MONO, color: '#2563eb', fontSize: 11 }}>{r.vpn_src_ip || '—'}</td>
                        <td style={TD}>
                          <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontWeight: 600,
                            background: r.event_type === 'failure' ? '#fef2f2' : r.event_type === 'success' ? '#f0fdf4' : '#eff6ff',
                            color: r.event_type === 'failure' ? '#dc2626' : r.event_type === 'success' ? '#16a34a' : '#2563eb' }}>
                            {r.event_type}
                          </span>
                        </td>
                        <td style={TD}><SevBadge label={r.severity_label} /></td>
                        <td style={{ ...TD, color: '#4a5568', maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.detail || r.message}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── IPS EVENTS ── */}
          {activeSection === 'ips' && ipsEvents && (
            <div>
              {ipsEvents.by_threat?.length > 0 && (
                <div style={{ ...CARD, marginBottom: 16 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 12 }}>Threat Summary</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {ipsEvents.by_threat.map((r: any, i: number) => {
                      const max = ipsEvents.by_threat[0]?.hit_count || 1;
                      const pct = Math.round((r.hit_count / max) * 100);
                      return (
                        <div key={i} style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8, padding: '10px 14px', minWidth: 150 }}>
                          <div style={{ fontSize: 11, fontWeight: 600, color: '#991b1b', marginBottom: 2, wordBreak: 'break-word' }}>{r.threat}</div>
                          <div style={{ fontSize: 10, color: '#718096', marginBottom: 4, textTransform: 'capitalize' }}>{r.subtype}</div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ fontSize: 12, fontWeight: 700, color: '#dc2626' }}>{r.hit_count} hits</span>
                            <span style={{ fontSize: 10, color: '#9ca3af' }}>{r.unique_sources} src</span>
                          </div>
                          <div style={{ height: 3, background: '#fecaca', borderRadius: 2 }}>
                            <div style={{ height: '100%', width: `${pct}%`, background: '#dc2626', borderRadius: 2 }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div style={CARD}>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 12 }}>IPS Event Log</div>
                {ipsEvents.events?.length === 0 ? (
                  <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>✓ No IPS events in this period</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                      {['Time','Firewall','Src IP','Dst IP','Type','Severity','Threat'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {ipsEvents.events?.map((r: any, i: number) => (
                        <tr key={i} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fff8f8' : '#fff' }}>
                          <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, color: '#1a202c', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                          <td style={{ ...TD, ...MONO, color: '#dc2626', fontSize: 11 }}>{r.src_ip || '—'}</td>
                          <td style={{ ...TD, ...MONO, color: '#2563eb', fontSize: 11 }}>{r.dst_ip || '—'}</td>
                          <td style={{ ...TD, color: '#718096', textTransform: 'capitalize', fontSize: 11 }}>{r.subtype || '—'}</td>
                          <td style={TD}><SevBadge label={r.severity_label} /></td>
                          <td style={{ ...TD, color: '#991b1b', fontWeight: 500, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {r.threat_name || r.message}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* ── AFTER HOURS ── */}
          {activeSection === 'afterhours' && (
            <div style={CARD}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>After-Hours Activity</div>
              <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>
                Security events and config changes outside business hours (before 7AM or after 7PM)
              </div>
              {afterHours.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>✓ No after-hours activity detected</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                    {['Time','Hour','Device','Vendor','Event Type','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {afterHours.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fffef5' : '#fff' }}>
                        <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleString()}</td>
                        <td style={{ ...TD, fontWeight: 700, color: '#ca8a04' }}>{String(r.hour_of_day).padStart(2,'0')}:xx</td>
                        <td style={{ ...TD, ...MONO, color: '#1a202c', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                        <td style={{ ...TD, color: '#718096', textTransform: 'capitalize' }}>{r.vendor}</td>
                        <td style={TD}>
                          <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontWeight: 600,
                            background: '#fefce8', color: '#ca8a04', border: '1px solid #fde68a' }}>
                            {r.event_type}
                          </span>
                        </td>
                        <td style={TD}><SevBadge label={r.severity_label} /></td>
                        <td style={{ ...TD, color: '#4a5568', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── WIRELESS AUTH ── */}
          {activeSection === 'wireless' && wirelessAuth && (
            <div>
              {wirelessAuth.summary && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 16 }}>
                  <StatCard value={parseInt(wirelessAuth.summary.failures  || 0)} label="802.1X Failures"  color='#dc2626' bg='#fef2f2' border='#fecaca' warn />
                  <StatCard value={parseInt(wirelessAuth.summary.successes || 0)} label="Successful Auths" color='#16a34a' bg='#f0fdf4' border='#bbf7d0' />
                  <StatCard value={parseInt(wirelessAuth.summary.devices   || 0)} label="Unique Devices"   color='#2563eb' bg='#eff6ff' border='#bfdbfe' />
                </div>
              )}
              <div style={CARD}>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Wireless Auth Failures</div>
                <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Aruba 802.1X authentication failures by MAC address and SSID</div>
                {wirelessAuth.failures?.length === 0 ? (
                  <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 13, fontWeight: 500 }}>✓ No wireless auth failures</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead><tr style={{ borderBottom: '2px solid #f0f2f5' }}>
                      {['Time','Controller','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {wirelessAuth.failures?.map((r: any, i: number) => (
                        <tr key={i} style={{ borderBottom: '1px solid #f0f2f5', background: i % 2 === 0 ? '#fafbfc' : '#fff' }}>
                          <td style={{ ...TD, ...MONO, fontSize: 10, color: '#9ca3af', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, color: '#1a202c', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                          <td style={TD}><SevBadge label={r.severity_label} /></td>
                          <td style={{ ...TD, color: '#4a5568', maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
