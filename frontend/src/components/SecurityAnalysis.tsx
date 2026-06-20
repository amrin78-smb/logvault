'use client';

import { useEffect, useState, useCallback } from 'react';
import { PageHeader, TableSkeleton, CardSkeleton, EmptyState } from './ui';
import { MITRE_TECHNIQUES, MITRE_TACTIC_ORDER } from './mitre';
import TimeRangePicker from './TimeRangePicker';

const CARD = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 16 };
const TH   = { padding: '8px 12px', textAlign: 'left' as const, color: 'var(--text-muted)', fontWeight: 600, fontSize: 'var(--text-xs)' };
const TD   = { padding: '9px 12px', fontSize: 'var(--text-sm)' };
const MONO = { fontFamily: 'var(--font-mono)' };

// Convert a 2-letter ISO country code to a flag emoji (regional indicator symbols)
function flagEmoji(code?: string | null): string {
  if (!code || code.length !== 2) return '';
  const cc = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...[...cc].map(c => 0x1f1e6 + c.charCodeAt(0) - 65));
}

// Render a country label (flag + name/code), or an em-dash when unknown
function CountryLabel({ country, code }: { country?: string | null; code?: string | null }) {
  const flag = flagEmoji(code);
  const name = country || code;
  if (!name) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  return (
    <span style={{ whiteSpace: 'nowrap' }}>
      {flag && <span style={{ marginRight: 5 }}>{flag}</span>}
      <span>{name}</span>
    </span>
  );
}

// Red "Known Bad" / threat pill for malicious source IPs
function ThreatBadge({ knownBad, abuseScore }: { knownBad?: boolean; abuseScore?: number | null }) {
  const score = typeof abuseScore === 'number' ? abuseScore : null;
  if (!knownBad && (score === null || score < 50)) return null;
  const label = knownBad ? 'Known Bad' : `Abuse ${score}`;
  return (
    <span style={{ padding: '2px 7px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 700,
      background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)', border: '1px solid var(--tint-danger)',
      textTransform: 'uppercase', letterSpacing: '0.4px', whiteSpace: 'nowrap' }}>
      {label}
    </span>
  );
}

function SevBadge({ label }: { label: string }) {
  const s: Record<string, { bg: string; color: string; border: string }> = {
    emergency: { bg: 'var(--tint-danger)',  color: 'var(--tint-danger-fg)',  border: 'var(--tint-danger)' },
    alert:     { bg: 'var(--tint-danger)',  color: 'var(--tint-danger-fg)',  border: 'var(--tint-danger)' },
    critical:  { bg: 'var(--tint-danger)',  color: 'var(--tint-danger-fg)',  border: 'var(--tint-danger)' },
    error:     { bg: 'var(--tint-warn)',    color: 'var(--tint-warn-fg)',    border: 'var(--tint-warn)' },
    warning:   { bg: 'var(--tint-warn)',    color: 'var(--tint-warn-fg)',    border: 'var(--tint-warn)' },
    notice:    { bg: 'var(--tint-info)',    color: 'var(--tint-info-fg)',    border: 'var(--tint-info)' },
    info:      { bg: 'var(--tint-success)', color: 'var(--tint-success-fg)', border: 'var(--tint-success)' },
  };
  const st = s[label] || s.info;
  return (
    <span style={{ padding: '2px 7px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 700,
      background: st.bg, color: st.color, border: `1px solid ${st.border}`,
      textTransform: 'uppercase', letterSpacing: '0.4px' }}>
      {label}
    </span>
  );
}

// Small tinted pill for an IPS event's criticality level (crlevel)
function CrLevelBadge({ level }: { level?: string | null }) {
  if (!level) return null;
  const lv = String(level).toLowerCase();
  const map: Record<string, { bg: string; color: string }> = {
    critical: { bg: 'var(--tint-danger)',  color: 'var(--tint-danger-fg)' },
    high:     { bg: 'var(--tint-danger)',  color: 'var(--tint-danger-fg)' },
    medium:   { bg: 'var(--tint-warn)',    color: 'var(--tint-warn-fg)' },
    low:      { bg: 'var(--tint-info)',    color: 'var(--tint-info-fg)' },
  };
  const st = map[lv];
  if (!st) return null; // only surface meaningful severity levels
  return (
    <span style={{ padding: '1px 6px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 700,
      background: st.bg, color: st.color, textTransform: 'uppercase', letterSpacing: '0.3px', whiteSpace: 'nowrap' }}>
      {lv}
    </span>
  );
}

function RiskBadge({ count, thresholds }: { count: number; thresholds: [number, number] }) {
  const [warn, danger] = thresholds;
  let bg = 'var(--tint-success)'; let color = 'var(--tint-success-fg)'; let label = 'Low';
  if (count >= danger) { bg = 'var(--tint-danger)'; color = 'var(--tint-danger-fg)'; label = 'High'; }
  else if (count >= warn) { bg = 'var(--tint-warn)'; color = 'var(--tint-warn-fg)'; label = 'Med'; }
  return (
    <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)', fontWeight: 700,
      background: bg, color }}>
      {label}
    </span>
  );
}

function StatCard({ value, label, color, bg, border, warn = false }: {
  value: number; label: string; color: string; bg: string; border: string; warn?: boolean;
}) {
  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 8, padding: '16px 18px',
      position: 'relative', overflow: 'hidden' }}>
      {warn && value > 0 && (
        <div style={{ position: 'absolute', top: 8, right: 10, fontSize: 'var(--text-lg)' }}>⚠️</div>
      )}
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.8px' }}>{label}</div>
      <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color, lineHeight: 1 }}>{(value || 0).toLocaleString()}</div>
    </div>
  );
}

export default function SecurityAnalysis({ hours, onHoursChange, refreshInterval, onRefreshChange, onTechnique, onDrill }: {
  hours: number;
  onHoursChange: (hours: number) => void;
  refreshInterval: number;
  onRefreshChange: (seconds: number) => void;
  onTechnique?: (technique: string) => void;
  onDrill?: (filter: { host?: string; q?: string; category?: string; technique?: string; severity?: string; vendor?: string }) => void;
}) {
  const [summary,      setSummary]      = useState<any>(null);
  const [authFails,    setAuthFails]    = useState<any[]>([]);
  const [bruteForce,   setBruteForce]   = useState<any[]>([]);
  const [fwDenies,     setFwDenies]     = useState<any>(null);
  const [vpnEvents,    setVpnEvents]    = useState<any[]>([]);
  const [ipsEvents,    setIpsEvents]    = useState<any>(null);
  const [afterHours,   setAfterHours]   = useState<any[]>([]);
  const [wirelessAuth, setWirelessAuth] = useState<any>(null);
  const [mitreCov,     setMitreCov]     = useState<any[]>([]);
  const [targetedUsers, setTargetedUsers] = useState<any[]>([]);
  const [failsByCountry, setFailsByCountry] = useState<any[]>([]);
  const [loading,      setLoading]      = useState(true);
  const [activeSection, setActiveSection] = useState('overview');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, af, bf, fw, vpn, ips, ah, wa, mc, tu, fc] = await Promise.all([
        fetch(`/api/security/summary?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/auth-failures?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/brute-force?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/firewall-denies?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/vpn-events?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/ips-events?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/after-hours?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/wireless-auth?hours=${hours}`).then(r => r.json()),
        fetch(`/api/stats/mitre-coverage?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/top-targeted-users?hours=${hours}`).then(r => r.json()),
        fetch(`/api/security/failed-logins-by-country?hours=${hours}`).then(r => r.json()),
      ]);
      setSummary(s ? {
        ...s,
        auth_failures:       parseInt(s.auth_failures       || 0),
        brute_force_success: parseInt(s.brute_force_success || 0),
        firewall_denies:     parseInt(s.firewall_denies     || 0),
        vpn_events:          parseInt(s.vpn_events          || 0),
        ips_events:          parseInt(s.ips_events          || 0),
        after_hours_events:  parseInt(s.after_hours_events  || 0),
        vpn_login_failures:  parseInt(s.vpn_login_failures  || 0),
        known_bad_failures:  parseInt(s.known_bad_failures  || 0),
      } : null);
      setAuthFails(af.data || []);
      setBruteForce(bf.data || []);
      setFwDenies(fw);
      setVpnEvents(vpn.data || []);
      setIpsEvents(ips);
      setAfterHours(ah.data || []);
      setWirelessAuth(wa);
      setMitreCov(mc.data || []);
      setTargetedUsers(tu.data || []);
      setFailsByCountry(fc.data || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [hours]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Build clickable-row props that drill into the Log Explorer pre-filtered to this
  // row's context. Returns {} (no cursor/onClick) when no useful filter value exists
  // or no onDrill handler is wired, so rows without a target aren't falsely clickable.
  // `restoreBg` is the row's normal background, restored on mouse-leave after the hover.
  const drillRow = (
    filter: { host?: string; q?: string; category?: string; technique?: string; severity?: string; vendor?: string },
    restoreBg: string,
  ) => {
    const value = filter.host || filter.q || filter.category || filter.technique || filter.severity || filter.vendor;
    if (!onDrill || !value) return {};
    return {
      onClick: () => onDrill(filter),
      title: 'Open in Log Explorer',
      style: { cursor: 'pointer' as const },
      onMouseEnter: (e: { currentTarget: HTMLElement }) => { e.currentTarget.style.background = 'var(--surface-subtle)'; },
      onMouseLeave: (e: { currentTarget: HTMLElement }) => { e.currentTarget.style.background = restoreBg; },
    };
  };

  const SECTIONS = [
    { id: 'overview',   label: 'Overview' },
    { id: 'authfail',   label: 'Auth Failures',     alert: (summary?.auth_failures    || 0) > 0 },
    { id: 'brute',      label: 'Brute Force',        alert: (summary?.brute_force_success || 0) > 0 },
    { id: 'firewall',   label: 'Firewall Denies',    alert: (summary?.firewall_denies  || 0) > 10 },
    { id: 'vpn',        label: 'VPN Events',         alert: vpnEvents.some(v => v.event_type === 'failure') },
    { id: 'ips',        label: 'IPS / Threats',      alert: (summary?.ips_events       || 0) > 0 },
    { id: 'afterhours', label: 'After-Hours',        alert: (summary?.after_hours_events || 0) > 0 },
    { id: 'wireless',   label: 'Wireless Auth',      alert: (wirelessAuth?.summary?.failures || 0) > 5 },
    { id: 'attack',     label: 'ATT&CK Coverage' },
  ];

  // ── MITRE ATT&CK coverage matrix data ──
  const covMap: Record<string, number> = {};
  mitreCov.forEach((r: any) => { covMap[r.technique] = parseInt(r.count) || 0; });
  const byTactic: Record<string, string[]> = {};
  Object.keys(MITRE_TECHNIQUES).forEach(id => {
    const tac = MITRE_TECHNIQUES[id].tactic;
    (byTactic[tac] = byTactic[tac] || []).push(id);
  });
  const covTactics = MITRE_TACTIC_ORDER.filter(t => byTactic[t] && byTactic[t].length);
  const covTotal = mitreCov.reduce((a: number, r: any) => a + (parseInt(r.count) || 0), 0);
  const covTacticsActive = covTactics.filter(t => byTactic[t].some(id => (covMap[id] || 0) > 0)).length;

  return (
    <div>
      <PageHeader title="Security" subtitle="Threat events, blocked traffic and VPN activity">
        <TimeRangePicker
          hours={hours}
          onHoursChange={onHoursChange}
          refreshInterval={refreshInterval}
          onRefreshChange={onRefreshChange}
          onRefreshNow={fetchAll}
        />
      </PageHeader>

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
            {(s as any).alert && activeSection !== s.id && (
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#dc2626',
                display: 'inline-block', boxShadow: '0 0 4px #dc2626' }} />
            )}
            {s.label}
          </button>
        ))}
        <button onClick={fetchAll} style={{ marginLeft: 'auto', padding: '6px 12px', borderRadius: 6,
          border: '1px solid var(--border)', cursor: 'pointer', fontSize: 'var(--text-xs)', background: 'var(--surface-subtle)', color: 'var(--text-muted)' }}>
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
                <StatCard value={summary.auth_failures}      label="Auth Failures"       color={summary.auth_failures > 0 ? 'var(--tint-danger-fg)' : 'var(--tint-success-fg)'}  bg={summary.auth_failures > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'} border={summary.auth_failures > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'} warn />
                <StatCard value={summary.brute_force_success} label="Brute Force Success" color={summary.brute_force_success > 0 ? 'var(--tint-purple-fg)' : 'var(--tint-success-fg)'} bg={summary.brute_force_success > 0 ? 'var(--tint-purple)' : 'var(--tint-success)'} border={summary.brute_force_success > 0 ? 'var(--tint-purple)' : 'var(--tint-success)'} warn />
                <StatCard value={summary.firewall_denies}    label="Firewall Denies"     color='var(--tint-warn-fg)' bg='var(--tint-warn)' border='var(--tint-warn)' />
                <StatCard value={summary.vpn_events}         label="VPN Events"          color='var(--tint-info-fg)' bg='var(--tint-info)' border='var(--tint-info)' />
                <StatCard value={summary.ips_events}         label="IPS / Threat Events" color={summary.ips_events > 0 ? 'var(--tint-danger-fg)' : 'var(--tint-success-fg)'} bg={summary.ips_events > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'} border={summary.ips_events > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'} warn />
                <StatCard value={summary.after_hours_events} label="After-Hours Activity" color={summary.after_hours_events > 0 ? 'var(--tint-warn-fg)' : 'var(--tint-success-fg)'} bg={summary.after_hours_events > 0 ? 'var(--tint-warn)' : 'var(--tint-success)'} border={summary.after_hours_events > 0 ? 'var(--tint-warn)' : 'var(--tint-success)'} warn />
                <StatCard value={summary.vpn_login_failures} label="VPN Login Failures" color={summary.vpn_login_failures > 0 ? 'var(--tint-warn-fg)' : 'var(--tint-success-fg)'} bg={summary.vpn_login_failures > 0 ? 'var(--tint-warn)' : 'var(--tint-success)'} border={summary.vpn_login_failures > 0 ? 'var(--tint-warn)' : 'var(--tint-success)'} warn />
                <StatCard value={summary.known_bad_failures} label="From Known-Bad IPs" color={summary.known_bad_failures > 0 ? 'var(--tint-danger-fg)' : 'var(--tint-success-fg)'} bg={summary.known_bad_failures > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'} border={summary.known_bad_failures > 0 ? 'var(--tint-danger)' : 'var(--tint-success)'} warn />
              </div>

              {/* Critical banners */}
              {summary.brute_force_success > 0 && (
                <div style={{ background: 'var(--tint-purple)', border: '1px solid var(--tint-purple)', borderRadius: 8,
                  padding: '14px 20px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 'var(--text-xl)' }}>🚨</span>
                  <div>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--tint-purple-fg)' }}>Possible Brute Force Success</div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--tint-purple-fg)', marginTop: 2 }}>
                      {summary.brute_force_success} source IP(s) had multiple failures followed by a successful login. Investigate immediately.
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('brute')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid var(--tint-purple)',
                      cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600, background: 'var(--bg-card)', color: 'var(--tint-purple-fg)' }}>
                    Investigate →
                  </button>
                </div>
              )}

              {summary.ips_events > 0 && (
                <div style={{ background: 'var(--tint-danger)', border: '1px solid var(--tint-danger)', borderRadius: 8,
                  padding: '14px 20px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 'var(--text-xl)' }}>🛡️</span>
                  <div>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--tint-danger-fg)' }}>IPS Threats Detected</div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--tint-danger-fg)', marginTop: 2 }}>
                      {summary.ips_events} IPS/threat event(s) triggered. Review threat signatures and source IPs.
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('ips')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid var(--tint-danger)',
                      cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600, background: 'var(--bg-card)', color: 'var(--tint-danger-fg)' }}>
                    Review →
                  </button>
                </div>
              )}

              {summary.after_hours_events > 0 && (
                <div style={{ background: 'var(--tint-warn)', border: '1px solid var(--tint-warn)', borderRadius: 8,
                  padding: '14px 20px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 'var(--text-xl)' }}>🌙</span>
                  <div>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 700, color: 'var(--tint-warn-fg)' }}>After-Hours Activity Detected</div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--tint-warn-fg)', marginTop: 2 }}>
                      {summary.after_hours_events} security event(s) occurred outside business hours (7AM–7PM).
                    </div>
                  </div>
                  <button onClick={() => setActiveSection('afterhours')}
                    style={{ marginLeft: 'auto', padding: '6px 14px', borderRadius: 6, border: '1px solid var(--tint-warn)',
                      cursor: 'pointer', fontSize: 'var(--text-sm)', fontWeight: 600, background: 'var(--bg-card)', color: 'var(--tint-warn-fg)' }}>
                    Review →
                  </button>
                </div>
              )}

              {/* Auth failure top sources quick view */}
              {authFails.length > 0 && (
                <div style={CARD}>
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Top Auth Failure Sources</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 12 }}>Real attacker IP and the account(s) being targeted — click a row for details</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                    <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                      {['Attacker IP','Country','Targeted User(s)','Failures','Last Attempt','Vendor','Risk'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {authFails.slice(0, 8).map((r, i) => {
                        const users: string[] = Array.isArray(r.sample_users) ? r.sample_users : [];
                        const distinct = parseInt(r.distinct_users) || 0;
                        const isThreat = r.is_known_bad || (typeof r.abuse_score === 'number' && r.abuse_score >= 50);
                        const rowBg = isThreat ? 'var(--tint-danger)' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                        return (
                          <tr key={i}
                            onClick={() => { if (onDrill && r.source_ip) onDrill({ host: r.source_ip }); else setActiveSection('authfail'); }}
                            title={onDrill && r.source_ip ? 'Open in Log Explorer' : undefined}
                            style={{ borderBottom: '1px solid var(--border-light)', cursor: 'pointer', background: rowBg }}
                            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--surface-subtle)'; }}
                            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = rowBg; }}>
                            <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 600, whiteSpace: 'nowrap' }}>
                              {r.source_ip}
                              {isThreat && <span style={{ marginLeft: 6 }}><ThreatBadge knownBad={r.is_known_bad} abuseScore={r.abuse_score} /></span>}
                            </td>
                            <td style={TD}><CountryLabel country={r.country} code={r.country_code} /></td>
                            <td style={{ ...TD, color: 'var(--text-primary)' }}>
                              {users.length > 0 ? users.slice(0, 3).join(', ') : '—'}
                              {distinct > 1 && <span style={{ color: 'var(--text-muted)', marginLeft: 6, fontSize: 'var(--text-xs)' }}>+{distinct} accounts</span>}
                            </td>
                            <td style={TD}><span style={{ fontWeight: 700, color: 'var(--tint-danger-fg)', background: 'var(--tint-danger)', padding: '2px 8px', borderRadius: 10 }}>{r.failure_count}</span></td>
                            <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.last_attempt).toLocaleTimeString()}</td>
                            <td style={{ ...TD, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{r.vendor}</td>
                            <td style={TD}><RiskBadge count={parseInt(r.failure_count)} thresholds={[5, 20]} /></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {/* ── AUTH FAILURES ── */}
          {activeSection === 'authfail' && (
            <>
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Authentication Failures</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Failed login attempts grouped by the real attacker IP, with the account(s) being targeted and source country
              </div>
              {authFails.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>✓ No authentication failures in this period</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                    {['Attacker IP','Country','Targeted User(s)','Failures','First Attempt','Last Attempt','Risk','Vendor'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {authFails.map((r, i) => {
                      const users: string[] = Array.isArray(r.sample_users) ? r.sample_users : [];
                      const distinct = parseInt(r.distinct_users) || 0;
                      const isThreat = r.is_known_bad || (typeof r.abuse_score === 'number' && r.abuse_score >= 50);
                      const rowBg = isThreat ? 'var(--tint-danger)' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                      const d = drillRow({ host: r.source_ip }, rowBg);
                      return (
                        <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                          <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 600, whiteSpace: 'nowrap' }}>
                            {r.source_ip}
                            {isThreat && <span style={{ marginLeft: 6 }}><ThreatBadge knownBad={r.is_known_bad} abuseScore={r.abuse_score} /></span>}
                          </td>
                          <td style={TD}><CountryLabel country={r.country} code={r.country_code} /></td>
                          <td style={{ ...TD, color: 'var(--text-primary)' }}>
                            {users.length > 0 ? users.slice(0, 5).join(', ') : '—'}
                            {distinct > 1 && <span style={{ color: 'var(--text-muted)', marginLeft: 6, fontSize: 'var(--text-xs)' }}>+{distinct} accounts</span>}
                          </td>
                          <td style={TD}><span style={{ fontWeight: 700, color: 'var(--tint-danger-fg)', background: 'var(--tint-danger)', padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-sm)' }}>{r.failure_count}</span></td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.first_attempt).toLocaleString()}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.last_attempt).toLocaleString()}</td>
                          <td style={TD}><RiskBadge count={parseInt(r.failure_count)} thresholds={[5, 20]} /></td>
                          <td style={{ ...TD, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{r.vendor}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Top Targeted Usernames */}
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Top Targeted Usernames</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Accounts receiving the most failed login attempts — a single account with many failures suggests targeted password guessing
              </div>
              {targetedUsers.length === 0 ? (
                <EmptyState title="No targeted accounts" message="No targeted usernames in this period." />
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                    {['Username','Failures','Distinct Sources','Last Attempt','Risk'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {targetedUsers.map((r, i) => {
                      const fails = parseInt(r.failure_count) || 0;
                      const hot = fails >= 20;
                      const rowBg = hot ? 'var(--tint-danger)' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                      const d = drillRow({ q: r.username }, rowBg);
                      return (
                        <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                          <td style={{ ...TD, ...MONO, color: 'var(--text-primary)', fontWeight: 600 }}>{r.username || '—'}</td>
                          <td style={TD}><span style={{ fontWeight: 700, color: 'var(--tint-danger-fg)', background: 'var(--tint-danger)', padding: '2px 8px', borderRadius: 10 }}>{fails}</span></td>
                          <td style={{ ...TD, color: 'var(--text-secondary)' }}>{parseInt(r.distinct_sources) || 0}</td>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{r.last_attempt ? new Date(r.last_attempt).toLocaleString() : '—'}</td>
                          <td style={TD}><RiskBadge count={fails} thresholds={[5, 20]} /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Failed Logins by Country */}
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Failed Logins by Country</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Geographic origin of failed login attempts (by real attacker IP)
              </div>
              {failsByCountry.length === 0 ? (
                <EmptyState title="No geolocated failures" message="No failed logins with a known country in this period." />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {failsByCountry.map((r, i) => {
                    const fails = parseInt(r.failure_count) || 0;
                    const max = parseInt(failsByCountry[0]?.failure_count) || 1;
                    const pct = Math.round((fails / max) * 100);
                    const d = drillRow({ q: r.country }, 'transparent');
                    return (
                      <div key={i} {...d} style={{ display: 'flex', alignItems: 'center', gap: 12, borderRadius: 4, ...(d.style || {}) }}>
                        <div style={{ width: 180, fontSize: 'var(--text-sm)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <CountryLabel country={r.country} code={r.country_code} />
                        </div>
                        <div style={{ flex: 1, height: 14, background: 'var(--border-light)', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: '#dc2626', borderRadius: 3 }} />
                        </div>
                        <div style={{ width: 70, textAlign: 'right', fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--tint-danger-fg)' }}>{fails.toLocaleString()}</div>
                        <div style={{ width: 90, textAlign: 'right', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{parseInt(r.distinct_sources) || 0} src</div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            </>
          )}

          {/* ── BRUTE FORCE ── */}
          {activeSection === 'brute' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Brute Force Analysis</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Source IPs with 3+ failures — purple highlight = failure followed by successful login (critical)
              </div>
              {bruteForce.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>✓ No brute force patterns detected</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                    {['Source IP','Host','Failures','First Fail','Last Fail','Success After?','Success Time'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {bruteForce.map((r, i) => {
                      const rowBg = r.success_after_failure ? 'var(--tint-purple)' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                      const d = drillRow({ host: r.source_ip }, rowBg);
                      return (
                      <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                        <td style={{ ...TD, ...MONO, color: r.success_after_failure ? 'var(--tint-purple-fg)' : '#dc2626', fontWeight: 600 }}>{r.source_ip}</td>
                        <td style={{ ...TD, ...MONO, color: 'var(--text-primary)' }}>{r.host}</td>
                        <td style={TD}><span style={{ fontWeight: 700, color: 'var(--tint-danger-fg)', background: 'var(--tint-danger)', padding: '2px 8px', borderRadius: 10 }}>{r.fail_count}</span></td>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.first_fail).toLocaleString()}</td>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(r.last_fail).toLocaleString()}</td>
                        <td style={TD}>
                          {r.success_after_failure
                            ? <span style={{ color: 'var(--tint-purple-fg)', fontWeight: 700, background: 'var(--tint-purple)', padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)' }}>🚨 YES</span>
                            : <span style={{ color: '#16a34a', fontSize: 'var(--text-xs)' }}>✓ No</span>}
                        </td>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: r.success_after_failure ? 'var(--tint-purple-fg)' : 'var(--text-muted)' }}>
                          {r.success_time ? new Date(r.success_time).toLocaleString() : '—'}
                        </td>
                      </tr>
                    ); })}
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
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Top Blocked Sources</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 12 }}>IPs generating the most denied traffic</div>
                  {fwDenies.by_source?.length === 0 ? (
                    <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-muted)' }}>No deny data</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                      <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                        {['Source IP','Deny Count','Destinations'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {fwDenies.by_source?.map((r: any, i: number) => {
                          const rowBg = i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                          const d = drillRow({ host: r.src_ip }, rowBg);
                          return (
                          <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                            <td style={{ ...TD, ...MONO, color: '#dc2626', fontWeight: 600 }}>{r.src_ip}</td>
                            <td style={TD}><span style={{ fontWeight: 700, color: 'var(--tint-warn-fg)', background: 'var(--tint-warn)', padding: '2px 8px', borderRadius: 10 }}>{r.deny_count}</span></td>
                            <td style={{ ...TD, color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>{Array.isArray(r.destinations) ? r.destinations.slice(0, 3).join(', ') : '—'}</td>
                          </tr>
                        ); })}
                      </tbody>
                    </table>
                  )}
                </div>

                {/* Top blocked destinations */}
                <div style={CARD}>
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Top Blocked Destinations</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 12 }}>Most targeted destinations being blocked</div>
                  {fwDenies.by_destination?.length === 0 ? (
                    <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-muted)' }}>No deny data</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                      <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                        {['Destination IP','Deny Count','From Sources'].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {fwDenies.by_destination?.map((r: any, i: number) => {
                          const rowBg = i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                          const d = drillRow({ host: r.dst_ip }, rowBg);
                          return (
                          <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                            <td style={{ ...TD, ...MONO, color: '#2563eb', fontWeight: 600 }}>{r.dst_ip}</td>
                            <td style={TD}><span style={{ fontWeight: 700, color: 'var(--tint-warn-fg)', background: 'var(--tint-warn)', padding: '2px 8px', borderRadius: 10 }}>{r.deny_count}</span></td>
                            <td style={{ ...TD, color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>{Array.isArray(r.sources) ? r.sources.slice(0, 3).join(', ') : '—'}</td>
                          </tr>
                        ); })}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>

              {/* Top denied services */}
              <div style={CARD}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Top Denied Services</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {fwDenies.by_service?.map((r: any, i: number) => {
                    const maxCount = fwDenies.by_service?.[0]?.deny_count || 1;
                    const pct = Math.round((r.deny_count / maxCount) * 100);
                    const d = drillRow({ q: r.service }, 'var(--surface-subtle)');
                    return (
                      <div key={i} {...d} style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border)', borderRadius: 8,
                        padding: '10px 14px', minWidth: 120, ...(d.style || {}) }}>
                        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{r.service}</div>
                        <div style={{ fontSize: 'var(--text-xs)', color: '#ea580c', fontWeight: 700, marginBottom: 6 }}>{r.deny_count} denies</div>
                        <div style={{ height: 4, background: 'var(--border-light)', borderRadius: 2 }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: '#ea580c', borderRadius: 2 }} />
                        </div>
                      </div>
                    );
                  })}
                  {(!fwDenies.by_service || fwDenies.by_service.length === 0) && (
                    <div style={{ padding: '24px 0', color: 'var(--text-muted)', textAlign: 'center', width: '100%' }}>No deny data for this period</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ── VPN EVENTS ── */}
          {activeSection === 'vpn' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>VPN Events</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>SSL VPN and IPSec events from Fortinet</div>
              {vpnEvents.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>✓ No VPN events in this period</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                    {['Time','Firewall','VPN Source IP','User','Country','Type','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {vpnEvents.map((r, i) => {
                      const rowBg = r.event_type === 'failure' ? 'var(--tint-danger)' : i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                      const d = drillRow({ host: r.vpn_src_ip || r.source_ip }, rowBg);
                      return (
                      <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                        <td style={{ ...TD, ...MONO, color: 'var(--text-primary)', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                        <td style={{ ...TD, ...MONO, color: '#2563eb', fontSize: 'var(--text-xs)' }}>{r.vpn_src_ip || '—'}</td>
                        <td style={{ ...TD, ...MONO, color: 'var(--text-primary)' }}>{r.username || '—'}</td>
                        <td style={TD}><CountryLabel country={r.country} code={null} /></td>
                        <td style={TD}>
                          <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)', fontWeight: 600,
                            background: r.event_type === 'failure' ? 'var(--tint-danger)' : r.event_type === 'success' ? 'var(--tint-success)' : 'var(--tint-info)',
                            color: r.event_type === 'failure' ? 'var(--tint-danger-fg)' : r.event_type === 'success' ? 'var(--tint-success-fg)' : 'var(--tint-info-fg)' }}>
                            {r.event_type}
                          </span>
                        </td>
                        <td style={TD}><SevBadge label={r.severity_label} /></td>
                        <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.detail || r.message}
                        </td>
                      </tr>
                    ); })}
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
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Threat Summary</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {ipsEvents.by_threat.map((r: any, i: number) => {
                      const max = ipsEvents.by_threat[0]?.hit_count || 1;
                      const pct = Math.round((r.hit_count / max) * 100);
                      const d = drillRow({ q: r.threat }, 'var(--tint-danger)');
                      return (
                        <div key={i} {...d} style={{ background: 'var(--tint-danger)', border: '1px solid var(--tint-danger)', borderRadius: 8, padding: '10px 14px', minWidth: 150, ...(d.style || {}) }}>
                          <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--tint-danger-fg)', marginBottom: 2, wordBreak: 'break-word' }}>{r.threat}</div>
                          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'capitalize' }}>{r.subtype}</div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--tint-danger-fg)' }}>{r.hit_count} hits</span>
                            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{r.unique_sources} src</span>
                          </div>
                          <div style={{ height: 3, background: 'var(--border-light)', borderRadius: 2 }}>
                            <div style={{ height: '100%', width: `${pct}%`, background: '#dc2626', borderRadius: 2 }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div style={CARD}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>IPS Event Log</div>
                {ipsEvents.events?.length === 0 ? (
                  <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>✓ No IPS events in this period</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                    <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                      {['Time','Firewall','Src IP','Dst IP','Target / URL','Type','Severity','Threat'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {ipsEvents.events?.map((r: any, i: number) => {
                        const rowBg = i % 2 === 0 ? 'var(--tint-danger)' : 'var(--bg-card)';
                        const ipsFilter = (r.src_ip || r.source_ip) ? { host: r.src_ip || r.source_ip } : { q: r.threat_name };
                        const d = drillRow(ipsFilter, rowBg);
                        return (
                        <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, color: 'var(--text-primary)', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                          <td style={{ ...TD, ...MONO, color: '#dc2626', fontSize: 'var(--text-xs)' }}>{r.src_ip || '—'}</td>
                          <td style={{ ...TD, ...MONO, color: '#2563eb', fontSize: 'var(--text-xs)' }}>{r.dst_ip || '—'}</td>
                          <td style={{ ...TD, color: 'var(--text-secondary)', fontSize: 'var(--text-xs)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                            title={r.url || r.hostname || ''}>
                            {r.url || r.hostname || '—'}
                          </td>
                          <td style={{ ...TD, color: 'var(--text-muted)', textTransform: 'capitalize', fontSize: 'var(--text-xs)' }}>{r.subtype || r.eventtype || '—'}</td>
                          <td style={TD}><SevBadge label={r.severity_label} /></td>
                          <td style={{ ...TD, color: '#991b1b', fontWeight: 500, maxWidth: 280 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 250 }}
                                title={r.threat_name || r.message || ''}>
                                {r.threat_name || r.message || '—'}
                              </span>
                              <CrLevelBadge level={r.crlevel} />
                              {r.web_category && (
                                <span style={{ padding: '1px 6px', borderRadius: 4, fontSize: 'var(--text-xs)', fontWeight: 600,
                                  background: 'var(--tint-info)', color: 'var(--tint-info-fg)', whiteSpace: 'nowrap' }}>
                                  {r.web_category}
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ); })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* ── AFTER HOURS ── */}
          {activeSection === 'afterhours' && (
            <div style={CARD}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>After-Hours Activity</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                Security events and config changes outside business hours (before 7AM or after 7PM)
              </div>
              {afterHours.length === 0 ? (
                <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>✓ No after-hours activity detected</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                    {['Time','Hour','Device','Vendor','Event Type','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {afterHours.map((r, i) => {
                      const rowBg = i % 2 === 0 ? 'var(--tint-warn)' : 'var(--bg-card)';
                      const d = drillRow({ host: r.source_ip }, rowBg);
                      return (
                      <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                        <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleString()}</td>
                        <td style={{ ...TD, fontWeight: 700, color: '#ca8a04' }}>{String(r.hour_of_day).padStart(2,'0')}:xx</td>
                        <td style={{ ...TD, ...MONO, color: 'var(--text-primary)', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                        <td style={{ ...TD, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{r.vendor}</td>
                        <td style={TD}>
                          <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 'var(--text-xs)', fontWeight: 600,
                            background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)', border: '1px solid var(--tint-warn)' }}>
                            {r.event_type}
                          </span>
                        </td>
                        <td style={TD}><SevBadge label={r.severity_label} /></td>
                        <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                      </tr>
                    ); })}
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
                  <StatCard value={parseInt(wirelessAuth.summary.failures  || 0)} label="802.1X Failures"  color='var(--tint-danger-fg)'  bg='var(--tint-danger)'  border='var(--tint-danger)' warn />
                  <StatCard value={parseInt(wirelessAuth.summary.successes || 0)} label="Successful Auths" color='var(--tint-success-fg)' bg='var(--tint-success)' border='var(--tint-success)' />
                  <StatCard value={parseInt(wirelessAuth.summary.devices   || 0)} label="Unique Devices"   color='var(--tint-info-fg)'    bg='var(--tint-info)'    border='var(--tint-info)' />
                </div>
              )}
              <div style={CARD}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Wireless Auth Failures</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>Aruba 802.1X authentication failures by MAC address and SSID</div>
                {wirelessAuth.failures?.length === 0 ? (
                  <div style={{ padding: '32px 0', textAlign: 'center', color: '#16a34a', fontSize: 'var(--text-base)', fontWeight: 500 }}>✓ No wireless auth failures</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                    <thead><tr style={{ borderBottom: '2px solid var(--border-light)' }}>
                      {['Time','Controller','Severity','Message'].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {wirelessAuth.failures?.map((r: any, i: number) => {
                        const rowBg = i % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-card)';
                        const d = drillRow({ host: r.source_ip }, rowBg);
                        return (
                        <tr key={i} {...d} style={{ borderBottom: '1px solid var(--border-light)', background: rowBg, ...(d.style || {}) }}>
                          <td style={{ ...TD, ...MONO, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{new Date(r.received_at).toLocaleTimeString()}</td>
                          <td style={{ ...TD, ...MONO, color: 'var(--text-primary)', fontWeight: 500 }}>{r.source_host || r.source_ip}</td>
                          <td style={TD}><SevBadge label={r.severity_label} /></td>
                          <td style={{ ...TD, color: 'var(--text-secondary)', maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.message}</td>
                        </tr>
                      ); })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {activeSection === 'attack' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 16 }}>
                <StatCard value={mitreCov.length}    label="Techniques Observed" color='var(--tint-purple-fg)' bg='var(--tint-purple)' border='var(--tint-purple)' />
                <StatCard value={covTotal}           label="Mapped Events"       color='var(--tint-info-fg)'   bg='var(--tint-info)'   border='var(--tint-info)' />
                <StatCard value={covTacticsActive}   label="Tactics Active"      color='var(--tint-warn-fg)'   bg='var(--tint-warn)'   border='var(--tint-warn)' />
              </div>
              <div style={CARD}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>MITRE ATT&amp;CK Coverage</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>
                  How observed activity maps to ATT&amp;CK techniques over the selected window. Click a technique to view its logs.
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: 10, alignItems: 'start' }}>
                  {covTactics.map(tac => (
                    <div key={tac} style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                      <div style={{ padding: '6px 10px', background: 'var(--surface-subtle)', fontSize: 'var(--text-xs)',
                        fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.4px' }}>
                        {tac}
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: 6 }}>
                        {byTactic[tac].map(id => {
                          const c = covMap[id] || 0;
                          const active = c > 0;
                          return (
                            <button key={id} onClick={() => active && onTechnique?.(id)} disabled={!active || !onTechnique}
                              title={`${id} · ${MITRE_TECHNIQUES[id].name}${active ? ` — ${c.toLocaleString()} events (click to view)` : ' — no activity in window'}`}
                              style={{ textAlign: 'left', cursor: active && onTechnique ? 'pointer' : 'default',
                                border: `1px solid ${active ? 'var(--tint-purple)' : 'var(--border-light)'}`,
                                background: active ? 'var(--tint-purple)' : 'var(--bg-primary)', borderRadius: 6,
                                padding: '6px 8px', display: 'flex', flexDirection: 'column', gap: 2, opacity: active ? 1 : 0.5 }}>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 700,
                                color: active ? 'var(--tint-purple-fg)' : 'var(--text-muted)' }}>
                                {id}{active ? ` · ${c.toLocaleString()}` : ''}
                              </span>
                              <span style={{ fontSize: 'var(--text-xs)', color: active ? 'var(--tint-purple-fg)' : 'var(--text-muted)',
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {MITRE_TECHNIQUES[id].name}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
                {covTotal === 0 && (
                  <div style={{ marginTop: 14, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                    No ATT&amp;CK-mapped events in this window yet. Techniques are tagged on new logs as they arrive at the collector.
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
