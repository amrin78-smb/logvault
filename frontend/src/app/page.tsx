'use client';

import { useState, useEffect, useCallback } from 'react';
import SeverityChart   from '@/components/SeverityChart';
import TimelineChart   from '@/components/TimelineChart';
import TopTalkers      from '@/components/TopTalkers';
import VendorBreakdown from '@/components/VendorBreakdown';
import { TopSecurityEvents, TopBlockedDestinations, TopConnectionFailures, VPNStatus, ActiveAlertsSummary, InterfaceEventsSummary, FirewallActions } from '@/components/DashboardWidgets';
import LogExplorer     from '@/components/LogExplorer';
import LiveTail        from '@/components/LiveTail';
import AlertEvents     from '@/components/AlertEvents';
import NetworkHealth   from '@/components/NetworkHealth';
import SecurityAnalysis from '@/components/SecurityAnalysis';
import StorageWidget   from '@/components/StorageWidget';
import KnownHosts      from '@/components/KnownHosts';
import Header          from '@/components/Header';
import AlertBanner     from '@/components/AlertBanner';
import TimeRangePicker from '@/components/TimeRangePicker';
import ErrorBoundary   from '@/components/ErrorBoundary';
import { useTheme }    from '@/components/ThemeContext';

type Tab = 'dashboard' | 'explorer' | 'livetail' | 'alerts' | 'health' | 'security' | 'hosts';
export interface ExplorerFilter { severity?: string; vendor?: string; host?: string; hours?: string; }

const Icons: Record<Tab, JSX.Element> = {
  dashboard: (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="1" y="9" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor"/></svg>),
  explorer:  (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="1.5" rx="0.75" fill="currentColor"/><rect x="1" y="7" width="10" height="1.5" rx="0.75" fill="currentColor"/><rect x="1" y="11" width="12" height="1.5" rx="0.75" fill="currentColor"/></svg>),
  livetail:  (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill="currentColor"/><circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" fill="none" opacity="0.5"/></svg>),
  alerts:    (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M8 1L1 13h14L8 1z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" fill="none"/><line x1="8" y1="6" x2="8" y2="9.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/><circle cx="8" cy="11.5" r="0.8" fill="currentColor"/></svg>),
  health:    (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><polyline points="1,8 4,4 6,10 9,3 11,8 13,6 15,8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>),
  security:  (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><path d="M8 1L2 4v5c0 3.5 2.5 6.5 6 7.4C11.5 15.5 14 12.5 14 9V4L8 1z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/><polyline points="5,8 7,10 11,6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>),
  hosts:     (<svg width="15" height="15" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="12" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3" fill="none"/><line x1="5" y1="13" x2="11" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><line x1="8" y1="10" x2="8" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
};

export default function Home() {
  const { theme } = useTheme();
  const [tab, setTab]                       = useState<Tab>('dashboard');
  const [hours, setHours]                   = useState(24);
  const [summary, setSummary]               = useState<any[]>([]);
  const [health, setHealth]                 = useState<any>(null);
  const [explorerFilter, setExplorerFilter] = useState<ExplorerFilter>({});
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [kpiFlash, setKpiFlash]             = useState(false);

  const fetchSummary = useCallback(async () => {
    try {
      const r = await fetch(`/api/stats/summary?hours=${hours}`);
      const d = await r.json();
      setSummary(prev => {
        // Flash KPI tiles when data changes
        const prevTotal = prev.reduce((s: number, r: any) => s + parseInt(r.log_count), 0);
        const newTotal  = (d.data || []).reduce((s: number, r: any) => s + parseInt(r.log_count), 0);
        if (prev.length > 0 && newTotal !== prevTotal) { setKpiFlash(true); setTimeout(() => setKpiFlash(false), 600); }
        return d.data || [];
      });
    } catch {}
  }, [hours]);

  const fetchHealth = useCallback(async () => {
    try { const r = await fetch('/api/health'); const d = await r.json(); setHealth(d); } catch {}
  }, []);

  useEffect(() => { fetchSummary(); fetchHealth(); }, [fetchSummary, fetchHealth]);

  const openExplorer = (filter: ExplorerFilter) => {
    setExplorerFilter({ ...filter, hours: String(hours) });
    setTab('explorer');
  };

  const totalLogs  = summary.reduce((s, r) => s + parseInt(r.log_count), 0);
  const critCount  = summary.filter(r => parseInt(r.severity) <= 2).reduce((s, r) => s + parseInt(r.log_count), 0);
  const errorCount = summary.filter(r => parseInt(r.severity) === 3).reduce((s, r) => s + parseInt(r.log_count), 0);
  const warnCount  = summary.filter(r => parseInt(r.severity) === 4).reduce((s, r) => s + parseInt(r.log_count), 0);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'dashboard', label: 'Dashboard' }, { id: 'explorer', label: 'Log Explorer' },
    { id: 'livetail',  label: 'Live Tail' }, { id: 'alerts',   label: 'Alerts' },
    { id: 'health',    label: 'Network Health' }, { id: 'security', label: 'Security' },
    { id: 'hosts',     label: 'Known Hosts' },
  ];

  const KPI = [
    { label: 'TOTAL LOGS',     value: totalLogs.toLocaleString(),  color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe', filter: {} },
    { label: 'CRITICAL/ALERT', value: critCount.toLocaleString(),  color: critCount  > 0 ? '#dc2626' : '#16a34a', bg: critCount  > 0 ? '#fef2f2' : '#f0fdf4', border: critCount  > 0 ? '#fecaca' : '#bbf7d0', filter: { severity: '0,1,2' } },
    { label: 'ERRORS',         value: errorCount.toLocaleString(), color: errorCount > 0 ? '#ea580c' : '#16a34a', bg: errorCount > 0 ? '#fff7ed' : '#f0fdf4', border: errorCount > 0 ? '#fed7aa' : '#bbf7d0', filter: { severity: '3' } },
    { label: 'WARNINGS',       value: warnCount.toLocaleString(),  color: '#ca8a04', bg: '#fefce8', border: '#fde68a', filter: { severity: '4' } },
  ];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', fontFamily: 'Inter, system-ui, sans-serif', color: 'var(--text-primary)' }}>
      <Header />
      <AlertBanner />

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 52px)' }}>
        {/* Sidebar */}
        <div style={{ width: 200, background: 'var(--bg-sidebar)', flexShrink: 0, display: 'flex', flexDirection: 'column', paddingTop: 8 }}>
          {TABS.map(t => {
            const active = tab === t.id;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '10px 16px',
                  background: active ? '#1e3a5f' : 'transparent', border: 'none', cursor: 'pointer',
                  fontSize: 12, fontWeight: active ? 600 : 400, color: active ? '#ffffff' : '#94a3b8',
                  textAlign: 'left', borderLeft: active ? '3px solid #3b82f6' : '3px solid transparent',
                  transition: 'all 0.15s', width: '100%' }}
                onMouseEnter={e => { if (!active) { (e.currentTarget as HTMLElement).style.background = '#162032'; (e.currentTarget as HTMLElement).style.color = '#cbd5e1'; } }}
                onMouseLeave={e => { if (!active) { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = '#94a3b8'; } }}>
                <span style={{ opacity: active ? 1 : 0.7, flexShrink: 0 }}>{Icons[t.id]}</span>
                {t.label}
              </button>
            );
          })}

          <div style={{ margin: '10px 14px', borderTop: '1px solid #1e2d40' }} />
          <div style={{ padding: '0 12px' }}>
            <div style={{ fontSize: 9, color: '#475569', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.8px', fontWeight: 600 }}>Time Range</div>
            {[{ label: '15 min', value: 0.25 }, { label: '1 hour', value: 1 }, { label: '6 hours', value: 6 },
              { label: '24 hours', value: 24 }, { label: '48 hours', value: 48 }, { label: '7 days', value: 168 }].map(h => (
              <button key={h.value} onClick={() => setHours(h.value)}
                style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 8px', marginBottom: 3,
                  borderRadius: 5, border: '1px solid', fontSize: 11, cursor: 'pointer', textAlign: 'left',
                  background: hours === h.value ? '#1e3a5f' : 'transparent',
                  borderColor: hours === h.value ? '#3b82f6' : '#1e2d40',
                  color: hours === h.value ? '#60a5fa' : '#64748b' }}>
                {h.label}
              </button>
            ))}
          </div>

          {health && (
            <div style={{ margin: '10px 12px 14px', padding: '7px 10px', background: '#0a1f10', border: '1px solid #16a34a33', borderRadius: 7 }}>
              <div style={{ fontSize: 9, color: '#475569', marginBottom: 3, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Ingestion</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e' }} />
                <span style={{ fontSize: 12, color: '#22c55e', fontWeight: 600 }}>{health.logs_last_hour.toLocaleString()}</span>
                <span style={{ fontSize: 9, color: '#4ade80' }}>logs/hr</span>
              </div>
            </div>
          )}
        </div>

        {/* Main content */}
        <div style={{ flex: 1, padding: 16, overflow: 'auto' }}>
          {tab === 'dashboard' && (
            <>
              {/* Header row */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, position: 'relative' }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>Dashboard</div>
                <ErrorBoundary name="Time Range Picker">
                  <TimeRangePicker
                    hours={hours}
                    onHoursChange={setHours}
                    refreshInterval={refreshInterval}
                    onRefreshChange={setRefreshInterval}
                    onRefreshNow={() => { fetchSummary(); fetchHealth(); }}
                  />
                </ErrorBoundary>
              </div>

              {/* KPI tiles */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10, marginBottom: 12 }}>
                {KPI.map(kpi => (
                  <div key={kpi.label} onClick={() => openExplorer(kpi.filter)}
                    style={{ background: kpi.bg, border: `1px solid ${kpi.border}`, borderRadius: 8,
                      padding: '12px 14px', cursor: 'pointer', transition: 'transform 0.15s, box-shadow 0.15s',
                      animation: kpiFlash ? 'kpiFlash 0.6s ease' : 'none' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.transform = 'translateY(-1px)'; (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.transform = 'none'; (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
                    <div style={{ fontSize: 9, color: '#718096', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{kpi.label}</div>
                    <div style={{ fontSize: 26, fontWeight: 700, color: kpi.color, lineHeight: 1 }}>{kpi.value}</div>
                    <div style={{ fontSize: 9, color: kpi.color, marginTop: 5, fontWeight: 500 }}>last {hours}h → View logs</div>
                  </div>
                ))}
              </div>

              {/* Row 2: Severity + Active Alerts + Network Health — 3 equal */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 10 }}>
                {[
                  <ErrorBoundary name="Severity Chart">
                    <SeverityChart summary={summary} onSeverityClick={(sev) => openExplorer({ severity: sev })} compact />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Active Alerts">
                    <ActiveAlertsSummary onNavigate={() => setTab('alerts')} />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Network Health">
                    <InterfaceEventsSummary hours={hours} onNavigate={() => setTab('health')} />
                  </ErrorBoundary>,
                ].map((widget, i) => (
                  <div key={i} style={{ height: 260, overflow: 'hidden' }}>
                    {widget}
                  </div>
                ))}
              </div>

              {/* Row 3: Traffic analysis — 4 equal columns */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10, marginBottom: 10 }}>
                <ErrorBoundary name="Top Security Events">
                  <TopSecurityEvents hours={hours} onNavigate={() => setTab('security')} />
                </ErrorBoundary>
                <ErrorBoundary name="Top Connection Failures">
                  <TopConnectionFailures hours={hours} />
                </ErrorBoundary>
                <ErrorBoundary name="VPN Status">
                  <VPNStatus hours={hours} onNavigate={() => setTab('security')} />
                </ErrorBoundary>
                <ErrorBoundary name="Firewall Actions">
                  <FirewallActions hours={hours} />
                </ErrorBoundary>
              </div>

              {/* Row 4: Timeline + Top Blocked + Top Talkers + Vendor — uniform heights */}
              <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 1fr', gap: 10, marginBottom: 12 }}>
                {[
                  <ErrorBoundary name="Timeline Chart">
                    <TimelineChart hours={hours} compact />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Top Blocked">
                    <TopBlockedDestinations hours={hours} onNavigate={() => setTab('security')} />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Top Talkers">
                    <TopTalkers hours={hours} onHostClick={(host) => openExplorer({ host })} compact />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Vendor Breakdown">
                    <VendorBreakdown hours={hours} onVendorClick={(vendor) => openExplorer({ vendor })} compact />
                  </ErrorBoundary>,
                ].map((widget, i) => (
                  <div key={i} style={{ height: 220, overflow: 'hidden' }}>
                    {widget}
                  </div>
                ))}
              </div>

              <ErrorBoundary name="Storage Widget"><StorageWidget /></ErrorBoundary>
            </>
          )}

          {tab === 'explorer'  && <ErrorBoundary name="Log Explorer"><LogExplorer initialFilter={explorerFilter} onFilterUsed={() => setExplorerFilter({})} /></ErrorBoundary>}
          {tab === 'livetail'  && <ErrorBoundary name="Live Tail"><LiveTail /></ErrorBoundary>}
          {tab === 'alerts'    && <ErrorBoundary name="Alerts"><AlertEvents /></ErrorBoundary>}
          {tab === 'health'    && <ErrorBoundary name="Network Health"><NetworkHealth hours={hours} /></ErrorBoundary>}
          {tab === 'security'  && <ErrorBoundary name="Security"><SecurityAnalysis hours={hours} /></ErrorBoundary>}
          {tab === 'hosts'     && <ErrorBoundary name="Known Hosts"><KnownHosts /></ErrorBoundary>}
        </div>
      </div>
    </div>
  );
}
