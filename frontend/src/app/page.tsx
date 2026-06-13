'use client';

import { useState, useEffect, useCallback } from 'react';
import { useSession }  from 'next-auth/react';
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
import Settings        from '@/components/Settings';
import Header          from '@/components/Header';
import AlertBanner     from '@/components/AlertBanner';
import TimeRangePicker from '@/components/TimeRangePicker';
import ErrorBoundary   from '@/components/ErrorBoundary';
import { useTheme }    from '@/components/ThemeContext';
import { useLicense, LicenseDisabledScreen } from '@/components/LicenseGuard';
import { PageHeader }  from '@/components/ui';
import { version as APP_VERSION } from '../../package.json';

type Tab = 'dashboard' | 'explorer' | 'livetail' | 'alerts' | 'health' | 'security' | 'hosts' | 'settings';
export interface ExplorerFilter { severity?: string; vendor?: string; host?: string; hours?: string; category?: string; q?: string; }

const Icons: Record<Tab, JSX.Element> = {
  dashboard: (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="1" y="9" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor"/></svg>),
  explorer:  (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="1.5" rx="0.75" fill="currentColor"/><rect x="1" y="7" width="10" height="1.5" rx="0.75" fill="currentColor"/><rect x="1" y="11" width="12" height="1.5" rx="0.75" fill="currentColor"/></svg>),
  livetail:  (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill="currentColor"/><circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" fill="none" opacity="0.5"/></svg>),
  alerts:    (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><path d="M8 1L1 13h14L8 1z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" fill="none"/><line x1="8" y1="6" x2="8" y2="9.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/><circle cx="8" cy="11.5" r="0.8" fill="currentColor"/></svg>),
  health:    (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><polyline points="1,8 4,4 6,10 9,3 11,8 13,6 15,8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>),
  security:  (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><path d="M8 1L2 4v5c0 3.5 2.5 6.5 6 7.4C11.5 15.5 14 12.5 14 9V4L8 1z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/><polyline points="5,8 7,10 11,6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>),
  hosts:     (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="12" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3" fill="none"/><line x1="5" y1="13" x2="11" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><line x1="8" y1="10" x2="8" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
  settings:  (<svg width="18" height="18" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="2.5" stroke="currentColor" strokeWidth="1.3" fill="none"/><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.05 3.05l1.06 1.06M11.89 11.89l1.06 1.06M3.05 12.95l1.06-1.06M11.89 4.11l1.06-1.06" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
};

// Dismissible success banner shown after the in-app updater redirects here with
// ?updated=true. Reads the query param on mount (no useSearchParams → no Suspense
// requirement) and strips it so a refresh won't re-show it. Auto-dismisses after
// 5 seconds. Defined at module level — never inside another component.
function UpdatedNotice() {
  const [show, setShow] = useState(false);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('updated') === 'true') {
      setShow(true);
      window.history.replaceState({}, '', window.location.pathname);
      const t = setTimeout(() => setShow(false), 5000);
      return () => clearTimeout(t);
    }
  }, []);
  if (!show) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 20px',
      background: '#16a34a', color: '#ffffff', fontSize: 13, fontWeight: 600 }}>
      <span aria-hidden>✓</span>
      <span style={{ flex: 1 }}>LogVault updated successfully</span>
      <button onClick={() => setShow(false)} aria-label="Dismiss"
        style={{ background: 'transparent', border: 'none', color: '#ffffff', fontSize: 16,
          lineHeight: 1, cursor: 'pointer', padding: 0 }}>
        ×
      </button>
    </div>
  );
}

export default function Home() {
  const { theme } = useTheme();
  const { data: session } = useSession();
  const { state: licenseState, loading: licenseLoading } = useLicense();
  const role        = ((session?.user as any)?.role as string) || 'user';
  const isAdmin     = role === 'admin' || role === 'super_admin';
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

  // Global "R" — refresh current tab (broadcasts to data components + dashboard)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'r' && e.key !== 'R') return;
      const el = document.activeElement as HTMLElement | null;
      const typing = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      e.preventDefault();
      window.dispatchEvent(new Event('nocvault:refresh'));
      fetchSummary();
      fetchHealth();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [fetchSummary, fetchHealth]);

  // Cross-component navigation — e.g. notifications bell jumps to Alerts tab
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (detail?.tab) setTab(detail.tab as Tab);
    };
    window.addEventListener('nocvault:navigate', handler);
    return () => window.removeEventListener('nocvault:navigate', handler);
  }, []);

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
    // Settings is admin-only (super_admin / admin)
    ...(isAdmin ? [{ id: 'settings' as Tab, label: 'Settings' }] : []),
  ];

  const KPI = [
    { label: 'Total Logs',       value: totalLogs.toLocaleString(),  accent: 'var(--navy)',                                  filter: {} },
    { label: 'Critical / Alert', value: critCount.toLocaleString(),  accent: critCount  > 0 ? 'var(--red)'    : 'var(--green)', filter: { severity: '0,1,2' } },
    { label: 'Errors',           value: errorCount.toLocaleString(), accent: errorCount > 0 ? 'var(--orange)' : 'var(--green)', filter: { severity: '3' } },
    { label: 'Warnings',         value: warnCount.toLocaleString(),  accent: warnCount  > 0 ? 'var(--yellow)' : 'var(--green)', filter: { severity: '4' } },
  ];

  if (!licenseLoading && licenseState.disabled) {
    return <LicenseDisabledScreen />;
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', fontFamily: 'Inter, system-ui, sans-serif', color: 'var(--text-primary)' }}>
      <Header />
      <AlertBanner />
      <UpdatedNotice />

      {/* Site-restriction notice for regular users */}
      {role === 'user' && (
        <div style={{ background: '#1a2744', color: '#ffffff', padding: '8px 20px',
          fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
            <path d="M8 1L2 4v5c0 3.5 2.5 6.5 6 7.4C11.5 15.5 14 12.5 14 9V4L8 1z"
              stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round" />
          </svg>
          Your access is restricted to your assigned sites only
        </div>
      )}

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 52px)' }}>
        {/* Sidebar */}
        <div style={{ width: 240, background: '#1a2744', flexShrink: 0, display: 'flex', flexDirection: 'column', paddingTop: 16 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'rgba(255,255,255,0.35)', letterSpacing: '1.2px', padding: '0 24px', marginBottom: 10 }}>
            NAVIGATION
          </div>
          {TABS.map(t => {
            const active = tab === t.id;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 11,
                  padding: '11px 20px', margin: '1px 10px', borderRadius: 10, border: 'none', cursor: 'pointer',
                  background: active ? 'rgba(200,16,46,0.15)' : 'transparent',
                  fontSize: 13, fontWeight: active ? 600 : 500,
                  color: active ? '#ffffff' : 'rgba(255,255,255,0.5)',
                  textAlign: 'left', transition: 'all 0.15s' }}
                onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.06)'; }}
                onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                {active && <span style={{ position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)', width: 3, height: 20, borderRadius: '0 2px 2px 0', background: '#C8102E' }} />}
                <span style={{ display: 'flex', flexShrink: 0, color: active ? '#C8102E' : 'currentColor' }}>{Icons[t.id]}</span>
                {t.label}
              </button>
            );
          })}

          <div style={{ margin: '14px 16px 10px', borderTop: '1px solid rgba(255,255,255,0.08)' }} />

          {health && (
            <div style={{ margin: '12px 14px', padding: '8px 12px', background: 'rgba(22,163,74,0.08)', border: '1px solid rgba(22,163,74,0.2)', borderRadius: 10 }}>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 700 }}>Ingestion</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e' }} />
                <span style={{ fontSize: 12, color: '#22c55e', fontWeight: 600 }}>{health.logs_last_hour.toLocaleString()}</span>
                <span style={{ fontSize: 9, color: '#4ade80' }}>logs/hr</span>
              </div>
            </div>
          )}

          <div style={{ flex: 1 }} />
          <div style={{ padding: '14px 24px', fontSize: 10, color: 'rgba(255,255,255,0.25)', letterSpacing: '0.5px', fontWeight: 500 }}>
            LogVault v{health?.version || APP_VERSION}
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1, padding: 16, overflow: 'auto' }}>
          {tab === 'dashboard' && (
            <>
              {/* Header row */}
              <PageHeader title="Dashboard" subtitle="Real-time syslog overview & traffic analysis">
                <ErrorBoundary name="Time Range Picker">
                  <TimeRangePicker
                    hours={hours}
                    onHoursChange={setHours}
                    refreshInterval={refreshInterval}
                    onRefreshChange={setRefreshInterval}
                    onRefreshNow={() => { fetchSummary(); fetchHealth(); }}
                  />
                </ErrorBoundary>
              </PageHeader>

              {/* KPI tiles */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 12 }}>
                {KPI.map(kpi => (
                  <div key={kpi.label} className="kpi-card" onClick={() => openExplorer(kpi.filter)}
                    style={{ borderLeftColor: kpi.accent, cursor: 'pointer',
                      animation: kpiFlash ? 'kpiFlash 0.6s ease' : 'none' }}>
                    <div style={{ fontSize: 36, fontWeight: 800, letterSpacing: '-1px', lineHeight: 1, color: kpi.accent }}>{kpi.value}</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginTop: 8 }}>{kpi.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>last {hours}h → View logs</div>
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
          {tab === 'settings'  && isAdmin && <ErrorBoundary name="Settings"><Settings /></ErrorBoundary>}
        </div>
      </div>
    </div>
  );
}
