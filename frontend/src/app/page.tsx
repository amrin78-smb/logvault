'use client';

import { useState, useEffect, useCallback } from 'react';
import dynamic          from 'next/dynamic';
import { useSession }  from 'next-auth/react';
import SeverityChart   from '@/components/SeverityChart';
import TimelineChart   from '@/components/TimelineChart';
import TopTalkers      from '@/components/TopTalkers';
import TopDestinations from '@/components/TopDestinations';
import VendorBreakdown from '@/components/VendorBreakdown';
import { TopSecurityEvents, TopBlockedDestinations, TopConnectionFailures, VPNStatus, ActiveAlertsSummary, InterfaceEventsSummary, FirewallActions, CapacityIngestionHealth, WhatsChanged, RiskiestEntities } from '@/components/DashboardWidgets';
import { KnownBadSources } from '@/components/ThreatIntel';
import StorageWidget   from '@/components/StorageWidget';
import Header          from '@/components/Header';
import AlertBanner     from '@/components/AlertBanner';
import TimeRangePicker from '@/components/TimeRangePicker';
import ErrorBoundary   from '@/components/ErrorBoundary';
import { useTheme }    from '@/components/ThemeContext';
import { useLicense, LicenseDisabledScreen, LicenseBanner } from '@/components/LicenseGuard';
import { PageHeader, Spinner } from '@/components/ui';
import { version as APP_VERSION } from '../../package.json';

// ── Code-split, non-Dashboard tabs (perf pass, 2026-07) ──────────────
// The Dashboard tab's own widgets (SeverityChart, TimelineChart, DashboardWidgets,
// etc. above) stay as regular static imports — they're needed immediately since
// Dashboard is the default tab, so lazy-loading them would only add loading-state
// complexity for content shown right away. Every OTHER tab's component is loaded
// on-demand instead of being bundled into the initial page load: a live audit found
// the app shipping ALL 10 tabs' JS (~1.4MB total) upfront regardless of which tab
// the user actually opens, with zero use of next/dynamic anywhere. These 9 imports
// are the fix — each becomes its own chunk, fetched only the first time its tab is
// selected. ssr:false is safe (not just an optimization) for all of them: `tab`
// state defaults to 'dashboard' and only ever changes via client-side interaction,
// so none of these conditionally-rendered branches are ever true during the
// server-render pass anyway — and LiveTail specifically depends on browser-only
// WebSocket APIs that would break under SSR if it ever were.
const tabLoading = (
  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '80px 0' }}>
    <Spinner size={22} />
  </div>
);
const LogExplorer      = dynamic(() => import('@/components/LogExplorer'),      { ssr: false, loading: () => tabLoading });
const LiveTail         = dynamic(() => import('@/components/LiveTail'),         { ssr: false, loading: () => tabLoading });
const AlertEvents      = dynamic(() => import('@/components/AlertEvents'),      { ssr: false, loading: () => tabLoading });
const NetworkHealth    = dynamic(() => import('@/components/NetworkHealth'),    { ssr: false, loading: () => tabLoading });
const SecurityAnalysis = dynamic(() => import('@/components/SecurityAnalysis'), { ssr: false, loading: () => tabLoading });
const IntelligenceConsole = dynamic(() => import('@/components/IntelligenceConsole'), { ssr: false, loading: () => tabLoading });
const KnownHosts       = dynamic(() => import('@/components/KnownHosts'),       { ssr: false, loading: () => tabLoading });
const ReportsTab       = dynamic(() => import('@/components/ReportsTab'),       { ssr: false, loading: () => tabLoading });
const Settings         = dynamic(() => import('@/components/Settings'),         { ssr: false, loading: () => tabLoading });

type Tab = 'dashboard' | 'explorer' | 'livetail' | 'alerts' | 'health' | 'security' | 'intelligence' | 'hosts' | 'reports' | 'settings';
export interface ExplorerFilter { severity?: string; vendor?: string; host?: string; hours?: string; category?: string; q?: string; technique?: string; threat?: string; }

const Icons: Record<Tab, JSX.Element> = {
  dashboard: (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="1" width="6" height="6" rx="1" fill="currentColor"/><rect x="1" y="9" width="6" height="6" rx="1" fill="currentColor"/><rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor"/></svg>),
  explorer:  (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="1.5" rx="0.75" fill="currentColor"/><rect x="1" y="7" width="10" height="1.5" rx="0.75" fill="currentColor"/><rect x="1" y="11" width="12" height="1.5" rx="0.75" fill="currentColor"/></svg>),
  livetail:  (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill="currentColor"/><circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" fill="none" opacity="0.5"/></svg>),
  alerts:    (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1L1 13h14L8 1z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" fill="none"/><line x1="8" y1="6" x2="8" y2="9.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/><circle cx="8" cy="11.5" r="0.8" fill="currentColor"/></svg>),
  health:    (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><polyline points="1,8 4,4 6,10 9,3 11,8 13,6 15,8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>),
  security:  (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1.4L2.6 3.7v4.4c0 3.3 2.3 5.5 5.4 6.5 3.1-1 5.4-3.2 5.4-6.5V3.7L8 1.4z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/><polyline points="5.4,7.8 7.2,9.6 10.6,5.9" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>),
  intelligence: (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1.6c-2.5 0-4.4 1.9-4.4 4.2 0 1.5.8 2.6 1.6 3.4.5.5.8 1 .8 1.7v.3h4v-.3c0-.7.3-1.2.8-1.7.8-.8 1.6-1.9 1.6-3.4C12.4 3.5 10.5 1.6 8 1.6z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/><line x1="6" y1="13.4" x2="10" y2="13.4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><line x1="6.6" y1="14.8" x2="9.4" y2="14.8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
  hosts:     (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="2" y="2" width="12" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3" fill="none"/><line x1="5" y1="13" x2="11" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><line x1="8" y1="10" x2="8" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
  reports:   (<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="2.5" y="1.5" width="11" height="13" rx="1.3" stroke="currentColor" strokeWidth="1.3" fill="none"/><line x1="5" y1="5" x2="11" y2="5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/><line x1="5" y1="8" x2="11" y2="8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/><line x1="5" y1="11" x2="9" y2="11" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>),
  settings:  (<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>),
};

// Suite-standard per-route nav icon chip colors. Only the ACTIVE nav item is
// colored; inactive items use the neutral faint-white chip.
const NAV_COLORS: Record<Tab, { color: string; bg: string }> = {
  dashboard: { color: '#f87171', bg: 'rgba(248,113,113,0.22)' },
  explorer:  { color: '#60a5fa', bg: 'rgba(96,165,250,0.20)' },
  livetail:  { color: '#22d3ee', bg: 'rgba(34,211,238,0.20)' },
  alerts:    { color: '#fbbf24', bg: 'rgba(251,191,36,0.20)' },
  health:    { color: '#34d399', bg: 'rgba(52,211,153,0.20)' },
  security:  { color: '#a78bfa', bg: 'rgba(167,139,250,0.20)' },
  intelligence: { color: '#f472b6', bg: 'rgba(244,114,182,0.20)' },
  hosts:     { color: '#38bdf8', bg: 'rgba(56,189,248,0.20)' },
  reports:   { color: '#fb923c', bg: 'rgba(251,146,60,0.20)' },
  settings:  { color: '#9ca3af', bg: 'rgba(156,163,175,0.20)' },
};

// Glyphs for the dashboard KPI tiles — currentColor inherits the tile accent.
const KpiIcons = {
  total:    (<svg width="17" height="17" viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="1.6" rx="0.8" fill="currentColor"/><rect x="1" y="7.2" width="10" height="1.6" rx="0.8" fill="currentColor"/><rect x="1" y="11.4" width="12" height="1.6" rx="0.8" fill="currentColor"/></svg>),
  critical: (<svg width="17" height="17" viewBox="0 0 16 16" fill="none"><path d="M8 1.6a3.4 3.4 0 0 0-3.4 3.4c0 3-1.4 3.9-1.4 3.9h9.6s-1.4-.9-1.4-3.9A3.4 3.4 0 0 0 8 1.6z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/><path d="M6.6 11.7a1.4 1.4 0 0 0 2.8 0" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
  error:    (<svg width="17" height="17" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.4" stroke="currentColor" strokeWidth="1.3" fill="none"/><line x1="5.8" y1="5.8" x2="10.2" y2="10.2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><line x1="10.2" y1="5.8" x2="5.8" y2="10.2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>),
  warning:  (<svg width="17" height="17" viewBox="0 0 16 16" fill="none"><path d="M8 2L1.6 13.4h12.8L8 2z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/><line x1="8" y1="6.4" x2="8" y2="9.6" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><circle cx="8" cy="11.4" r="0.75" fill="currentColor"/></svg>),
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
      background: '#16a34a', color: '#ffffff', fontSize: 'var(--text-base)', fontWeight: 600 }}>
      <span aria-hidden>✓</span>
      <span style={{ flex: 1 }}>LogVault updated successfully</span>
      <button onClick={() => setShow(false)} aria-label="Dismiss"
        style={{ background: 'transparent', border: 'none', color: '#ffffff', fontSize: 'var(--text-lg)',
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
  const [alertTechnique, setAlertTechnique] = useState<string | undefined>(undefined);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [kpiFlash, setKpiFlash]             = useState(false);
  // Sidebar collapse — suite-standard 240↔64px, persisted to localStorage so it
  // survives refresh (matches netvault/ddivault/spanvault).
  const [collapsed, setCollapsed]           = useState(false);
  useEffect(() => {
    try { setCollapsed(localStorage.getItem('logvault-sidebar-collapsed') === 'true'); } catch {}
  }, []);
  const toggleCollapsed = () => setCollapsed(c => {
    const next = !c;
    try { localStorage.setItem('logvault-sidebar-collapsed', String(next)); } catch {}
    return next;
  });

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

  // Cache-busting query param: see Header.tsx pollHealth comment.
  const fetchHealth = useCallback(async () => {
    try { const r = await fetch(`/api/health?_=${Date.now()}`); const d = await r.json(); setHealth(d); } catch {}
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

  const openAlerts = (technique?: string) => {
    setAlertTechnique(technique);
    setTab('alerts');
  };

  const totalLogs  = summary.reduce((s, r) => s + parseInt(r.log_count), 0);
  const critCount  = summary.filter(r => parseInt(r.severity) <= 2).reduce((s, r) => s + parseInt(r.log_count), 0);
  const errorCount = summary.filter(r => parseInt(r.severity) === 3).reduce((s, r) => s + parseInt(r.log_count), 0);
  const warnCount  = summary.filter(r => parseInt(r.severity) === 4).reduce((s, r) => s + parseInt(r.log_count), 0);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'dashboard', label: 'Dashboard' }, { id: 'explorer', label: 'Log Explorer' },
    { id: 'livetail',  label: 'Live Tail' }, { id: 'alerts',   label: 'Alerts' },
    { id: 'health',    label: 'Network Health' }, { id: 'security', label: 'Security' },
    { id: 'intelligence', label: 'Intelligence' },
    { id: 'hosts',     label: 'Known Hosts' },
    { id: 'reports',   label: 'Reports' },
    // Settings is admin-only (super_admin / admin)
    ...(isAdmin ? [{ id: 'settings' as Tab, label: 'Settings' }] : []),
  ];

  const KPI = [
    // Total Logs: navy left-border accent, but value text uses --text-primary so it
    // stays readable in dark mode (navy #1a2744 is invisible on the dark card bg).
    { label: 'Total Logs',       value: totalLogs.toLocaleString(),  accent: 'var(--navy)',                                  valueColor: 'var(--text-primary)',                       filter: {},                  icon: KpiIcons.total },
    { label: 'Critical / Alert', value: critCount.toLocaleString(),  accent: critCount  > 0 ? 'var(--red)'    : 'var(--green)', valueColor: critCount  > 0 ? 'var(--red)'    : 'var(--green)', filter: { severity: '0,1,2' }, icon: KpiIcons.critical },
    { label: 'Errors',           value: errorCount.toLocaleString(), accent: errorCount > 0 ? 'var(--orange)' : 'var(--green)', valueColor: errorCount > 0 ? 'var(--orange)' : 'var(--green)', filter: { severity: '3' },     icon: KpiIcons.error },
    { label: 'Warnings',         value: warnCount.toLocaleString(),  accent: warnCount  > 0 ? 'var(--yellow)' : 'var(--green)', valueColor: warnCount  > 0 ? 'var(--yellow)' : 'var(--green)', filter: { severity: '4' },     icon: KpiIcons.warning },
  ];

  if (!licenseLoading && licenseState.disabled) {
    return <LicenseDisabledScreen mode={licenseState.mode} />;
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', fontFamily: 'Inter, system-ui, sans-serif', color: 'var(--text-primary)' }}>
      <Header />

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 72px)' }}>
        {/* Sidebar — pinned to the viewport (sticky) so the footer/version stays
            visible at the bottom of the screen instead of the bottom of the scrolled
            page. Collapsible 240↔64px, matching the rest of the suite. */}
        <div style={{ width: collapsed ? 64 : 240, background: '#1a2744', flexShrink: 0,
          display: 'flex', flexDirection: 'column', paddingTop: 16,
          position: 'sticky', top: 72, height: 'calc(100vh - 72px)', alignSelf: 'flex-start',
          overflowX: 'hidden', overflowY: 'auto', transition: 'width 0.18s ease' }}>
          {!collapsed && (
            <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'rgba(255,255,255,0.35)', letterSpacing: '1.2px', padding: '0 24px', marginBottom: 10 }}>
              NAVIGATION
            </div>
          )}
          {collapsed && <div style={{ height: 6 }} />}
          {TABS.map(t => {
            const active = tab === t.id;
            const chip = NAV_COLORS[t.id];
            return (
              <button key={t.id} onClick={() => setTab(t.id)} title={collapsed ? t.label : undefined}
                style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 12,
                  padding: collapsed ? '11px 0' : '11px 20px', margin: '1px 10px', borderRadius: 10, border: 'none', cursor: 'pointer',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  background: active ? 'rgba(200,16,46,0.15)' : 'transparent',
                  fontSize: 'var(--text-md)', fontWeight: active ? 600 : 500,
                  color: active ? '#ffffff' : 'rgba(255,255,255,0.55)',
                  textAlign: 'left', transition: 'all 0.15s' }}
                onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.06)'; }}
                onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                {active && <span style={{ position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)', width: 3, height: 20, borderRadius: '0 2px 2px 0', background: 'var(--primary)' }} />}
                <span style={{ width: 28, height: 28, borderRadius: 8, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.15s', background: active ? chip.bg : 'rgba(255,255,255,0.07)', color: active ? chip.color : 'rgba(255,255,255,0.45)' }}>{Icons[t.id]}</span>
                {!collapsed && t.label}
              </button>
            );
          })}

          {!collapsed && <div style={{ margin: '14px 16px 10px', borderTop: '1px solid rgba(255,255,255,0.08)' }} />}

          {health && !collapsed && (
            <div style={{ margin: '12px 14px', padding: '8px 12px', background: 'rgba(22,163,74,0.08)', border: '1px solid rgba(22,163,74,0.2)', borderRadius: 10 }}>
              <div style={{ fontSize: 'var(--text-xs)', color: 'rgba(255,255,255,0.35)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 700 }}>Ingestion</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e' }} />
                <span style={{ fontSize: 'var(--text-sm)', color: '#22c55e', fontWeight: 600 }}>{health.logs_last_hour.toLocaleString()}</span>
                <span style={{ fontSize: 'var(--text-xs)', color: '#4ade80' }}>logs/hr</span>
              </div>
            </div>
          )}

          <div style={{ flex: 1 }} />

          {/* Collapse toggle — suite-standard chevron, rotates 180° when collapsed */}
          <button onClick={toggleCollapsed} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            style={{ display: 'flex', alignItems: 'center', gap: 10,
              justifyContent: collapsed ? 'center' : 'flex-start',
              margin: '4px 10px', padding: collapsed ? '10px 0' : '10px 12px',
              background: 'transparent', border: 'none', borderRadius: 10, cursor: 'pointer',
              color: 'rgba(255,255,255,0.4)', fontSize: 'var(--text-sm)', transition: 'all 0.15s' }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.06)'; (e.currentTarget as HTMLElement).style.color = '#ffffff'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = 'rgba(255,255,255,0.4)'; }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
              style={{ transform: collapsed ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s', flexShrink: 0 }}>
              <polyline points="15 18 9 12 15 6" />
            </svg>
            {!collapsed && <span style={{ whiteSpace: 'nowrap' }}>Collapse</span>}
          </button>

          {!collapsed && (
            <div style={{ padding: '8px 24px 14px', fontSize: 'var(--text-xs)', color: 'rgba(255,255,255,0.25)', letterSpacing: '0.5px', fontWeight: 500 }}>
              LogVault v{health?.version || APP_VERSION}
            </div>
          )}
        </div>

        {/* Main content column — banners live INSIDE here so they span only the
            content width (not the full screen over the sidebar), matching the suite.
            The tab content below them keeps the 16px padding. */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'auto' }}>
          <LicenseBanner />
          <AlertBanner />
          <UpdatedNotice />
          {/* Site-restriction notice for regular users */}
          {role === 'user' && (
            <div style={{ background: '#1a2744', color: '#ffffff', padding: '8px 20px',
              fontSize: 'var(--text-sm)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                <path d="M8 1L2 4v5c0 3.5 2.5 6.5 6 7.4C11.5 15.5 14 12.5 14 9V4L8 1z"
                  stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round" />
              </svg>
              Your access is restricted to your assigned sites only
            </div>
          )}
          <div style={{ flex: 1, padding: 16 }}>
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
                    style={{ borderLeftColor: kpi.accent, cursor: 'pointer', padding: '12px 14px',
                      animation: kpiFlash ? 'kpiFlash 0.6s ease' : 'none' }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                      <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 800, letterSpacing: '-0.5px', lineHeight: 1.1, color: kpi.valueColor }}>{kpi.value}</div>
                      <div style={{ width: 32, height: 32, borderRadius: 9, flexShrink: 0, color: kpi.accent,
                        background: `color-mix(in srgb, ${kpi.accent} 13%, transparent)`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{kpi.icon}</div>
                    </div>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginTop: 7 }}>{kpi.label}</div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2 }}>last {hours}h → View logs</div>
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

              {/* Row 3: Top Security Events + VPN Status + Firewall Actions — 3 equal columns */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 10 }}>
                <ErrorBoundary name="Top Security Events">
                  <TopSecurityEvents hours={hours} onNavigate={() => setTab('security')} />
                </ErrorBoundary>
                <ErrorBoundary name="VPN Status">
                  <VPNStatus hours={hours} onNavigate={() => setTab('security')} />
                </ErrorBoundary>
                <ErrorBoundary name="Firewall Actions">
                  <FirewallActions hours={hours} />
                </ErrorBoundary>
              </div>

              {/* Row 4: Top Blocked + Top Connection Failures + Top Destinations — 3 equal,
                  all single-line IP + flag/country/ASN/known-bad widgets */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 10 }}>
                {[
                  <ErrorBoundary name="Top Blocked">
                    <TopBlockedDestinations hours={hours} onNavigate={() => setTab('security')} />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Top Connection Failures">
                    <TopConnectionFailures hours={hours} />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Top Destinations">
                    {/* Drill into the destination IP via the existing host filter — it
                        already matches structured_data.dstip, so this mirrors Top Talkers'
                        source drill-down without a separate (riskier) dst filter path. */}
                    <TopDestinations hours={hours} onHostClick={(host) => openExplorer({ host })} />
                  </ErrorBoundary>,
                ].map((widget, i) => (
                  <div key={i} style={{ height: 220, overflow: 'hidden' }}>
                    {widget}
                  </div>
                ))}
              </div>

              {/* Row 5: Timeline + Top Talkers (source) + Vendor Breakdown — 3 equal */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 12 }}>
                {[
                  <ErrorBoundary name="Timeline Chart">
                    <TimelineChart hours={hours} compact />
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

              {/* Row 6: Capacity & Ingestion Health + What's New / Changed — 2 equal columns */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                {[
                  <ErrorBoundary name="Capacity & Ingestion Health">
                    <CapacityIngestionHealth openExplorer={openExplorer} />
                  </ErrorBoundary>,
                  <ErrorBoundary name="What's New / Changed">
                    <WhatsChanged openExplorer={openExplorer} />
                  </ErrorBoundary>,
                ].map((widget, i) => (
                  <div key={i} style={{ height: 340, overflow: 'hidden' }}>
                    {widget}
                  </div>
                ))}
              </div>

              {/* Row 7: Intelligence — riskiest entities (UEBA) + known-bad external sources */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
                {[
                  <ErrorBoundary name="Riskiest Entities">
                    <RiskiestEntities openExplorer={openExplorer} onNavigate={() => setTab('intelligence')} />
                  </ErrorBoundary>,
                  <ErrorBoundary name="Known-Bad Sources">
                    <KnownBadSources onNavigate={(ip) => openExplorer({ host: ip })} />
                  </ErrorBoundary>,
                ].map((widget, i) => (
                  <div key={i} style={{ height: 320, overflow: 'hidden' }}>
                    {widget}
                  </div>
                ))}
              </div>

              <ErrorBoundary name="Storage Widget"><StorageWidget /></ErrorBoundary>
            </>
          )}

          {tab === 'explorer'  && <ErrorBoundary name="Log Explorer"><LogExplorer initialFilter={explorerFilter} onFilterUsed={() => setExplorerFilter({})} /></ErrorBoundary>}
          {tab === 'livetail'  && <ErrorBoundary name="Live Tail"><LiveTail /></ErrorBoundary>}
          {tab === 'alerts'    && <ErrorBoundary name="Alerts"><AlertEvents initialTechnique={alertTechnique} hours={hours} onTechniqueConsumed={() => setAlertTechnique(undefined)} /></ErrorBoundary>}
          {tab === 'health'    && <ErrorBoundary name="Network Health"><NetworkHealth hours={hours} onHoursChange={setHours} refreshInterval={refreshInterval} onRefreshChange={setRefreshInterval} /></ErrorBoundary>}
          {tab === 'security'  && <ErrorBoundary name="Security"><SecurityAnalysis hours={hours} onHoursChange={setHours} refreshInterval={refreshInterval} onRefreshChange={setRefreshInterval} onTechnique={(t, info) => (info && info.alerts > 0 ? openAlerts(t) : openExplorer({ technique: t }))} onDrill={openExplorer} /></ErrorBoundary>}
          {tab === 'intelligence' && <ErrorBoundary name="Intelligence"><IntelligenceConsole openExplorer={openExplorer} hours={String(hours)} /></ErrorBoundary>}
          {tab === 'hosts'     && <ErrorBoundary name="Known Hosts"><KnownHosts /></ErrorBoundary>}
          {tab === 'reports'   && <ErrorBoundary name="Reports"><ReportsTab /></ErrorBoundary>}
          {tab === 'settings'  && isAdmin && <ErrorBoundary name="Settings"><Settings /></ErrorBoundary>}
          </div>
        </div>
      </div>
    </div>
  );
}
