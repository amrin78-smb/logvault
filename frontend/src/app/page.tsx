'use client';

import { useState, useEffect, useCallback } from 'react';
import SeverityChart   from '@/components/SeverityChart';
import TimelineChart   from '@/components/TimelineChart';
import TopTalkers      from '@/components/TopTalkers';
import VendorBreakdown from '@/components/VendorBreakdown';
import { TopSecurityEvents, TopBlockedDestinations, VPNStatus, ActiveAlertsSummary, TopServices, InterfaceEventsSummary, FirewallActions } from '@/components/DashboardWidgets';
import LogExplorer     from '@/components/LogExplorer';
import LiveTail        from '@/components/LiveTail';
import AlertEvents     from '@/components/AlertEvents';
import NetworkHealth   from '@/components/NetworkHealth';
import SecurityAnalysis from '@/components/SecurityAnalysis';
import StorageWidget   from '@/components/StorageWidget';
import KnownHosts      from '@/components/KnownHosts';
import Header          from '@/components/Header';

type Tab = 'dashboard' | 'explorer' | 'livetail' | 'alerts' | 'health' | 'security' | 'hosts';

export interface ExplorerFilter {
  severity?: string; vendor?: string; host?: string; hours?: string;
}

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
  const [tab, setTab]                       = useState<Tab>('dashboard');
  const [hours, setHours]                   = useState(24);
  const [summary, setSummary]               = useState<any[]>([]);
  const [health, setHealth]                 = useState<any>(null);
  const [explorerFilter, setExplorerFilter] = useState<ExplorerFilter>({});
  const [refreshInterval, setRefreshInterval] = useState(30);

  const fetchSummary = useCallback(async () => {
    try { const r = await fetch(`/api/stats/summary?hours=${hours}`); const d = await r.json(); setSummary(d.data || []); } catch {}
  }, [hours]);
  const fetchHealth = useCallback(async () => {
    try { const r = await fetch('/api/health'); const d = await r.json(); setHealth(d); } catch {}
  }, []);

  useEffect(() => { fetchSummary(); fetchHealth(); }, [fetchSummary, fetchHealth]);
  useEffect(() => { const t = setInterval(() => { fetchSummary(); fetchHealth(); }, refreshInterval * 1000); return () => clearInterval(t); }, [fetchSummary, fetchHealth, refreshInterval]);

  const openExplorer = (filter: ExplorerFilter) => { setExplorerFilter({ ...filter, hours: String(hours) }); setTab('explorer'); };

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

  const HOUR_OPTIONS = [{ label: '1h', value: 1 }, { label: '6h', value: 6 }, { label: '24h', value: 24 }, { label: '48h', value: 48 }, { label: '7d', value: 168 }, { label: '30d', value: 720 }];

  return (
    <div style={{ minHeight: '100vh', background: '#f0f2f5', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <Header />
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 60px)' }}>

        {/* Sidebar */}
        <div style={{ width: 200, background: '#0f1b2d', flexShrink: 0, display: 'flex', flexDirection: 'column', paddingTop: 8 }}>
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
            {[{ label: '1 hour', value: 1 }, { label: '6 hours', value: 6 }, { label: '24 hours', value: 24 }, { label: '48 hours', value: 48 }, { label: '7 days', value: 168 }].map(h => (
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

        {/* Main */}
        <div style={{ flex: 1, padding: 16, overflow: 'auto' }}>
          {tab === 'dashboard' && (
            <>
              {/* Top bar: page title + controls */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: '#1a202c' }}>Dashboard</div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  {/* Refresh */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: '#fff', border: '1px solid #e2e6ea', borderRadius: 7, padding: '4px 8px' }}>
                    <span style={{ fontSize: 10, color: '#9ca3af' }}>↻</span>
                    {[10, 30, 60, 300].map(s => (
                      <button key={s} onClick={() => setRefreshInterval(s)}
                        style={{ padding: '3px 7px', borderRadius: 4, border: 'none', fontSize: 11, cursor: 'pointer',
                          fontWeight: refreshInterval === s ? 600 : 400,
                          background: refreshInterval === s ? '#1a202c' : 'transparent',
                          color: refreshInterval === s ? '#fff' : '#6b7280' }}>
                        {s < 60 ? `${s}s` : `${s/60}m`}
                      </button>
                    ))}
                    <button onClick={() => { fetchSummary(); fetchHealth(); }}
                      style={{ padding: '3px 7px', borderRadius: 4, border: '1px solid #e2e6ea', cursor: 'pointer', fontSize: 11, background: '#f8f9fb', color: '#718096', marginLeft: 2 }}>
                      Now
                    </button>
                  </div>
                  {/* Range */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 3, background: '#fff', border: '1px solid #e2e6ea', borderRadius: 7, padding: '4px 6px' }}>
                    <span style={{ fontSize: 10, color: '#9ca3af', marginRight: 2 }}>Range</span>
                    {HOUR_OPTIONS.map(h => (
                      <button key={h.value} onClick={() => setHours(h.value)}
                        style={{ padding: '3px 8px', borderRadius: 4, border: 'none', fontSize: 11, cursor: 'pointer',
                          fontWeight: hours === h.value ? 600 : 400,
                          background: hours === h.value ? '#1a202c' : 'transparent',
                          color: hours === h.value ? '#fff' : '#6b7280' }}>
                        {h.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* KPI tiles - compact */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10, marginBottom: 12 }}>
                {KPI.map(kpi => (
                  <div key={kpi.label} onClick={() => openExplorer(kpi.filter)}
                    style={{ background: kpi.bg, border: `1px solid ${kpi.border}`, borderRadius: 8,
                      padding: '12px 14px', cursor: 'pointer', transition: 'transform 0.15s, box-shadow 0.15s' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.transform = 'translateY(-1px)'; (e.currentTarget as HTMLElement).style.boxShadow = '0 4px 12px rgba(0,0,0,0.08)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.transform = 'none'; (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}>
                    <div style={{ fontSize: 9, color: '#718096', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{kpi.label}</div>
                    <div style={{ fontSize: 26, fontWeight: 700, color: kpi.color, lineHeight: 1 }}>{kpi.value}</div>
                    <div style={{ fontSize: 9, color: kpi.color, marginTop: 5, fontWeight: 500 }}>last {hours}h → View logs</div>
                  </div>
                ))}
              </div>

              {/* Row 2: Timeline + Severity + Top Talkers + Vendor — all same height */}
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: 10, marginBottom: 10 }}>
                <div style={{ height: 220, overflow: 'hidden' }}>
                  <TimelineChart hours={hours} compact />
                </div>
                <div style={{ height: 220, overflow: 'hidden' }}>
                  <SeverityChart summary={summary} onSeverityClick={(sev) => openExplorer({ severity: sev })} compact />
                </div>
                <div style={{ height: 220, overflow: 'hidden' }}>
                  <TopTalkers hours={hours} onHostClick={(host) => openExplorer({ host })} compact />
                </div>
                <div style={{ height: 220, overflow: 'hidden' }}>
                  <VendorBreakdown hours={hours} onVendorClick={(vendor) => openExplorer({ vendor })} compact />
                </div>
              </div>

              {/* Row 3: Security widgets */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10, marginBottom: 10 }}>
                <TopSecurityEvents hours={hours} />
                <TopBlockedDestinations hours={hours} />
                <VPNStatus hours={hours} />
                <ActiveAlertsSummary onNavigate={() => setTab('alerts')} />
              </div>

              {/* Row 4: Network widgets */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 12 }}>
                <TopServices hours={hours} />
                <FirewallActions hours={hours} />
                <InterfaceEventsSummary hours={hours} onNavigate={() => setTab('health')} />
              </div>

              <StorageWidget />
            </>
          )}
          {tab === 'explorer'  && <LogExplorer initialFilter={explorerFilter} onFilterUsed={() => setExplorerFilter({})} />}
          {tab === 'livetail'  && <LiveTail />}
          {tab === 'alerts'    && <AlertEvents />}
          {tab === 'health'    && <NetworkHealth hours={hours} />}
          {tab === 'security'  && <SecurityAnalysis hours={hours} />}
          {tab === 'hosts'     && <KnownHosts />}
        </div>
      </div>
    </div>
  );
}
