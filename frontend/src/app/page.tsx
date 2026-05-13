'use client';

import { useState, useEffect, useCallback } from 'react';
import SeverityChart   from '@/components/SeverityChart';
import TimelineChart   from '@/components/TimelineChart';
import TopTalkers      from '@/components/TopTalkers';
import VendorBreakdown from '@/components/VendorBreakdown';
import RecentCritical  from '@/components/RecentCritical';
import LogExplorer     from '@/components/LogExplorer';
import LiveTail        from '@/components/LiveTail';
import AlertEvents     from '@/components/AlertEvents';
import KnownHosts      from '@/components/KnownHosts';
import NetworkHealth   from '@/components/NetworkHealth';
import SecurityAnalysis from '@/components/SecurityAnalysis';
import StorageWidget   from '@/components/StorageWidget';
import Header          from '@/components/Header';

type Tab = 'dashboard' | 'explorer' | 'livetail' | 'alerts' | 'health' | 'security' | 'hosts';

export interface ExplorerFilter {
  severity?: string;
  vendor?: string;
  host?: string;
  hours?: string;
}

const Icons: Record<Tab, JSX.Element> = {
  dashboard: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="1" y="1" width="6" height="6" rx="1" fill="currentColor" opacity="0.9"/>
      <rect x="9" y="1" width="6" height="6" rx="1" fill="currentColor" opacity="0.9"/>
      <rect x="1" y="9" width="6" height="6" rx="1" fill="currentColor" opacity="0.9"/>
      <rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor" opacity="0.9"/>
    </svg>
  ),
  explorer: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="1" y="3" width="14" height="1.5" rx="0.75" fill="currentColor"/>
      <rect x="1" y="7" width="10" height="1.5" rx="0.75" fill="currentColor"/>
      <rect x="1" y="11" width="12" height="1.5" rx="0.75" fill="currentColor"/>
      <circle cx="13" cy="11.75" r="2.5" stroke="currentColor" strokeWidth="1.3" fill="none"/>
      <line x1="14.8" y1="13.5" x2="16" y2="14.7" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ),
  livetail: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="3" fill="currentColor"/>
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" fill="none" opacity="0.5"/>
    </svg>
  ),
  alerts: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M8 1L1 13h14L8 1z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" fill="none"/>
      <line x1="8" y1="6" x2="8" y2="9.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <circle cx="8" cy="11.5" r="0.8" fill="currentColor"/>
    </svg>
  ),
  health: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <polyline points="1,8 4,4 6,10 9,3 11,8 13,6 15,8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    </svg>
  ),
  security: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M8 1L2 4v5c0 3.5 2.5 6.5 6 7.4C11.5 15.5 14 12.5 14 9V4L8 1z" stroke="currentColor" strokeWidth="1.3" fill="none" strokeLinejoin="round"/>
      <polyline points="5,8 7,10 11,6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  hosts: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="2" y="2" width="12" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3" fill="none"/>
      <line x1="5" y1="13" x2="11" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
      <line x1="8" y1="10" x2="8" y2="13" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
      <circle cx="5.5" cy="6" r="1" fill="currentColor"/>
      <circle cx="8" cy="6" r="1" fill="currentColor"/>
      <circle cx="10.5" cy="6" r="1" fill="currentColor"/>
    </svg>
  ),
};

export default function Home() {
  const [tab, setTab]                       = useState<Tab>('dashboard');
  const [hours, setHours]                   = useState(24);
  const [summary, setSummary]               = useState<any[]>([]);
  const [health, setHealth]                 = useState<any>(null);
  const [explorerFilter, setExplorerFilter] = useState<ExplorerFilter>({});

  const fetchSummary = useCallback(async () => {
    try { const r = await fetch(`/api/stats/summary?hours=${hours}`); const d = await r.json(); setSummary(d.data || []); } catch {}
  }, [hours]);

  const fetchHealth = useCallback(async () => {
    try { const r = await fetch('/api/health'); const d = await r.json(); setHealth(d); } catch {}
  }, []);

  useEffect(() => { fetchSummary(); fetchHealth(); }, [fetchSummary, fetchHealth]);
  useEffect(() => {
    const t = setInterval(() => { fetchSummary(); fetchHealth(); }, 30000);
    return () => clearInterval(t);
  }, [fetchSummary, fetchHealth]);

  const openExplorer = (filter: ExplorerFilter) => {
    setExplorerFilter({ ...filter, hours: String(hours) });
    setTab('explorer');
  };

  const totalLogs  = summary.reduce((s, r) => s + parseInt(r.log_count), 0);
  const critCount  = summary.filter(r => parseInt(r.severity) <= 2).reduce((s, r) => s + parseInt(r.log_count), 0);
  const errorCount = summary.filter(r => parseInt(r.severity) === 3).reduce((s, r) => s + parseInt(r.log_count), 0);
  const warnCount  = summary.filter(r => parseInt(r.severity) === 4).reduce((s, r) => s + parseInt(r.log_count), 0);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'explorer',  label: 'Log Explorer' },
    { id: 'livetail',  label: 'Live Tail' },
    { id: 'alerts',    label: 'Alerts' },
    { id: 'health',    label: 'Network Health' },
    { id: 'security',  label: 'Security' },
    { id: 'hosts',     label: 'Known Hosts' },
  ];

  const KPI = [
    { label: 'TOTAL LOGS',     value: totalLogs.toLocaleString(),  color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe', filter: {} },
    { label: 'CRITICAL/ALERT', value: critCount.toLocaleString(),  color: critCount  > 0 ? '#dc2626' : '#16a34a', bg: critCount  > 0 ? '#fef2f2' : '#f0fdf4', border: critCount  > 0 ? '#fecaca' : '#bbf7d0', filter: { severity: '0,1,2' } },
    { label: 'ERRORS',         value: errorCount.toLocaleString(), color: errorCount > 0 ? '#ea580c' : '#16a34a', bg: errorCount > 0 ? '#fff7ed' : '#f0fdf4', border: errorCount > 0 ? '#fed7aa' : '#bbf7d0', filter: { severity: '3' } },
    { label: 'WARNINGS',       value: warnCount.toLocaleString(),  color: '#ca8a04', bg: '#fefce8', border: '#fde68a', filter: { severity: '4' } },
  ];

  const HOUR_OPTIONS = [
    { label: '1h', value: 1 }, { label: '6h', value: 6 }, { label: '24h', value: 24 },
    { label: '48h', value: 48 }, { label: '7d', value: 168 }, { label: '30d', value: 720 },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#f0f2f5', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <Header />
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 60px)' }}>

        {/* Sidebar */}
        <div style={{ width: 210, background: '#0f1b2d', flexShrink: 0, display: 'flex', flexDirection: 'column', paddingTop: 8 }}>
          {TABS.map(t => {
            const active = tab === t.id;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '11px 18px',
                  background: active ? '#1e3a5f' : 'transparent', border: 'none', cursor: 'pointer',
                  fontSize: 13, fontWeight: active ? 600 : 400,
                  color: active ? '#ffffff' : '#94a3b8', textAlign: 'left',
                  borderLeft: active ? '3px solid #3b82f6' : '3px solid transparent',
                  transition: 'all 0.15s', width: '100%' }}
                onMouseEnter={e => { if (!active) { (e.currentTarget as HTMLElement).style.background = '#162032'; (e.currentTarget as HTMLElement).style.color = '#cbd5e1'; } }}
                onMouseLeave={e => { if (!active) { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = '#94a3b8'; } }}>
                <span style={{ opacity: active ? 1 : 0.7, flexShrink: 0 }}>{Icons[t.id]}</span>
                {t.label}
              </button>
            );
          })}

          <div style={{ margin: '12px 16px', borderTop: '1px solid #1e2d40' }} />

          <div style={{ padding: '0 14px' }}>
            <div style={{ fontSize: 10, color: '#475569', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.8px', fontWeight: 600 }}>Time Range</div>
            {[{ label: '1 hour', value: 1 }, { label: '6 hours', value: 6 }, { label: '24 hours', value: 24 },
              { label: '48 hours', value: 48 }, { label: '7 days', value: 168 }].map(h => (
              <button key={h.value} onClick={() => setHours(h.value)}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px',
                  marginBottom: 3, borderRadius: 6, border: '1px solid', fontSize: 12, cursor: 'pointer',
                  textAlign: 'left', background: hours === h.value ? '#1e3a5f' : 'transparent',
                  borderColor: hours === h.value ? '#3b82f6' : '#1e2d40',
                  color: hours === h.value ? '#60a5fa' : '#64748b', transition: 'all 0.15s' }}>
                <svg width="10" height="10" viewBox="0 0 10 10" fill="none" style={{ flexShrink: 0 }}>
                  <circle cx="5" cy="5" r="4" stroke="currentColor" strokeWidth="1.2" fill="none"/>
                  <line x1="5" y1="2" x2="5" y2="5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
                  <line x1="5" y1="5" x2="7" y2="6.2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
                </svg>
                {h.label}
              </button>
            ))}
          </div>

          {health && (
            <div style={{ margin: '12px 14px 16px', padding: '8px 10px',
              background: '#0a1f10', border: '1px solid #16a34a33', borderRadius: 8 }}>
              <div style={{ fontSize: 10, color: '#475569', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Ingestion Rate</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e' }} />
                <span style={{ fontSize: 13, color: '#22c55e', fontWeight: 600 }}>{health.logs_last_hour.toLocaleString()}</span>
                <span style={{ fontSize: 10, color: '#4ade80' }}>logs/hr</span>
              </div>
            </div>
          )}
        </div>

        {/* Main content */}
        <div style={{ flex: 1, padding: 20, overflow: 'auto' }}>
          {tab === 'dashboard' && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: '#1a202c', letterSpacing: '-0.3px' }}>Dashboard</div>
                  <div style={{ fontSize: 12, color: '#718096', marginTop: 2 }}>Real-time syslog overview</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4,
                  background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 8, padding: '5px 6px',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
                  <span style={{ fontSize: 10, color: '#9ca3af', marginRight: 4, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Range</span>
                  {HOUR_OPTIONS.map(h => (
                    <button key={h.value} onClick={() => setHours(h.value)}
                      style={{ padding: '4px 10px', borderRadius: 5, border: 'none', fontSize: 12,
                        cursor: 'pointer', fontWeight: hours === h.value ? 600 : 400,
                        background: hours === h.value ? '#1a202c' : 'transparent',
                        color: hours === h.value ? '#ffffff' : '#6b7280', transition: 'all 0.15s' }}>
                      {h.label}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 20 }}>
                {KPI.map(kpi => (
                  <div key={kpi.label} onClick={() => openExplorer(kpi.filter)}
                    style={{ background: kpi.bg, border: `1px solid ${kpi.border}`, borderRadius: 10,
                      padding: '18px 20px', cursor: 'pointer', transition: 'transform 0.15s, box-shadow 0.15s',
                      boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)'; (e.currentTarget as HTMLElement).style.boxShadow = '0 6px 16px rgba(0,0,0,0.1)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.transform = 'none'; (e.currentTarget as HTMLElement).style.boxShadow = '0 1px 3px rgba(0,0,0,0.05)'; }}>
                    <div style={{ fontSize: 10, color: '#718096', marginBottom: 8, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{kpi.label}</div>
                    <div style={{ fontSize: 34, fontWeight: 700, color: kpi.color, lineHeight: 1 }}>{kpi.value}</div>
                    <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span>last {hours}h</span>
                      <span style={{ color: kpi.color, fontWeight: 500 }}>→ View logs</span>
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>
                <TimelineChart hours={hours} />
                <SeverityChart summary={summary} onSeverityClick={(sev) => openExplorer({ severity: sev })} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
                <TopTalkers hours={hours} onHostClick={(host) => openExplorer({ host })} />
                <VendorBreakdown hours={hours} onVendorClick={(vendor) => openExplorer({ vendor })} />
              </div>
              <RecentCritical hours={hours} onRowClick={(severity) => openExplorer({ severity })} />
              <div style={{ marginTop: 16 }}>
                <StorageWidget />
              </div>
            </>
          )}
          {tab === 'explorer' && <LogExplorer initialFilter={explorerFilter} onFilterUsed={() => setExplorerFilter({})} />}
          {tab === 'livetail' && <LiveTail />}
          {tab === 'alerts'   && <AlertEvents />}
          {tab === 'health'    && <NetworkHealth hours={hours} />}
          {tab === 'security'  && <SecurityAnalysis hours={hours} />}
          {tab === 'hosts'     && <KnownHosts />}
        </div>
      </div>
    </div>
  );
}
