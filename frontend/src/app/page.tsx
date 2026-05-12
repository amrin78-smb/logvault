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
import Header          from '@/components/Header';

type Tab = 'dashboard' | 'explorer' | 'livetail' | 'alerts' | 'hosts';

const CARD  = { background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 };
const TITLE = { fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 4 };
const SUB   = { fontSize: 11, color: '#718096', marginBottom: 16 };

export default function Home() {
  const [tab, setTab]         = useState<Tab>('dashboard');
  const [hours, setHours]     = useState(24);
  const [summary, setSummary] = useState<any[]>([]);
  const [health, setHealth]   = useState<any>(null);

  const fetchSummary = useCallback(async () => {
    try { const r = await fetch(`/api/stats/summary?hours=${hours}`); const d = await r.json(); setSummary(d.data || []); } catch {}
  }, [hours]);

  const fetchHealth = useCallback(async () => {
    try { const r = await fetch('/api/health'); const d = await r.json(); setHealth(d); } catch {}
  }, []);

  useEffect(() => { fetchSummary(); fetchHealth(); }, [fetchSummary, fetchHealth]);
  useEffect(() => { const t = setInterval(() => { fetchSummary(); fetchHealth(); }, 30000); return () => clearInterval(t); }, [fetchSummary, fetchHealth]);

  const totalLogs  = summary.reduce((s, r) => s + parseInt(r.log_count), 0);
  const critCount  = summary.filter(r => parseInt(r.severity) <= 2).reduce((s, r) => s + parseInt(r.log_count), 0);
  const errorCount = summary.filter(r => parseInt(r.severity) === 3).reduce((s, r) => s + parseInt(r.log_count), 0);
  const warnCount  = summary.filter(r => parseInt(r.severity) === 4).reduce((s, r) => s + parseInt(r.log_count), 0);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'explorer',  label: 'Log Explorer' },
    { id: 'livetail',  label: 'Live Tail' },
    { id: 'alerts',    label: 'Alerts' },
    { id: 'hosts',     label: 'Known Hosts' },
  ];

  const KPI = [
    { label: 'Total Logs',     value: totalLogs.toLocaleString(),  color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe', icon: '📋' },
    { label: 'Critical/Alert', value: critCount.toLocaleString(),  color: critCount  > 0 ? '#dc2626' : '#16a34a', bg: critCount  > 0 ? '#fef2f2' : '#f0fdf4', border: critCount  > 0 ? '#fecaca' : '#bbf7d0', icon: '🔴' },
    { label: 'Errors',         value: errorCount.toLocaleString(), color: errorCount > 0 ? '#ea580c' : '#16a34a', bg: errorCount > 0 ? '#fff7ed' : '#f0fdf4', border: errorCount > 0 ? '#fed7aa' : '#bbf7d0', icon: '🟠' },
    { label: 'Warnings',       value: warnCount.toLocaleString(),  color: '#ca8a04', bg: '#fefce8', border: '#fde68a', icon: '🟡' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#f0f2f5', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <Header />

      {/* Side nav + content layout like NetVault */}
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 60px)' }}>

        {/* Sidebar */}
        <div style={{ width: 200, background: '#0f1b2d', flexShrink: 0,
          display: 'flex', flexDirection: 'column', paddingTop: 16 }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              style={{ padding: '11px 20px', background: tab === t.id ? '#1e3a5f' : 'none',
                border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                color: tab === t.id ? '#ffffff' : '#94a3b8', textAlign: 'left',
                borderLeft: tab === t.id ? '3px solid #3b82f6' : '3px solid transparent',
                transition: 'all 0.15s' }}>
              {t.label}
            </button>
          ))}

          {/* Time range at bottom of sidebar */}
          <div style={{ marginTop: 'auto', padding: '16px 16px 20px' }}>
            <div style={{ fontSize: 10, color: '#475569', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Time Range
            </div>
            {[6, 24, 48, 168].map(h => (
              <button key={h} onClick={() => setHours(h)}
                style={{ display: 'block', width: '100%', padding: '6px 10px', marginBottom: 4,
                  borderRadius: 6, border: '1px solid', fontSize: 12, cursor: 'pointer', textAlign: 'left',
                  background: hours === h ? '#1e3a5f' : 'transparent',
                  borderColor: hours === h ? '#3b82f6' : '#1e2d40',
                  color: hours === h ? '#60a5fa' : '#64748b' }}>
                {h === 168 ? '7 days' : `${h} hours`}
              </button>
            ))}
            {health && (
              <div style={{ marginTop: 12, fontSize: 11, color: '#22c55e', textAlign: 'center' }}>
                ● {health.logs_last_hour.toLocaleString()} logs/hr
              </div>
            )}
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1, padding: 24, overflow: 'auto' }}>
          {tab === 'dashboard' && (
            <>
              {/* KPI tiles */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 20 }}>
                {KPI.map(kpi => (
                  <div key={kpi.label} style={{ background: kpi.bg,
                    border: `1px solid ${kpi.border}`, borderRadius: 10, padding: '18px 20px' }}>
                    <div style={{ fontSize: 11, color: '#718096', marginBottom: 6, fontWeight: 600,
                      textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {kpi.label}
                    </div>
                    <div style={{ fontSize: 32, fontWeight: 700, color: kpi.color, lineHeight: 1 }}>
                      {kpi.value}
                    </div>
                    <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 6 }}>last {hours}h</div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>
                <TimelineChart hours={hours} />
                <SeverityChart summary={summary} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
                <TopTalkers hours={hours} />
                <VendorBreakdown hours={hours} />
              </div>

              <RecentCritical hours={hours} />
            </>
          )}
          {tab === 'explorer' && <LogExplorer />}
          {tab === 'livetail' && <LiveTail />}
          {tab === 'alerts'   && <AlertEvents />}
          {tab === 'hosts'    && <KnownHosts />}
        </div>
      </div>
    </div>
  );
}
