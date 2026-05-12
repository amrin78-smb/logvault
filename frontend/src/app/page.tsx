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

export default function Home() {
  const [tab, setTab]         = useState<Tab>('dashboard');
  const [hours, setHours]     = useState(24);
  const [summary, setSummary] = useState<any[]>([]);
  const [health, setHealth]   = useState<any>(null);

  const fetchSummary = useCallback(async () => {
    try {
      const r = await fetch(`/api/stats/summary?hours=${hours}`);
      const d = await r.json();
      setSummary(d.data || []);
    } catch {}
  }, [hours]);

  const fetchHealth = useCallback(async () => {
    try {
      const r = await fetch('/api/health');
      const d = await r.json();
      setHealth(d);
    } catch {}
  }, []);

  useEffect(() => { fetchSummary(); fetchHealth(); }, [fetchSummary, fetchHealth]);
  useEffect(() => {
    const t = setInterval(() => { fetchSummary(); fetchHealth(); }, 30000);
    return () => clearInterval(t);
  }, [fetchSummary, fetchHealth]);

  const totalLogs  = summary.reduce((s, r) => s + parseInt(r.log_count), 0);
  const critCount  = summary.filter(r => r.severity <= 2).reduce((s, r) => s + parseInt(r.log_count), 0);
  const errorCount = summary.filter(r => r.severity === 3).reduce((s, r) => s + parseInt(r.log_count), 0);
  const warnCount  = summary.filter(r => r.severity === 4).reduce((s, r) => s + parseInt(r.log_count), 0);

  const TABS: { id: Tab; label: string }[] = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'explorer',  label: 'Log Explorer' },
    { id: 'livetail',  label: 'Live Tail' },
    { id: 'alerts',    label: 'Alerts' },
    { id: 'hosts',     label: 'Known Hosts' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#0f1117', color: '#e2e8f0', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <Header />

      {/* Navigation */}
      <div style={{ background: '#161b27', borderBottom: '1px solid #1e2d40', padding: '0 24px', display: 'flex', gap: 0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: '12px 20px', background: 'none', border: 'none', cursor: 'pointer',
              fontSize: 14, fontWeight: 500,
              color: tab === t.id ? '#38bdf8' : '#94a3b8',
              borderBottom: tab === t.id ? '2px solid #38bdf8' : '2px solid transparent' }}>
            {t.label}
          </button>
        ))}

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 12, color: '#64748b' }}>Time range:</span>
          {[6, 24, 48, 168].map(h => (
            <button key={h} onClick={() => setHours(h)}
              style={{ padding: '4px 10px', borderRadius: 4, border: '1px solid', fontSize: 12, cursor: 'pointer',
                background: hours === h ? '#1e3a5f' : 'transparent',
                borderColor: hours === h ? '#38bdf8' : '#2d3748',
                color: hours === h ? '#38bdf8' : '#94a3b8' }}>
              {h === 168 ? '7d' : `${h}h`}
            </button>
          ))}
          {health && (
            <span style={{ marginLeft: 8, fontSize: 12, color: '#22c55e' }}>
              ● {health.logs_last_hour.toLocaleString()} logs/hr
            </span>
          )}
        </div>
      </div>

      <div style={{ padding: 24 }}>
        {tab === 'dashboard' && (
          <>
            {/* KPI Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 24 }}>
              {[
                { label: 'Total Logs',     value: totalLogs.toLocaleString(),  color: '#38bdf8' },
                { label: 'Critical/Alert', value: critCount.toLocaleString(),  color: critCount  > 0 ? '#ef4444' : '#22c55e' },
                { label: 'Errors',         value: errorCount.toLocaleString(), color: errorCount > 0 ? '#f97316' : '#22c55e' },
                { label: 'Warnings',       value: warnCount.toLocaleString(),  color: '#eab308' },
              ].map(kpi => (
                <div key={kpi.label} style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
                  <div style={{ fontSize: 12, color: '#64748b', marginBottom: 4 }}>{kpi.label}</div>
                  <div style={{ fontSize: 28, fontWeight: 700, color: kpi.color }}>{kpi.value}</div>
                  <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>last {hours}h</div>
                </div>
              ))}
            </div>

            {/* Charts row 1 */}
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>
              <TimelineChart hours={hours} />
              <SeverityChart summary={summary} />
            </div>

            {/* Charts row 2 */}
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
  );
}
