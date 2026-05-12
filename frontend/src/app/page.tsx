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
  const critCount  = summary.filter(r => parseInt(r.severity) <= 2).reduce((s, r) => s + parseInt(r.log_count), 0);
  const errorCount = summary.filter(r => parseInt(r.severity) === 3).reduce((s, r) => s + parseInt(r.log_count), 0);
  const warnCount  = summary.filter(r => parseInt(r.severity) === 4).reduce((s, r) => s + parseInt(r.log_count), 0);

  const TABS: { id: Tab; label: string; icon: string }[] = [
    { id: 'dashboard', label: 'Dashboard',   icon: '▦' },
    { id: 'explorer',  label: 'Log Explorer', icon: '⊞' },
    { id: 'livetail',  label: 'Live Tail',    icon: '◉' },
    { id: 'alerts',    label: 'Alerts',       icon: '⚠' },
    { id: 'hosts',     label: 'Known Hosts',  icon: '⊙' },
  ];

  const KPI = [
    { label: 'Total Logs',     value: totalLogs.toLocaleString(),  color: '#58a6ff', bg: '#1a2840', border: '#1f6feb' },
    { label: 'Critical/Alert', value: critCount.toLocaleString(),  color: critCount  > 0 ? '#f85149' : '#3fb950', bg: critCount  > 0 ? '#2d0f0f' : '#0f2d1a', border: critCount  > 0 ? '#f8514944' : '#3fb95044' },
    { label: 'Errors',         value: errorCount.toLocaleString(), color: errorCount > 0 ? '#db6d28' : '#3fb950', bg: errorCount > 0 ? '#2d1b0e' : '#0f2d1a', border: errorCount > 0 ? '#db6d2844' : '#3fb95044' },
    { label: 'Warnings',       value: warnCount.toLocaleString(),  color: '#d29922',  bg: '#2d240e', border: '#d2992244' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#0d1117', color: '#e6edf3',
      fontFamily: 'Inter, system-ui, sans-serif' }}>
      <Header />

      {/* Nav bar */}
      <div style={{ background: '#161c26', borderBottom: '1px solid #30363d',
        padding: '0 24px', display: 'flex', alignItems: 'stretch' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: '0 18px', height: 44, background: 'none', border: 'none',
              cursor: 'pointer', fontSize: 13, fontWeight: 500, display: 'flex',
              alignItems: 'center', gap: 6,
              color: tab === t.id ? '#58a6ff' : '#8b949e',
              borderBottom: tab === t.id ? '2px solid #58a6ff' : '2px solid transparent',
              transition: 'color 0.15s' }}>
            <span style={{ fontSize: 11 }}>{t.icon}</span>
            {t.label}
          </button>
        ))}

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#6e7681' }}>Range:</span>
          {[6, 24, 48, 168].map(h => (
            <button key={h} onClick={() => setHours(h)}
              style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid',
                fontSize: 11, cursor: 'pointer', fontWeight: 500,
                background: hours === h ? '#1f6feb22' : 'transparent',
                borderColor: hours === h ? '#58a6ff' : '#30363d',
                color: hours === h ? '#58a6ff' : '#8b949e',
                transition: 'all 0.15s' }}>
              {h === 168 ? '7d' : `${h}h`}
            </button>
          ))}
          {health && (
            <div style={{ marginLeft: 8, display: 'flex', alignItems: 'center', gap: 5,
              background: '#0f2d1a', border: '1px solid #3fb95033', borderRadius: 20,
              padding: '3px 10px' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#3fb950',
                boxShadow: '0 0 6px #3fb950' }} />
              <span style={{ fontSize: 11, color: '#3fb950', fontWeight: 500 }}>
                {health.logs_last_hour.toLocaleString()} logs/hr
              </span>
            </div>
          )}
        </div>
      </div>

      <div style={{ padding: 24 }}>
        {tab === 'dashboard' && (
          <>
            {/* KPI tiles */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 20 }}>
              {KPI.map(kpi => (
                <div key={kpi.label} style={{ background: kpi.bg,
                  border: `1px solid ${kpi.border}`, borderRadius: 10, padding: '18px 20px' }}>
                  <div style={{ fontSize: 11, color: '#8b949e', marginBottom: 6, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    {kpi.label}
                  </div>
                  <div style={{ fontSize: 32, fontWeight: 700, color: kpi.color, lineHeight: 1 }}>
                    {kpi.value}
                  </div>
                  <div style={{ fontSize: 10, color: '#6e7681', marginTop: 6 }}>last {hours}h</div>
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
  );
}
