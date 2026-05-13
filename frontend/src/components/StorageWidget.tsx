'use client';
import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function StorageWidget() {
  const [data, setData]       = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/stats/storage')
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  // Disk space check via a rough estimate
  // 171 GB free on this server
  const DISK_FREE_GB  = 171.93;
  const DISK_USED_GB  = 27.97;
  const DISK_TOTAL_GB = DISK_FREE_GB + DISK_USED_GB;
  const diskPct       = Math.round((DISK_USED_GB / DISK_TOTAL_GB) * 100);

  if (loading) return (
    <div style={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ color: '#9ca3af', fontSize: 13 }}>Loading storage info...</div>
    </div>
  );

  if (!data) return null;

  const tableMB   = (data.table_size_bytes / 1024 / 1024).toFixed(2);
  const tableGB   = (data.table_size_bytes / 1024 / 1024 / 1024).toFixed(3);
  const maxDailyGB = 50; // warn if projected to exceed 50GB

  // Project 90-day usage based on current daily average
  const projected90dGB = data.avg_bytes_per_day > 0
    ? ((data.avg_bytes_per_day * 90) / 1024 / 1024 / 1024).toFixed(2)
    : null;

  const chartData = (data.daily_breakdown || []).map((r: any) => ({
    day:   new Date(r.day).toLocaleDateString([], { month: 'short', day: 'numeric' }),
    logs:  parseInt(r.log_count),
  }));

  return (
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Storage & Capacity</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Database size and log volume trends</div>

      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'DB Size',       value: data.db_size,      color: '#2563eb' },
          { label: 'Log Table',     value: data.table_size,   color: '#7c3aed' },
          { label: 'Total Logs',    value: parseInt(data.total_rows).toLocaleString(), color: '#0891b2' },
          { label: 'Logs Today',    value: parseInt(data.rows_24h).toLocaleString(),   color: '#16a34a' },
        ].map(s => (
          <div key={s.label} style={{ background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 8, padding: '12px 14px' }}>
            <div style={{ fontSize: 10, color: '#718096', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Server disk space */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: '#1a202c' }}>Server Disk (C:)</span>
          <span style={{ fontSize: 12, color: '#718096' }}>
            {DISK_USED_GB} GB used / {DISK_TOTAL_GB.toFixed(1)} GB total — <strong style={{ color: diskPct > 80 ? '#dc2626' : diskPct > 60 ? '#ca8a04' : '#16a34a' }}>{DISK_FREE_GB} GB free</strong>
          </span>
        </div>
        <div style={{ height: 8, background: '#f0f2f5', borderRadius: 4, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${diskPct}%`, borderRadius: 4, transition: 'width 0.5s',
            background: diskPct > 80 ? '#dc2626' : diskPct > 60 ? '#ca8a04' : '#2563eb' }} />
        </div>
      </div>

      {/* LogVault DB space */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: '#1a202c' }}>LogVault Database</span>
          <span style={{ fontSize: 12, color: '#718096' }}>
            {data.db_size} used — {data.days_stored} days of logs stored
          </span>
        </div>
        <div style={{ height: 8, background: '#f0f2f5', borderRadius: 4, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${Math.min((data.db_size_bytes / (DISK_FREE_GB * 1024 * 1024 * 1024)) * 100, 100)}%`,
            background: '#7c3aed', borderRadius: 4 }} />
        </div>
      </div>

      {/* Projection */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
        <div style={{ background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 8, padding: '12px 14px' }}>
          <div style={{ fontSize: 10, color: '#718096', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Avg Growth / Day</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: '#1a202c' }}>{data.avg_size_per_day}</div>
          <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 2 }}>based on data stored so far</div>
        </div>
        <div style={{ background: projected90dGB && parseFloat(projected90dGB) > 10 ? '#fefce8' : '#f0fdf4',
          border: `1px solid ${projected90dGB && parseFloat(projected90dGB) > 10 ? '#fde68a' : '#bbf7d0'}`,
          borderRadius: 8, padding: '12px 14px' }}>
          <div style={{ fontSize: 10, color: '#718096', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Projected 90-Day Usage</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: projected90dGB && parseFloat(projected90dGB) > 10 ? '#ca8a04' : '#16a34a' }}>
            {projected90dGB ? `${projected90dGB} GB` : 'Insufficient data'}
          </div>
          <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 2 }}>at current ingestion rate</div>
        </div>
      </div>

      {/* Daily log volume chart */}
      {chartData.length > 0 && (
        <>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#1a202c', marginBottom: 8 }}>Daily Log Volume (Last 7 Days)</div>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f2f5" />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6, fontSize: 12 }} />
              <Bar dataKey="logs" fill="#2563eb" radius={[4, 4, 0, 0]} name="Logs" />
            </BarChart>
          </ResponsiveContainer>
        </>
      )}

      {/* Retention info */}
      <div style={{ marginTop: 16, padding: '10px 14px', background: '#eff6ff',
        border: '1px solid #bfdbfe', borderRadius: 8, fontSize: 11, color: '#1e40af' }}>
        <strong>Retention policy:</strong> Logs older than 90 days are automatically deleted every night at 2:00 AM by the LogVault-Cleanup scheduled task.
        To adjust, edit <code style={{ background: '#dbeafe', padding: '1px 4px', borderRadius: 3 }}>RETENTION_DAYS</code> in <code style={{ background: '#dbeafe', padding: '1px 4px', borderRadius: 3 }}>.env.local</code>
        and update <code style={{ background: '#dbeafe', padding: '1px 4px', borderRadius: 3 }}>scripts/cleanup.js</code>.
      </div>
    </div>
  );
}
