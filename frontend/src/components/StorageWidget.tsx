'use client';
import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function StorageWidget() {
  const [data,    setData]    = useState<any>(null);
  const [disk,    setDisk]    = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/stats/storage').then(r => r.json()),
      fetch('/api/stats/disk').then(r => r.json()),
    ]).then(([storage, diskInfo]) => {
      setData(storage);
      setDisk(diskInfo);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
      <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>Loading storage info...</div>
    </div>
  );

  if (!data) return null;

  const chartData = (data.daily_breakdown || []).map((r: any) => ({
    day:  new Date(r.day).toLocaleDateString([], { month: 'short', day: 'numeric' }),
    logs: parseInt(r.log_count),
  }));

  const projected90dGB = data.avg_bytes_per_day > 0
    ? ((data.avg_bytes_per_day * 90) / 1024 / 1024 / 1024).toFixed(2)
    : null;

  // Disk bar values
  const diskPct     = disk?.used_pct ?? null;
  const diskUsedGB  = disk?.used_gb ?? null;
  const diskFreeGB  = disk?.free_gb ?? null;
  const diskTotalGB = disk?.total_gb ?? null;
  const diskError   = disk?.error ?? null;

  // DB bar — as % of total disk
  const dbPct = disk?.total_bytes && data.db_size_bytes
    ? Math.min(Math.round((data.db_size_bytes / disk.total_bytes) * 100), 100)
    : null;

  const CARD_INNER = { background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 14px' };

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
      <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>Storage & Capacity</div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 16 }}>Database size and log volume trends</div>

      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'DB Size',    value: data.db_size,                                   color: '#2563eb' },
          { label: 'Log Table',  value: data.table_size,                                color: '#7c3aed' },
          { label: 'Total Logs', value: parseInt(data.total_rows).toLocaleString(),     color: '#0891b2' },
          { label: 'Logs Today', value: parseInt(data.rows_24h).toLocaleString(),       color: '#16a34a' },
        ].map(s => (
          <div key={s.label} style={CARD_INNER}>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Server disk — real data */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>Server Disk (C:)</span>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {diskError ? (
              <span style={{ color: '#ca8a04' }}>⚠ Unable to read disk info</span>
            ) : diskUsedGB !== null ? (
              <>
                {diskUsedGB} GB used / {diskTotalGB} GB total —{' '}
                <strong style={{ color: diskPct! > 80 ? '#dc2626' : diskPct! > 60 ? '#ca8a04' : '#16a34a' }}>
                  {diskFreeGB} GB free
                </strong>
              </>
            ) : '—'}
          </span>
        </div>
        <div style={{ height: 8, background: 'var(--border-light)', borderRadius: 4, overflow: 'hidden' }}>
          {diskPct !== null ? (
            <div style={{ height: '100%', width: `${diskPct}%`, borderRadius: 4, transition: 'width 0.5s',
              background: diskPct > 80 ? '#dc2626' : diskPct > 60 ? '#ca8a04' : '#2563eb' }} />
          ) : (
            <div style={{ height: '100%', width: '30%', borderRadius: 4, background: 'var(--border)' }} />
          )}
        </div>
      </div>

      {/* LogVault DB space */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>LogVault Database</span>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {data.db_size} used — {data.days_stored} days of logs stored
          </span>
        </div>
        <div style={{ height: 8, background: 'var(--border-light)', borderRadius: 4, overflow: 'hidden' }}>
          <div style={{ height: '100%',
            width: dbPct !== null ? `${dbPct}%` : `${Math.min((data.db_size_bytes / (200 * 1024 * 1024 * 1024)) * 100, 100)}%`,
            background: '#7c3aed', borderRadius: 4, transition: 'width 0.5s' }} />
        </div>
      </div>

      {/* Projection cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
        <div style={CARD_INNER}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Avg Growth / Day</div>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>{data.avg_size_per_day}</div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>based on data stored so far</div>
        </div>
        <div style={{ background: projected90dGB && parseFloat(projected90dGB) > 10 ? '#fefce8' : '#f0fdf4',
          border: `1px solid ${projected90dGB && parseFloat(projected90dGB) > 10 ? '#fde68a' : '#bbf7d0'}`,
          borderRadius: 8, padding: '12px 14px' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Projected 90-Day Usage</div>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: projected90dGB && parseFloat(projected90dGB) > 10 ? '#ca8a04' : '#16a34a' }}>
            {projected90dGB ? `${projected90dGB} GB` : 'Insufficient data'}
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>at current ingestion rate</div>
        </div>
      </div>

      {/* Daily chart */}
      {chartData.length > 0 && (
        <>
          <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>Daily Log Volume (Last 7 Days)</div>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
              <XAxis dataKey="day" tick={{ fontSize: 'var(--text-xs)', fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 'var(--text-xs)', fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 'var(--text-sm)' }} />
              <Bar dataKey="logs" fill="#2563eb" radius={[4, 4, 0, 0]} name="Logs" />
            </BarChart>
          </ResponsiveContainer>
        </>
      )}

      {/* Retention info */}
      <div style={{ marginTop: 16, padding: '10px 14px', background: '#eff6ff',
        border: '1px solid #bfdbfe', borderRadius: 8, fontSize: 'var(--text-xs)', color: '#1e40af' }}>
        <strong>Retention policy:</strong> Logs older than {process.env.RETENTION_DAYS || 90} days are automatically deleted nightly.
        Adjust <code style={{ background: '#dbeafe', padding: '1px 4px', borderRadius: 3 }}>RETENTION_DAYS</code> in{' '}
        <code style={{ background: '#dbeafe', padding: '1px 4px', borderRadius: 3 }}>.env.local</code> to change.
      </div>
    </div>
  );
}
