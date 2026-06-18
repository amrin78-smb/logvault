'use client';
import { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626', error: '#ea580c', warning: '#ca8a04', info: '#16a34a',
};

export default function TimelineChart({ hours, compact }: { hours: number; compact?: boolean }) {
  const [data, setData]       = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    fetch(`/api/stats/timeline?hours=${hours}`)
      .then(r => r.json())
      .then(d => {
        const map = new Map<string, any>();
        for (const row of (d.data || [])) {
          const bucketDate = new Date(row.bucket);
          const key = String(bucketDate.getTime());
          const timeLabel = hours <= 24
            ? bucketDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : bucketDate.toLocaleDateString([], { month: 'short', day: 'numeric' });
          if (!map.has(key)) map.set(key, { time: timeLabel, _ts: key });
          const count = parseInt(row.log_count) || 0;
          if (count > 0) map.get(key)[row.severity_label] = count;
        }
        setData([...map.values()].sort((a, b) => parseInt(a._ts) - parseInt(b._ts)));
        setLoading(false);
      }).catch(() => setLoading(false));
  }, [hours]);

  const hasData = data.some(d => Object.keys(d).some(k => k !== 'time' && k !== '_ts' && (d[k] || 0) > 0));

  return (
    <div style={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 8,
      padding: '12px 14px', height: '100%', boxSizing: 'border-box', display: 'flex', flexDirection: 'column' }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: '#1a202c', marginBottom: 1, flexShrink: 0 }}>Log Volume Over Time</div>
      <div style={{ fontSize: 10, color: '#9ca3af', marginBottom: 6, flexShrink: 0 }}>Ingestion rate — last {hours}h</div>
      <div style={{ flex: 1, minHeight: 0 }}>
        {!hasData || loading ? (
          <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 12 }}>
            {loading ? 'Loading...' : 'No data'}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 2, right: 4, left: -22, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f2f5" />
              <XAxis dataKey="time" tick={{ fontSize: 9, fill: '#9ca3af' }} axisLine={{ stroke: '#e2e6ea' }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 9, fill: '#9ca3af' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6, fontSize: 11 }}
                formatter={(v: any, n: any) => [v + ' logs', n]} />
              {Object.entries(SEV_COLORS).map(([sev, color]) => (
                <Area key={sev} type="monotone" dataKey={sev} stackId="1"
                  stroke={color} fill={color} fillOpacity={0.15} strokeWidth={1.5} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 5, justifyContent: 'center', flexShrink: 0 }}>
        {Object.entries(SEV_COLORS).map(([sev, color]) => (
          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
            <div style={{ width: 6, height: 6, borderRadius: 1, background: color }} />
            <span style={{ fontSize: 9, color: '#9ca3af' }}>{sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
