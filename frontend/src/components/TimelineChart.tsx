'use client';
import { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#ef4444',
  error: '#f97316', warning: '#eab308', notice: '#3b82f6',
  info: '#22c55e', debug: '#475569',
};

export default function TimelineChart({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/stats/timeline?hours=${hours}`)
      .then(r => r.json())
      .then(d => {
        const map = new Map<string, any>();
        for (const row of (d.data || [])) {
          const key = row.bucket;
          if (!map.has(key)) map.set(key, { time: new Date(key).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
          map.get(key)[row.severity_label] = parseInt(row.log_count);
        }
        setData([...map.values()]);
      }).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Log Volume Over Time</div>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2d40" />
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} />
          <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
          <Tooltip contentStyle={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 6 }} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          {['critical','error','warning','info'].map(s => (
            <Area key={s} type="monotone" dataKey={s} stackId="1"
              stroke={SEV_COLORS[s]} fill={SEV_COLORS[s]} fillOpacity={0.3} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
