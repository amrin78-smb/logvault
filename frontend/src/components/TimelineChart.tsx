'use client';
import { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626', error: '#ea580c', warning: '#ca8a04', info: '#16a34a',
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
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Log Volume Over Time</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Ingestion rate by severity</div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f2f5" />
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={{ stroke: '#e2e6ea' }} tickLine={false} />
          <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6, fontSize: 12, color: '#1a202c' }} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          {Object.entries(SEV_COLORS).map(([sev, color]) => (
            <Area key={sev} type="monotone" dataKey={sev} stackId="1"
              stroke={color} fill={color} fillOpacity={0.15} strokeWidth={2} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
