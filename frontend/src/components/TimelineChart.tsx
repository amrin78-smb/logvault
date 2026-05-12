'use client';
import { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  critical: '#f85149', error: '#db6d28', warning: '#d29922', info: '#3fb950',
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
          if (!map.has(key)) map.set(key, {
            time: new Date(key).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          });
          map.get(key)[row.severity_label] = parseInt(row.log_count);
        }
        setData([...map.values()]);
      }).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: '#161c26', border: '1px solid #30363d', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>Log Volume Over Time</div>
      <div style={{ fontSize: 11, color: '#6e7681', marginBottom: 16 }}>Ingestion rate by severity</div>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#6e7681' }} axisLine={{ stroke: '#30363d' }} tickLine={false} />
          <YAxis tick={{ fontSize: 10, fill: '#6e7681' }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={{ background: '#1c2333', border: '1px solid #30363d', borderRadius: 6, fontSize: 12 }} />
          <Legend wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
          {Object.entries(SEV_COLORS).map(([sev, color]) => (
            <Area key={sev} type="monotone" dataKey={sev} stackId="1"
              stroke={color} fill={color} fillOpacity={0.25} strokeWidth={1.5} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
