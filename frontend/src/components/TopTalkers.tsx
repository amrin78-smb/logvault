'use client';
import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function TopTalkers({ hours }: { hours: number }) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    fetch(`/api/stats/top-talkers?hours=${hours}&limit=8`)
      .then(r => r.json()).then(d => setData(d.data || [])).catch(() => {});
  }, [hours]);

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Top Talkers</div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2d40" horizontal={false} />
          <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
          <YAxis type="category" dataKey="host" width={120} tick={{ fontSize: 10, fill: '#94a3b8' }} />
          <Tooltip contentStyle={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 6 }} />
          <Bar dataKey="log_count" name="Logs" fill="#38bdf8" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
