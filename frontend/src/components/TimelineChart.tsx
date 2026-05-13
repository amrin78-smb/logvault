'use client';
import { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626', error: '#ea580c', warning: '#ca8a04', info: '#16a34a',
};

export default function TimelineChart({ hours }: { hours: number }) {
  const [data, setData]       = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(false);
    fetch(`/api/stats/timeline?hours=${hours}`)
      .then(r => r.json())
      .then(d => {
        const map = new Map<string, any>();
        for (const row of (d.data || [])) {
          // Handle bucket as Date object, string, or ISO string from PostgreSQL
          const bucketDate = new Date(row.bucket);
          const key        = String(bucketDate.getTime());
          const timeLabel  = hours <= 24
            ? bucketDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            : bucketDate.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

          if (!map.has(key)) map.set(key, { time: timeLabel, _ts: key });
          const count = parseInt(row.log_count) || 0;
          if (count > 0) map.get(key)[row.severity_label] = count;
        }
        // Sort by timestamp
        const sorted = [...map.values()].sort((a, b) => parseInt(a._ts) - parseInt(b._ts));
        setData(sorted);
        setLoading(false);
      })
      .catch(() => { setError(true); setLoading(false); });
  }, [hours]);

  const hasData = data.some(d => Object.keys(d).some(k => k !== 'time' && k !== '_ts' && (d[k] || 0) > 0));

  return (
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Log Volume Over Time</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 16 }}>Ingestion rate by severity — last {hours}h</div>

      {error ? (
        <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#dc2626', fontSize: 13 }}>
          Failed to load chart data
        </div>
      ) : loading ? (
        <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>
          Loading...
        </div>
      ) : !hasData ? (
        <div style={{ height: 200, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13, gap: 6 }}>
          <span>No log data for this time period</span>
          <span style={{ fontSize: 11 }}>Try sending test logs or selecting a wider range</span>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f2f5" />
            <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={{ stroke: '#e2e6ea' }} tickLine={false} />
            <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6, fontSize: 12, color: '#1a202c' }}
              formatter={(value: any, name: any) => [value + ' logs', name]}
            />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            {Object.entries(SEV_COLORS).map(([sev, color]) => (
              <Area key={sev} type="monotone" dataKey={sev} stackId="1"
                stroke={color} fill={color} fillOpacity={0.15} strokeWidth={2} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
