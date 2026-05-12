'use client';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#dc2626',
  error: '#ea580c', warning: '#ca8a04', notice: '#2563eb',
  info: '#16a34a', debug: '#9ca3af',
};

const RADIAN = Math.PI / 180;
const renderLabel = ({ cx, cy, midAngle, outerRadius, name, percent }: any) => {
  if (percent < 0.05) return null;
  const r  = outerRadius + 22;
  const x  = cx + r * Math.cos(-midAngle * RADIAN);
  const y  = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#1a202c" textAnchor={x > cx ? 'start' : 'end'}
      dominantBaseline="central" fontSize={11} fontWeight={600}>
      {`${name} ${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

export default function SeverityChart({ summary }: { summary: any[] }) {
  const data = summary
    .filter(r => parseInt(r.log_count) > 0)
    .map(r => ({ name: r.severity_label, value: parseInt(r.log_count), color: SEV_COLORS[r.severity_label] || '#9ca3af' }));

  return (
    <div style={{ background: '#ffffff', border: '1px solid #e2e6ea', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: '#1a202c', marginBottom: 2 }}>Severity Distribution</div>
      <div style={{ fontSize: 11, color: '#718096', marginBottom: 12 }}>Log breakdown by severity level</div>
      {data.length === 0 ? (
        <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#9ca3af', fontSize: 13 }}>
          No data for this period
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={48} outerRadius={70}
              dataKey="value" nameKey="name" labelLine={true} label={renderLabel}>
              {data.map((entry, i) => <Cell key={i} fill={entry.color} stroke="#fff" strokeWidth={2} />)}
            </Pie>
            <Tooltip contentStyle={{ background: '#fff', border: '1px solid #e2e6ea', borderRadius: 6, fontSize: 12, color: '#1a202c' }}
              formatter={(value: any, name: any) => [value.toLocaleString() + ' logs', name]} />
          </PieChart>
        </ResponsiveContainer>
      )}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
        {data.map(d => (
          <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 5,
            background: '#f8f9fb', border: '1px solid #e2e6ea', borderRadius: 20, padding: '3px 10px' }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
            <span style={{ fontSize: 11, color: '#4a5568', textTransform: 'capitalize' }}>
              {d.name}
            </span>
            <span style={{ fontSize: 11, color: '#1a202c', fontWeight: 700 }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
