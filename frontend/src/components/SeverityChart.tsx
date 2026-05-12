'use client';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  emergency: '#f85149', alert: '#f85149', critical: '#f85149',
  error: '#db6d28', warning: '#d29922', notice: '#58a6ff',
  info: '#3fb950', debug: '#6e7681',
};

const RADIAN = Math.PI / 180;
const renderLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, name, percent }: any) => {
  if (percent < 0.05) return null;
  const radius = innerRadius + (outerRadius - innerRadius) * 1.4;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#e6edf3" textAnchor={x > cx ? 'start' : 'end'}
      dominantBaseline="central" fontSize={11} fontWeight={500}>
      {`${name} ${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

export default function SeverityChart({ summary }: { summary: any[] }) {
  const data = summary
    .filter(r => parseInt(r.log_count) > 0)
    .map(r => ({
      name:  r.severity_label,
      value: parseInt(r.log_count),
      color: SEV_COLORS[r.severity_label] || '#6e7681',
    }));

  return (
    <div style={{ background: '#161c26', border: '1px solid #30363d', borderRadius: 10, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3', marginBottom: 4 }}>Severity Distribution</div>
      <div style={{ fontSize: 11, color: '#6e7681', marginBottom: 16 }}>Log breakdown by severity level</div>
      {data.length === 0 ? (
        <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6e7681', fontSize: 13 }}>
          No data for this period
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={50} outerRadius={75}
              dataKey="value" nameKey="name" labelLine={false} label={renderLabel}>
              {data.map((entry, i) => <Cell key={i} fill={entry.color} stroke="#161c26" strokeWidth={2} />)}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#1c2333', border: '1px solid #30363d', borderRadius: 6, fontSize: 12 }}
              formatter={(value: any, name: any) => [value.toLocaleString() + ' logs', name]}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
      {/* Legend */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
        {data.map(d => (
          <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
            <span style={{ fontSize: 11, color: '#8b949e', textTransform: 'capitalize' }}>
              {d.name} <span style={{ color: '#e6edf3', fontWeight: 600 }}>{d.value}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
