'use client';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const SEV_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#dc2626', critical: '#ef4444',
  error: '#f97316', warning: '#eab308', notice: '#3b82f6',
  info: '#22c55e', debug: '#475569',
};

export default function SeverityChart({ summary }: { summary: any[] }) {
  const data = summary.map(r => ({
    name:  r.severity_label,
    value: parseInt(r.log_count),
    color: SEV_COLORS[r.severity_label] || '#475569',
  }));

  return (
    <div style={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 8, padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>Severity Distribution</div>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
            dataKey="value" nameKey="name"
            label={({ name, percent }) => percent > 0.03 ? `${name} ${(percent * 100).toFixed(0)}%` : ''}>
            {data.map((entry, i) => <Cell key={i} fill={entry.color} />)}
          </Pie>
          <Tooltip contentStyle={{ background: '#161b27', border: '1px solid #1e2d40', borderRadius: 6 }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
