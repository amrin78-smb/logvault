'use client';

export default function Header() {
  return (
    <div style={{ background: '#161b27', borderBottom: '1px solid #1e2d40', padding: '0 24px',
      display: 'flex', alignItems: 'center', height: 56, gap: 12 }}>
      {/* Shield icon */}
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <path d="M14 2L4 7v8c0 5.25 4.25 10.15 10 11.35C19.75 25.15 24 20.25 24 15V7L14 2z"
          fill="#1e3a5f" stroke="#38bdf8" strokeWidth="1.5"/>
        <circle cx="14" cy="13" r="2.5" fill="#38bdf8"/>
        <line x1="11" y1="13" x2="17" y2="13" stroke="#38bdf8" strokeWidth="1" opacity="0.5"/>
        <line x1="14" y1="10" x2="14" y2="16" stroke="#38bdf8" strokeWidth="1" opacity="0.5"/>
        <circle cx="11" cy="13" r="1" fill="#38bdf8" opacity="0.7"/>
        <circle cx="17" cy="13" r="1" fill="#38bdf8" opacity="0.7"/>
        <circle cx="14" cy="10" r="1" fill="#38bdf8" opacity="0.7"/>
        <circle cx="14" cy="16" r="1" fill="#38bdf8" opacity="0.7"/>
      </svg>

      <div>
        <span style={{ fontSize: 16, fontWeight: 700, color: '#f0f9ff', letterSpacing: '-0.3px' }}>
          Log<span style={{ color: '#38bdf8' }}>Vault</span>
        </span>
        <span style={{ marginLeft: 8, fontSize: 11, color: '#475569', fontWeight: 400 }}>
          NexVault Syslog Analyzer
        </span>
      </div>

      <div style={{ marginLeft: 'auto', display: 'flex', gap: 16, alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: '#475569' }}>
          Ports: 514 / 1514 (UDP+TCP)
        </span>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e',
          boxShadow: '0 0 6px #22c55e' }} />
        <span style={{ fontSize: 11, color: '#22c55e' }}>Collector Active</span>
      </div>
    </div>
  );
}
