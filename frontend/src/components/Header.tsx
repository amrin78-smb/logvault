'use client';

export default function Header() {
  return (
    <div style={{ background: '#0f1b2d', padding: '0 24px',
      display: 'flex', alignItems: 'center', height: 60, gap: 14,
      boxShadow: '0 2px 8px rgba(0,0,0,0.3)' }}>
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <path d="M16 2L4 8v9c0 6.2 5.1 12 12 13.4C23 28.9 28 23.2 28 17V8L16 2z"
          fill="#1e3a5f" stroke="#3b82f6" strokeWidth="1.5"/>
        <circle cx="16" cy="15" r="2.8" fill="#60a5fa"/>
        <line x1="12" y1="15" x2="20" y2="15" stroke="#93c5fd" strokeWidth="1.2"/>
        <line x1="16" y1="11" x2="16" y2="19" stroke="#93c5fd" strokeWidth="1.2"/>
        <circle cx="12" cy="15" r="1.3" fill="#93c5fd"/>
        <circle cx="20" cy="15" r="1.3" fill="#93c5fd"/>
        <circle cx="16" cy="11" r="1.3" fill="#93c5fd"/>
        <circle cx="16" cy="19" r="1.3" fill="#93c5fd"/>
      </svg>
      <div>
        <span style={{ fontSize: 18, fontWeight: 700, color: '#ffffff', letterSpacing: '-0.3px' }}>
          Log<span style={{ color: '#60a5fa' }}>Vault</span>
        </span>
        <span style={{ marginLeft: 10, fontSize: 11, color: '#64748b', fontWeight: 400 }}>
          NexVault · Syslog Analyzer
        </span>
      </div>
      <div style={{ marginLeft: 'auto', display: 'flex', gap: 20, alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>
          UDP+TCP · 514 · 1514
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6,
          background: '#0d2d1a', border: '1px solid #16a34a44',
          borderRadius: 20, padding: '4px 12px' }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e',
            boxShadow: '0 0 6px #22c55e' }} />
          <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>Collector Active</span>
        </div>
      </div>
    </div>
  );
}
