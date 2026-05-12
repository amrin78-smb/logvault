'use client';

export default function Header() {
  return (
    <div style={{ background: '#161c26', borderBottom: '1px solid #30363d',
      padding: '0 24px', display: 'flex', alignItems: 'center', height: 56, gap: 12 }}>
      {/* Shield icon */}
      <svg width="30" height="30" viewBox="0 0 30 30" fill="none">
        <path d="M15 2L4 7.5v8c0 5.8 4.7 11.2 11 12.5C21.3 26.7 26 21.3 26 15.5v-8L15 2z"
          fill="#1f6feb" stroke="#58a6ff" strokeWidth="1.5"/>
        <circle cx="15" cy="14" r="2.5" fill="#58a6ff"/>
        <line x1="11.5" y1="14" x2="18.5" y2="14" stroke="#58a6ff" strokeWidth="1.2" opacity="0.6"/>
        <line x1="15" y1="10.5" x2="15" y2="17.5" stroke="#58a6ff" strokeWidth="1.2" opacity="0.6"/>
        <circle cx="11.5" cy="14" r="1.2" fill="#58a6ff" opacity="0.8"/>
        <circle cx="18.5" cy="14" r="1.2" fill="#58a6ff" opacity="0.8"/>
        <circle cx="15" cy="10.5" r="1.2" fill="#58a6ff" opacity="0.8"/>
        <circle cx="15" cy="17.5" r="1.2" fill="#58a6ff" opacity="0.8"/>
      </svg>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{ fontSize: 17, fontWeight: 700, color: '#e6edf3', letterSpacing: '-0.3px' }}>
          Log<span style={{ color: '#58a6ff' }}>Vault</span>
        </span>
        <span style={{ fontSize: 11, color: '#6e7681', fontWeight: 400 }}>
          NexVault · Syslog Analyzer
        </span>
      </div>

      <div style={{ marginLeft: 'auto', display: 'flex', gap: 20, alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: '#6e7681', fontFamily: 'JetBrains Mono, monospace' }}>
          UDP+TCP · 514 · 1514
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#3fb950',
            boxShadow: '0 0 8px #3fb950' }} />
          <span style={{ fontSize: 11, color: '#3fb950', fontWeight: 500 }}>Collector Active</span>
        </div>
      </div>
    </div>
  );
}
