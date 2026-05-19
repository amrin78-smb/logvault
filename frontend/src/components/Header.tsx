'use client';
import { useTheme } from './ThemeContext';

export default function Header() {
  const { theme, toggle } = useTheme();

  return (
    <div style={{ height: 52, background: '#0f1b2d', display: 'flex', alignItems: 'center',
      padding: '0 20px', borderBottom: '1px solid #1e2d40', flexShrink: 0 }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ width: 28, height: 28, background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
          borderRadius: 7, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="white" strokeWidth="1.3" fill="none"/>
            <circle cx="8" cy="8" r="2" fill="white"/>
          </svg>
        </div>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: '#ffffff', letterSpacing: '-0.3px' }}>LogVault</div>
          <div style={{ fontSize: 9, color: '#475569', letterSpacing: '0.5px' }}>NexVault · Syslog Analyzer</div>
        </div>
      </div>

      <div style={{ flex: 1 }} />

      {/* Status indicators */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ fontSize: 11, color: '#64748b' }}>UDP+TCP · 514 · 1514</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e' }} />
          <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>Collector Active</span>
        </div>

        {/* Dark mode toggle */}
        <button onClick={toggle}
          style={{ background: '#1e2d40', border: '1px solid #334155', borderRadius: 7,
            padding: '5px 10px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
            color: '#94a3b8', fontSize: 11, transition: 'all 0.15s' }}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
          {theme === 'dark' ? (
            <>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <circle cx="6" cy="6" r="3" fill="currentColor"/>
                <line x1="6" y1="0" x2="6" y2="1.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
                <line x1="6" y1="10.5" x2="6" y2="12" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
                <line x1="0" y1="6" x2="1.5" y2="6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
                <line x1="10.5" y1="6" x2="12" y2="6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
              </svg>
              Light
            </>
          ) : (
            <>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M10 6.5A4.5 4.5 0 1 1 5.5 2a3.5 3.5 0 0 0 4.5 4.5z" fill="currentColor"/>
              </svg>
              Dark
            </>
          )}
        </button>
      </div>
    </div>
  );
}
