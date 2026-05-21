'use client';
import { useTheme } from './ThemeContext';
import { useSession, signOut } from 'next-auth/react';

export default function Header() {
  const { theme, toggle } = useTheme();
  const { data: session } = useSession();
  const user = session?.user as any;

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

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* Collector status */}
        <div style={{ fontSize: 11, color: '#64748b' }}>UDP+TCP · 514 · 1514</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e' }} />
          <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>Collector Active</span>
        </div>

        {/* Dark mode toggle */}
        <button onClick={toggle}
          style={{ background: '#1e2d40', border: '1px solid #334155', borderRadius: 7,
            padding: '5px 10px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
            color: '#94a3b8', fontSize: 11, transition: 'all 0.15s' }}>
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

        {/* User info + sign out */}
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8,
            background: '#1e2d40', border: '1px solid #334155', borderRadius: 7, padding: '5px 10px' }}>
            {/* Avatar */}
            <div style={{ width: 22, height: 22, borderRadius: '50%', background: '#2563eb',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10, fontWeight: 700, color: '#fff', flexShrink: 0 }}>
              {(user.name || user.email || '?')[0].toUpperCase()}
            </div>
            <div>
              <div style={{ fontSize: 11, color: '#f1f5f9', fontWeight: 600, lineHeight: 1 }}>
                {user.name || user.email}
              </div>
              {user.role && (
                <div style={{ fontSize: 9, color: '#64748b', textTransform: 'capitalize', marginTop: 1 }}>
                  {user.role.replace('_', ' ')}
                </div>
              )}
            </div>
            <button onClick={() => signOut({ callbackUrl: `${process.env.NEXT_PUBLIC_NETVAULT_HUB_URL || 'http://192.168.6.111:3000'}/login` })}
              title="Sign out"
              style={{ background: 'none', border: '1px solid #334155', borderRadius: 5,
                padding: '3px 6px', cursor: 'pointer', color: '#64748b', fontSize: 10,
                transition: 'all 0.15s', marginLeft: 2 }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#ef4444'; (e.currentTarget as HTMLElement).style.borderColor = '#ef4444'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#64748b'; (e.currentTarget as HTMLElement).style.borderColor = '#334155'; }}>
              ⎋ Out
            </button>
          </div>
        )}

        {/* Back to hub */}
        <a href="http://192.168.6.111:3000"
          style={{ display: 'flex', alignItems: 'center', gap: 5, background: '#1e2d40',
            border: '1px solid #334155', borderRadius: 7, padding: '5px 10px',
            color: '#94a3b8', fontSize: 11, textDecoration: 'none', transition: 'all 0.15s' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#f1f5f9'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#94a3b8'; }}>
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
            <path d="M4 2L1 5l3 3M1 5h8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          Hub
        </a>
      </div>
    </div>
  );
}
