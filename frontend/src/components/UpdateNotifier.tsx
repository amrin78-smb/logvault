'use client';

import { useState, useEffect } from 'react';

interface UpdateInfo {
  available: boolean;
  current?: string;
  latest?: string;
}

const DISMISS_KEY_PREFIX = 'logvault-update-dismissed-';

// Slim blue banner shown when a newer LogVault version is published on GitHub.
// Polls /api/system/update-available on mount + every 6 hours. Defined at module
// level (never nested inside another component).
export default function UpdateNotifier() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const check = async () => {
      try {
        const res = await fetch('/api/system/update-available');
        const data: UpdateInfo = await res.json();
        if (cancelled) return;
        setInfo(data);
        if (data.available && data.latest) {
          try {
            const wasDismissed = sessionStorage.getItem(DISMISS_KEY_PREFIX + data.latest);
            setDismissed(!!wasDismissed);
          } catch {
            setDismissed(false);
          }
        }
      } catch {
        if (!cancelled) setInfo(null);
      }
    };

    check();
    const interval = setInterval(check, 6 * 60 * 60 * 1000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const goToSettings = () => {
    // LogVault renders Settings as a tab inside the main page (no /settings
    // route), so navigate via the shared cross-component navigation event and
    // leave a hint for the Settings component to open the Updates sub-tab.
    try { sessionStorage.setItem('logvault-settings-tab', 'updates'); } catch { /* ignore */ }
    window.dispatchEvent(new CustomEvent('nocvault:navigate', { detail: { tab: 'settings' } }));
  };

  const handleDismiss = () => {
    if (info?.latest) {
      try {
        sessionStorage.setItem(DISMISS_KEY_PREFIX + info.latest, '1');
      } catch {
        /* sessionStorage may be unavailable; dismiss for this session anyway */
      }
    }
    setDismissed(true);
  };

  if (!info || !info.available || dismissed) return null;

  return (
    <div style={{
      background: '#1d4ed8', color: '#fff', padding: '8px 20px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      width: '100%', fontSize: 'var(--text-base)', flexShrink: 0, zIndex: 90,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span>🔄</span>
        <span>LogVault v{info.latest} is available</span>
        <span style={{ opacity: 0.7 }}>→</span>
        <button
          type="button"
          onClick={goToSettings}
          style={{
            background: 'transparent', color: '#fff', border: 'none', padding: 0,
            cursor: 'pointer', fontSize: 'var(--text-base)', textDecoration: 'underline', whiteSpace: 'nowrap',
          }}
        >
          Go to Settings
        </button>
      </div>
      <button
        type="button"
        onClick={handleDismiss}
        aria-label="Dismiss"
        style={{
          background: 'transparent', color: '#fff', border: 'none',
          cursor: 'pointer', fontSize: 'var(--text-lg)', lineHeight: 1, padding: 0, marginLeft: 16,
        }}
      >
        ×
      </button>
    </div>
  );
}
