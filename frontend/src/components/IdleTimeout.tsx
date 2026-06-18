'use client';

import { useState, useEffect, useRef } from 'react';

const HUB_URL = process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || 'http://localhost:3000';
const WARNING_MS = 60 * 1000; // show warning 60s before expiry

// Manual CSRF sign-out — same flow as Header. Do NOT use the next-auth
// signOut helper (breaks the SSO cookie flow). Clears the session then returns to
// the hub login with a timeout reason.
async function csrfSignOut() {
  try {
    const csrfRes = await fetch('/api/auth/csrf');
    const { csrfToken } = await csrfRes.json();
    await fetch('/api/auth/signout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrfToken=${csrfToken}&callbackUrl=/`,
    });
  } catch {}
  window.location.replace(`${HUB_URL}/login?reason=timeout`);
}

export default function IdleTimeout() {
  const [showWarning, setShowWarning] = useState(false);

  // Timer handles kept in refs so listeners/cleanup always see the latest.
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const warningTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const timeoutMsRef = useRef<number>(0);

  // Refs let the modal buttons call into the latest effect-scoped handlers
  // without redefining components or re-running the effect.
  const resetRef = useRef<(() => void) | null>(null);
  const signOutRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let cancelled = false;

    const clearTimers = () => {
      if (idleTimerRef.current) {
        clearTimeout(idleTimerRef.current);
        idleTimerRef.current = null;
      }
      if (warningTimerRef.current) {
        clearTimeout(warningTimerRef.current);
        warningTimerRef.current = null;
      }
    };

    const doSignOut = () => {
      clearTimers();
      csrfSignOut();
    };

    const startTimers = () => {
      const total = timeoutMsRef.current;
      if (!total || total <= 0) return;
      clearTimers();
      setShowWarning(false);

      // Warning fires WARNING_MS before the full timeout (or immediately
      // before logout if the configured window is shorter than the warning).
      const warnAfter = Math.max(total - WARNING_MS, 0);
      warningTimerRef.current = setTimeout(() => {
        if (!cancelled) setShowWarning(true);
      }, warnAfter);

      idleTimerRef.current = setTimeout(() => {
        if (!cancelled) doSignOut();
      }, total);
    };

    const resetTimers = () => {
      if (cancelled) return;
      startTimers();
    };

    // Expose a stable reset for the modal buttons via the window-scoped ref.
    resetRef.current = resetTimers;
    signOutRef.current = doSignOut;

    const events = ['mousemove', 'keydown', 'click', 'scroll'];

    const init = async () => {
      try {
        const res = await fetch(`${HUB_URL}/api/settings`, { credentials: 'include' });
        if (!res.ok) return;
        const settings = await res.json();
        const raw = settings && settings['idle_timeout_minutes'];

        // "never", missing, or unparseable → do nothing.
        if (raw == null || String(raw).toLowerCase() === 'never') return;
        const minutes = parseInt(String(raw), 10);
        if (isNaN(minutes) || minutes <= 0) return;
        if (cancelled) return;

        timeoutMsRef.current = minutes * 60 * 1000;

        events.forEach((evt) =>
          window.addEventListener(evt, resetTimers, { passive: true })
        );
        startTimers();
      } catch {
        // Fetch failed — silently do nothing, never crash the page.
      }
    };

    init();

    return () => {
      cancelled = true;
      events.forEach((evt) => window.removeEventListener(evt, resetTimers));
      clearTimers();
    };
    // Fetch timeout value ONCE on mount only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!showWarning) return null;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 99999,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 420,
          background: '#ffffff',
          borderRadius: 8,
          overflow: 'hidden',
          boxShadow: '0 4px 16px rgba(0,0,0,0.12)',
          fontFamily: 'system-ui, -apple-system, sans-serif',
        }}
      >
        <div
          style={{
            background: '#1a2744',
            color: '#ffffff',
            padding: '16px 20px',
            fontSize: 16,
            fontWeight: 600,
          }}
        >
          Session Timeout
        </div>
        <div style={{ padding: '20px', color: '#111827', fontSize: 14, lineHeight: 1.5 }}>
          You will be logged out in 60 seconds due to inactivity
        </div>
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 10,
            padding: '0 20px 20px',
          }}
        >
          <button
            type="button"
            onClick={() => {
              setShowWarning(false);
              if (resetRef.current) resetRef.current();
            }}
            style={{
              background: '#C8102E',
              color: '#ffffff',
              border: 'none',
              borderRadius: 6,
              padding: '10px 16px',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Stay logged in
          </button>
          <button
            type="button"
            onClick={() => {
              if (signOutRef.current) signOutRef.current();
            }}
            style={{
              background: '#ffffff',
              color: '#374151',
              border: '1px solid #e5e7eb',
              borderRadius: 6,
              padding: '10px 16px',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Sign out now
          </button>
        </div>
      </div>
    </div>
  );
}
