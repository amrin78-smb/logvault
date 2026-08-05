'use client';
import { useEffect, useState } from 'react';
import { applyCorners, getCorners, CORNERS_EVENT, type Corners } from '@/lib/corners';

// Sub-components live at module top level, never nested inside CornersToggle —
// a component defined inside another is re-created on every render, which
// remounts its DOM (suite-wide rule; see Header.tsx's SearchRow for the same
// note). Here that would also kill the button's :hover/transition mid-press.

// Card tokens, NOT alpha-white-over-navy: this control now lives on the avatar
// dropdown panel (a --bg-card surface), not in the navy header bar, so the old
// rgba(255,255,255,0.xx) treatment would be invisible here. The row copies the
// padding/font-size/hover of the sibling dropdown items in Header.tsx.
const ROW_PADDING = '9px 16px';

function CornersIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" aria-hidden>
      <path d="M3 9V5a2 2 0 0 1 2-2h4" />
      <path d="M15 3h4a2 2 0 0 1 2 2v4" />
      <path d="M21 15v4a2 2 0 0 1-2 2h-4" />
      <path d="M9 21H5a2 2 0 0 1-2-2v-4" />
    </svg>
  );
}

function RoundedIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden>
      <rect x="2.5" y="2.5" width="11" height="11" rx="3.5" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

function SquareIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden>
      <rect x="2.5" y="2.5" width="11" height="11" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

function CornerSegment({ label, active, onSelect, children }: {
  label: string; active: boolean; onSelect: () => void; children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={active}
      title={`${label} corners`}
      style={{
        display: 'flex', alignItems: 'center', gap: 5,
        padding: '3px 9px', border: 'none', cursor: 'pointer',
        borderRadius: 'var(--radius-sm)',
        background: active ? 'var(--bg-card)' : 'transparent',
        boxShadow: active ? '0 1px 2px rgba(0,0,0,0.10)' : 'none',
        color: active ? 'var(--text-primary)' : 'var(--text-muted)',
        fontSize: 'var(--text-xs)', fontWeight: 600, fontFamily: 'inherit',
        letterSpacing: '0.02em', whiteSpace: 'nowrap',
        transition: 'background 0.15s, color 0.15s',
      }}
      onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.color = 'var(--text-primary)'; }}
      onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'; }}
    >
      {children}{label}
    </button>
  );
}

/**
 * "Corners" preference row for the avatar dropdown menu: a label on the left
 * and a compact Rounded | Square segmented control on the right.
 *
 * Deliberately NOT admin-gated — this is a per-browser display preference
 * stored in localStorage, with no server state and no security surface, so it
 * lives in the avatar dropdown (reachable by every role) rather than the
 * role-gated Settings tab.
 */
export default function CornersToggle() {
  // 'rounded' is the SSR-safe initial value and the real state is read in an
  // effect, never at render: the <html> attribute is stamped by the no-flash
  // script in layout.tsx and does not exist during server rendering, so reading
  // it at render time would produce a hydration mismatch on square-corner
  // browsers. One post-mount re-render is the correct trade.
  const [corners, setCorners] = useState<Corners>('rounded');

  useEffect(() => {
    setCorners(getCorners());
    // Keep in sync if another mounted instance (or a future settings row) flips it.
    const onChange = (e: Event) => setCorners((e as CustomEvent<Corners>).detail);
    window.addEventListener(CORNERS_EVENT, onChange);
    return () => window.removeEventListener(CORNERS_EVENT, onChange);
  }, []);

  const select = (value: Corners) => {
    if (value === corners) return;
    applyCorners(value);
    setCorners(value);
  };

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10, width: '100%',
      padding: ROW_PADDING, color: 'var(--text-secondary)', fontSize: 'var(--text-base)',
    }}>
      <CornersIcon />
      <span style={{ flex: 1, textAlign: 'left', whiteSpace: 'nowrap' }}>Corners</span>
      <div
        role="group"
        aria-label="Corner style"
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 2, padding: 2,
          background: 'var(--surface-subtle)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          flexShrink: 0,
        }}
      >
        <CornerSegment label="Rounded" active={corners === 'rounded'} onSelect={() => select('rounded')}>
          <RoundedIcon />
        </CornerSegment>
        <CornerSegment label="Square" active={corners === 'square'} onSelect={() => select('square')}>
          <SquareIcon />
        </CornerSegment>
      </div>
    </div>
  );
}
