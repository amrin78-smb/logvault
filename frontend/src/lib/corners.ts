/**
 * Corner style (rounded | square) — a per-browser display preference.
 *
 * Mechanics mirror the theme switch in `components/ThemeContext.tsx`: a single
 * attribute on <html> plus a localStorage key. LogVault has no `lib/theme.ts`
 * (the theme lives entirely in that context), so this file is standalone — but
 * the storage prefix matches (`logvault-theme` → `logvault-corners`) so all of
 * this app's display prefs sit together in devtools.
 *
 * The rounded style is the ABSENCE of the attribute, not a value: `applyCorners`
 * removes `data-corners` entirely for 'rounded'. There is no
 * `[data-corners="rounded"]` selector in globals.css — the :root defaults ARE
 * the rounded style.
 *
 * Only the three radius tokens (--radius, --radius-sm, --radius-pill) are
 * overridden. A component that hardcodes a numeric border-radius silently opts
 * itself out and stays rounded; use the tokens.
 */

export type Corners = 'rounded' | 'square';

export const CORNERS_KEY = 'logvault-corners';
export const CORNERS_EVENT = 'logvault:corners';

/** Current corner style. SSR-safe (returns the 'rounded' default on the server). */
export function getCorners(): Corners {
  if (typeof document === 'undefined') return 'rounded';
  if (document.documentElement.getAttribute('data-corners') === 'square') return 'square';
  try {
    return localStorage.getItem(CORNERS_KEY) === 'square' ? 'square' : 'rounded';
  } catch {
    return 'rounded';
  }
}

/** Stamp the <html> attribute, persist, and notify any mounted listeners. */
export function applyCorners(value: Corners): void {
  if (typeof document === 'undefined') return;
  if (value === 'square') document.documentElement.setAttribute('data-corners', 'square');
  else document.documentElement.removeAttribute('data-corners');
  // Private-mode / disabled-storage browsers throw on setItem — the corner style
  // must still apply for this page view, it just won't survive a reload.
  try {
    localStorage.setItem(CORNERS_KEY, value);
  } catch {}
  window.dispatchEvent(new CustomEvent<Corners>(CORNERS_EVENT, { detail: value }));
}

/** Flip the current style and apply it. Returns the newly applied value. */
export function toggleCorners(): Corners {
  const next: Corners = getCorners() === 'square' ? 'rounded' : 'square';
  applyCorners(next);
  return next;
}

/**
 * Body of the synchronous no-flash <script> injected into <head> by layout.tsx.
 * Runs before first paint so a square-corners user never sees a rounded frame.
 * Self-contained and wrapped in try/catch: if storage is unavailable it must
 * fail silently rather than break the document.
 */
export const CORNERS_INIT_SCRIPT = `try{if(localStorage.getItem('${CORNERS_KEY}')==='square'){document.documentElement.setAttribute('data-corners','square');}}catch(e){}`;
