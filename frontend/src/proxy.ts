// frontend/src/proxy.ts
//
// Edge middleware (Next.js 16 "proxy") with two jobs:
//
//   1. Proxy every /api/* call (except /api/auth/*, handled by the next-auth
//      route) straight to the Express API, stamping the authenticated user's
//      identity as X-User-Id / X-User-Role headers read from the VERIFIED
//      session token. We always strip any client-supplied X-User-* headers and
//      overwrite them from getToken(), so a browser can NEVER spoof its role.
//      This replaces the old per-request getServerSession() proxy route
//      (src/app/api/[...path]/route.ts): one cheap edge JWE decode + a rewrite,
//      instead of a full session decrypt inside an extra Node hop on every call.
//
//      Unauthenticated calls are rejected HERE with a 401 unless the path is on
//      the small PUBLIC_API_PATHS allow-list below. We used to proxy them
//      through anyway with no identity headers on the theory that Express
//      "fails closed" by defaulting to the 'user' role — but that's only true
//      for routes that actually consult req.rbac. A route that never checks
//      req.rbac at all (e.g. a GET handler with no guard) is wide open to
//      anonymous callers. Rejecting at the edge removes the whole bug class
//      instead of relying on every Express route to remember to check.
//
//   2. Guard page routes — redirect to the NocVault hub login when there is no
//      session.
//
// IMPORTANT: getToken must be told the custom cookie name
// (nexvault.session-token) and that the cookie is not Secure (HTTP on the local
// network), otherwise it returns null and RBAC silently breaks.

import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { resolveOrigin } from '@/lib/publicUrl';

const API_BASE = process.env.LV_API_URL || 'http://127.0.0.1:3005';
// Legacy static fallback — kept ONLY for the rare case a request doesn't carry
// a usable Host (resolveOrigin() falls back to this). NetVault (the hub) always
// runs on port 3000, regardless of this app's own port.
const HUB_FALLBACK = process.env.NOCVAULT_HUB_URL || 'http://localhost:3000';

const TOKEN_OPTS = {
  secret: process.env.NEXTAUTH_SECRET,
  cookieName: 'nexvault.session-token',
  // Must match the cookie's Secure flag (set from NEXTAUTH_URL protocol in
  // auth.ts), otherwise getToken returns null and RBAC silently breaks.
  secureCookie: (process.env.NEXTAUTH_URL || '').startsWith('https'),
};

// The small set of /api/* routes that are genuinely meant to work with no
// session — pre-login pages and external/cross-origin dashboards. EXACT path
// match only (no prefix matching): e.g. '/api/stats' must NOT also allow
// '/api/stats/by-vendor' through, since the /api/stats/* sub-routes are
// site-scoped, session-gated data, unlike the bare /api/stats aggregate.
// Kept in sync with api/server.js's enforceLicense() exemptPaths + the
// explicit "unauthenticated"/"no-auth" route comments there.
const PUBLIC_API_PATHS = new Set([
  '/api/license-status',
  '/api/health',
  '/api/stats',
  '/api/system/update-available',
]);

// Per-user app-access gate (NocVault suite). `apps` is the list of app slugs the
// user is allowed, carried from the SSO token into LogVault's session JWT
// (auth.ts). Fail OPEN: no/empty claim = default-all, so older tokens minted
// before this feature never lock anyone out. netvault (the hub) is always allowed.
function appAllowed(apps: unknown, slug: string): boolean {
  if (slug === 'netvault') return true;
  if (!Array.isArray(apps) || apps.length === 0) return true;
  return apps.includes(slug);
}

export default async function proxy(req: NextRequest) {
  const { pathname, search } = req.nextUrl;

  // 1. Proxy non-auth API calls to Express, stamping RBAC headers from the
  //    verified token. /api/auth/* is excluded by the matcher (next-auth route).
  if (pathname.startsWith('/api/')) {
    const target = new URL(`${API_BASE}${pathname}${search}`);

    // Strip any client-supplied identity headers before re-adding our own —
    // prevents a browser forging X-User-Role: super_admin.
    const headers = new Headers(req.headers);
    headers.delete('x-user-id');
    headers.delete('x-user-role');

    const token = await getToken({ req, ...TOKEN_OPTS });
    if (token) {
      // Per-user app-access enforcement (same helper/semantics as the page-route
      // guard below): a valid session whose allowed-apps claim omits logvault must
      // not be able to reach the API either — page navigation was gated, but a
      // direct fetch('/api/...') with the same cookie previously sailed straight
      // through to Express. This is an API caller, so deny with JSON, not a redirect.
      if (!appAllowed((token as { apps?: unknown }).apps, 'logvault')) {
        return NextResponse.json({ error: 'forbidden', reason: 'app_access_denied' }, { status: 403 });
      }
      headers.set('x-user-id', String((token as { id?: string | number }).id ?? '0'));
      headers.set('x-user-role', String((token as { role?: string }).role ?? 'user'));
    } else if (!PUBLIC_API_PATHS.has(pathname)) {
      // No session and not on the public allow-list — reject here instead of
      // proxying through with no identity headers. See the file-header comment
      // for why we no longer trust every Express route to fail closed on its own.
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.rewrite(target, { request: { headers } });
  }

  // 2. Page-route auth guard.
  const token = await getToken({ req, ...TOKEN_OPTS });
  if (!token) {
    const hub = resolveOrigin(req, 3000, HUB_FALLBACK);
    return NextResponse.redirect(`${hub}/login`);
  }
  // Per-user app-access enforcement: a valid session whose allowed-apps claim
  // omits logvault is bounced to the hub launcher with a denied banner. The
  // launcher lives on the hub origin, so this never loops inside LogVault.
  if (!appAllowed((token as { apps?: unknown }).apps, 'logvault')) {
    const hub = resolveOrigin(req, 3000, HUB_FALLBACK);
    return NextResponse.redirect(`${hub}/launcher?denied=logvault`);
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    // Non-auth API calls → proxy to Express (exclude /api/auth/*).
    '/api/((?!auth(?:/|$)).+)',
    // Page routes → auth guard (exclude api, sso landing, next internals).
    '/((?!api|sso|_next/static|_next/image|favicon.ico).*)',
  ],
};
