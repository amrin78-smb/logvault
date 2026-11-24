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
// The post-login return path, shared with app/auth/signin/route.ts so this gate
// and NextAuth's sign-in redirect cannot drift apart — plus the session-cookie
// presence predicate behind the loop guard in the page branch below.
import { HUB_SSO_CALLBACK_PATH, hasSessionCookie } from '@/lib/authRedirect';

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
//
// ⛔ /api/system/last-update-status is NOT on this list and must not be added
// "for consistency with /api/system/update-available". update-available returns
// two version strings; last-update-status spreads the WHOLE status file written
// by Update-LogVault.ps1 — stage reached, error code, raw updater error text,
// rollback flag, plus whatever install paths or commit hashes the script wrote.
// It sat here and was readable with no session at all. Its only two consumers
// (UpdateFailureBanner, and the Settings update overlay) always have a session
// and are admin-only in the UI, and the Express route now carries requireAdmin
// to match. SpanVault's frontend/src/middleware.ts refuses the same route for
// the same reason — see the ⛔ comment there.
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
    // Carry the hub's own SSO re-entry path so signing in returns the user to
    // LogVault instead of the launcher. The hub honours it because it is
    // relative and starts with neither /sso nor /login (see the filter in
    // net-vault app/(auth)/login/page.tsx).
    //
    // ⛔ BUT ONLY FOR A VISITOR WITH NO SESSION COOKIE AT ALL, AND THAT
    // CONDITION IS LOAD-BEARING. getToken() also returns null when a cookie
    // EXISTS and cannot be READ: `secureCookie` above is derived from
    // NEXTAUTH_URL's protocol, so an http NEXTAUTH_URL on an https deployment
    // -- or a rotated NEXTAUTH_SECRET -- makes every valid session unreadable.
    // Sending those users back with a callbackUrl loops: the hub mints a
    // token, /sso sets a cookie, this gate still cannot read it, back to the
    // hub, forever. Nothing on either side counts hops, so the browser spins
    // until ERR_TOO_MANY_REDIRECTS, which is far harder to diagnose than the
    // launcher. Omitting the callbackUrl makes the hub fall back to /launcher,
    // so a misconfiguration STOPS VISIBLY instead of spinning.
    // ⛔ "PRESENT" MEANS THE COOKIE *OR ANY OF ITS CHUNKS*, so this is a
    // prefix test and not `cookies.has(name)`. next-auth splits a session
    // cookie over 4096 bytes into `<name>.0`, `<name>.1`, … and getToken()
    // reassembles from that set, so a chunked session is one getToken() can
    // read and `has('<name>')` cannot SEE — and a chunked session that is ALSO
    // unreadable would land straight back in the loop above. The predicate is
    // exact-or-`<name>.` (never a bare startsWith, which would count somebody
    // else's `<name>foo`) and lives in @/lib/authRedirect so it is unit-tested
    // and identical to the siblings' guards.
    //
    // LogVault's real exposure here is chunking plus a rotated NEXTAUTH_SECRET.
    // The `__Secure-` form the helper also matches is insurance only: auth.ts
    // overrides the cookie NAME with a literal, so next-auth never writes the
    // prefixed name on this app (see the helper's own comment).
    const cookieNames = req.cookies.getAll().map((c) => c.name);
    if (hasSessionCookie(cookieNames, TOKEN_OPTS.cookieName)) {
      return NextResponse.redirect(`${hub}/login`);
    }
    const callback = encodeURIComponent(HUB_SSO_CALLBACK_PATH);
    return NextResponse.redirect(`${hub}/login?callbackUrl=${callback}`);
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
    // Page routes → auth guard (exclude api, sso landing, the auth bounce
    // routes, next internals and public static assets).
    //
    // `auth/signin` and `auth/error` MUST stay excluded. They are
    // authOptions.pages.signIn / .error (src/app/auth/*/route.ts): local,
    // request-aware 307s to the hub's login page. The guard below answers "no
    // session" with exactly that redirect, so gating the redirect target itself
    // is an infinite loop — the browser would be sent to /auth/signin, be found
    // unauthenticated there, and be sent to /auth/signin again. They disclose
    // nothing: both only re-derive the hub origin from the request and bounce.
    //
    // `flags` MUST stay excluded. Anything this matcher catches goes through
    // the auth guard and comes back as app HTML, so /flags/sg.svg returned a
    // 10 KB HTML document with Content-Type text/html instead of the SVG —
    // every country flag rendered as a broken image, and a missing flag
    // answered 200 instead of 404 so the component's onError fallback could
    // never fire. They are public artwork with no data in them, exactly like
    // favicon.ico above. Excluding them also keeps them true static assets:
    // no per-request JWT verification, and next.config.js's /flags/ 
    // Cache-Control rule actually applies (a middleware-rendered response
    // carries the page's headers, not the static file's).
    '/((?!api|sso|auth/signin|auth/error|_next/static|_next/image|favicon.ico|flags/).*)',
  ],
};
