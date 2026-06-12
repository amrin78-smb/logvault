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
//   2. Guard page routes — redirect to the NocVault hub login when there is no
//      session.
//
// IMPORTANT: getToken must be told the custom cookie name
// (nexvault.session-token) and that the cookie is not Secure (HTTP on the local
// network), otherwise it returns null and RBAC silently breaks.

import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

const API_BASE = process.env.LV_API_URL || 'http://127.0.0.1:3005';
const HUB = process.env.NOCVAULT_HUB_URL || 'http://localhost:3000';

const TOKEN_OPTS = {
  secret: process.env.NEXTAUTH_SECRET,
  cookieName: 'nexvault.session-token',
  secureCookie: false,
};

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
      headers.set('x-user-id', String((token as { id?: string | number }).id ?? '0'));
      headers.set('x-user-role', String((token as { role?: string }).role ?? 'user'));
    }
    // Unauthenticated API calls (e.g. /api/license-status) pass through with no
    // RBAC headers; Express treats them as the default 'user' (fail-closed).
    return NextResponse.rewrite(target, { request: { headers } });
  }

  // 2. Page-route auth guard.
  const token = await getToken({ req, ...TOKEN_OPTS });
  if (!token) {
    return NextResponse.redirect(`${HUB}/login`);
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
