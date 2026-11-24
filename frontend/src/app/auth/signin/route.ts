// frontend/src/app/auth/signin/route.ts
//
// `authOptions.pages.signIn` — a LOCAL, REQUEST-AWARE bounce to the NocVault
// hub's login page. LogVault has no login UI of its own; the hub is the suite's
// single authentication point.
//
// This route exists because NextAuth v4 reads `pages` once at module load, so
// the previous `${NOCVAULT_HUB_URL}/login` could never follow the request — and
// NOCVAULT_HUB_URL is the hub's server-side LOOPBACK, which a browser cannot
// reach. The full reasoning, and why that variable is still correct everywhere
// else, is at the top of @/lib/authRedirect.
//
// ⛔ This path is excluded from the page-route matcher in frontend/src/proxy.ts.
// It has to be: that matcher's guard redirects an unauthenticated request to the
// hub login, and this route IS that redirect — gating it would loop forever.
//
// ⛔ force-dynamic is not optional. A statically evaluated route handler would
// bake ONE host into the redirect at build time, which is the entire bug being
// fixed here, just moved from an env var to the build.
//
// Nothing from the query string reaches the redirect except a closed-charset
// error code: the post-login destination is the constant HUB_SSO_CALLBACK_PATH,
// so no client value can steer where the browser ends up. See @/lib/authRedirect.

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { hubLoginLocation } from '@/lib/authRedirect';

export const dynamic = 'force-dynamic';

export function GET(req: NextRequest) {
  // 307, not 302: the method and body are irrelevant for a GET bounce, but 307
  // is the honest "this is where to ask instead, don't rewrite the request" —
  // and it keeps anything from caching a hub origin derived from one request's
  // Host header.
  return NextResponse.redirect(hubLoginLocation(req), 307);
}

// A HEAD is answered the same way (matching spanvault's route), so a link
// checker or a prefetch gets the redirect rather than a 405.
export function HEAD(req: NextRequest) {
  return NextResponse.redirect(hubLoginLocation(req), 307);
}
