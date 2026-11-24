// frontend/src/app/auth/error/route.ts
//
// `authOptions.pages.error` — the error twin of ../signin/route.ts.
//
// ⛔ IT IS A SECOND PATH ON PURPOSE, NOT A COPY. auth.ts previously pointed
// `pages.signIn` AND `pages.error` at the identical hub URL, so nothing in a
// log or a browser history could tell "LogVault asked you to sign in" apart
// from "LogVault's auth configuration failed". The two carry different query
// strings from NextAuth, too (next-auth/core/index.js):
//   signIn -> ?callbackUrl=<where the user was going>[&error=<code>]
//   error  -> ?error=<code>            (never a callbackUrl)
// so the error code is the ONLY thing there is to carry here, and it is carried
// rather than dropped — the hub's login page acts on `error=AccessDenied`, and
// an unrecognised code is ignored there rather than shown raw. (The post-login
// destination is the same constant on both routes; only the error code differs.)
//
// Both routes land the browser on the same hub login page, because that is the
// only place in the suite a person can sign in. What differs is which facts
// survive the hop, and that is now explicit in two files instead of implicit in
// one duplicated string.
//
// See ../signin/route.ts and @/lib/authRedirect for the matcher exclusion and
// the force-dynamic requirement — both apply identically here.

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { hubLoginLocation } from '@/lib/authRedirect';

export const dynamic = 'force-dynamic';

export function GET(req: NextRequest) {
  return NextResponse.redirect(hubLoginLocation(req), 307);
}

export function HEAD(req: NextRequest) {
  return NextResponse.redirect(hubLoginLocation(req), 307);
}
