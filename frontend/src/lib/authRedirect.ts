// frontend/src/lib/authRedirect.ts
//
// The per-request browser redirect target behind NextAuth's `pages.signIn` /
// `pages.error`. Used by the two local bounce routes
// (src/app/auth/signin/route.ts and src/app/auth/error/route.ts).
//
// ⛔ WHY THOSE ROUTES EXIST — DO NOT PUT AN ABSOLUTE URL BACK IN `pages`.
//
// NextAuth v4 evaluates `authOptions.pages` ONCE at module load. Its core does
// nothing but string-concatenate the stored value:
//   next-auth/core/index.js  ->  redirect: `${pages.signIn}?callbackUrl=...`
//                                redirect: `${pages.error}?error=...`
// so a value built from an env var can never follow the request. auth.ts used
// to pin BOTH entries to `${NOCVAULT_HUB_URL}/login` — and NOCVAULT_HUB_URL is
// DELIBERATELY the hub's SERVER-SIDE LOOPBACK (net-vault 1.60.1): a
// server-to-server hub call routed through the public TLS front door fails with
// ERR_TLS_CERT_ALTNAME_INVALID, because the production certificate names the
// site and not the IP. That makes the variable right for every server-side
// fetch and dead for a browser. Production therefore answered
//   GET /api/auth/signin  ->  302 Location: http://127.0.0.1:13000/login?...
// to a BROWSER, which cannot follow the server's own loopback. The page gate in
// proxy.ts was correct throughout, because it calls resolveOrigin() per
// request.
//
// `pages` now holds LOCAL RELATIVE paths. NextAuth writes them to the Location
// header verbatim (next-auth/next/index.js), a relative Location is resolved by
// the browser against the host it is already on, so the first hop stays on
// LogVault — and these routes then make the cross-origin hop with the SAME
// resolveOrigin() call the page gate already makes.
//
// ⛔ NOCVAULT_HUB_URL itself is untouched and must stay untouched. It is still
// the right value for server-side calls, and it is still the legacy fallback
// here for the one case resolveOrigin() cannot serve (a request carrying no
// usable Host) — exactly as proxy.ts passes it.

import type { NextRequest } from 'next/server';
import { resolveOrigin } from './publicUrl';

// The two local bounce paths. Kept here so auth.ts, the route handlers and
// proxy.ts's matcher exclusion cannot drift apart.
//
// ⛔ Both are excluded from the page-route matcher in proxy.ts. They MUST be:
// anything that matcher catches goes through the "no session -> redirect to the
// hub login" guard, and a sign-in page that is itself behind the sign-in guard
// is an infinite redirect.
export const SIGNIN_PATH = '/auth/signin';
export const ERROR_PATH = '/auth/error';

/**
 * Where the hub should send the browser back to once it has a session: the
 * hub's OWN SSO issuer for LogVault, which mints a short-lived signed token and
 * redirects to LogVault's `/sso` page with it.
 *
 * ⛔ A CONSTANT, AND THAT IS THE SECURITY PROPERTY. Nothing from the request or
 * the query string reaches the redirect, so a foreign host cannot appear in the
 * output BY CONSTRUCTION — there is no sanitiser to get wrong and no incoming
 * `callbackUrl` to re-base. An earlier draft took the path+query off NextAuth's
 * appended `callbackUrl` and re-based it on LogVault's own request-derived
 * origin; that needed an open-redirect guard, needed this app's own public port
 * derived from proxy headers (see the port-precedence trap in
 * .ai-codex/gotchas.md), and produced a value the hub DISCARDS anyway.
 *
 * ⛔ IT IS A HUB PATH, NOT A LOGVAULT PATH, and it must stay relative. The
 * hub's login page honours only a same-origin relative target — net-vault
 * `app/(auth)/login/page.tsx` requires `startsWith('/')`, rejects `//`, `/sso`
 * and `/login`, and falls back to `/launcher` for anything else — so an
 * absolute LogVault URL is thrown away there. `/api/sso/logvault` starts with
 * `/api`, so it clears that guard.
 *
 * ⛔ THE SPELLING IS A CONTRACT WITH THE OTHER REPOSITORY. It is the verbatim
 * value the hub's own issuer uses when IT finds no session
 * (net-vault `app/api/sso/logvault/route.ts`:
 * `new URL('/login?callbackUrl=%2Fapi%2Fsso%2Flogvault', ownOrigin)`), so the
 * post-login hop is one the hub already drives. Check that file before
 * changing a character of it.
 */
export const HUB_SSO_CALLBACK_PATH = '/api/sso/logvault';

/**
 * Does `name` name THIS session cookie — the cookie itself, or one of its
 * chunks?
 *
 * ⛔ EXACT-OR-`<base>.` PREFIX, NOT A BARE `startsWith`. next-auth SPLITS a
 * session cookie over 4096 bytes into `<base>.0`, `<base>.1`, … (`SessionStore`
 * / `#chunk()` in next-auth/core/lib/cookie.js) and `getToken()` reassembles
 * from exactly that set, so matching the chunk prefix is matching what the
 * reader reads — it cannot drift if the suffix scheme changes. But a bare
 * `startsWith(base)` would also swallow `nexvault.session-tokenfoo`, which is
 * somebody else's cookie and must never be mistaken for a session of ours.
 *
 * Same shape as the siblings (spanvault `lib/hubSignin.ts`, ddivault's inline
 * guard) — deliberately, because three different shapes across three repos is
 * how the `x-forwarded-port` precedence bug happened.
 */
export function isSessionCookieName(name: string, base: string): boolean {
  return name === base || name.startsWith(`${base}.`);
}

/**
 * Is a session cookie PRESENT (readable or not) among `cookieNames`?
 *
 * Used by the page gate in proxy.ts to tell "never signed in" from "signed in
 * but the cookie cannot be decoded" — two situations `getToken()` reports
 * identically, as null, and which need opposite answers. See the gotchas entry
 * "The page gate's `callbackUrl` is CONDITIONAL".
 *
 * ⛔ `__Secure-<base>` is checked as INSURANCE and is NOT live here today.
 * next-auth spreads `authOptions.cookies` OVER `defaultCookies(useSecureCookies)`,
 * and `frontend/src/auth.ts` overrides `cookies.sessionToken.name` with the
 * literal `nexvault.session-token`, so the prefix — which exists only in those
 * defaults — is never written on this app; `secure: true` changes the cookie's
 * FLAGS, never its NAME. Removing that override (the obvious "simplify") makes
 * the prefixed form live immediately, which is why it is matched here and why a
 * test pins the override's continued existence.
 */
export function hasSessionCookie(cookieNames: Iterable<string>, base: string): boolean {
  for (const name of cookieNames) {
    if (isSessionCookieName(name, base)) return true;
    if (isSessionCookieName(name, `__Secure-${base}`)) return true;
  }
  return false;
}

// NextAuth's own error codes are short identifiers ('CredentialsSignin',
// 'AccessDenied', 'Configuration', ...). Anything else is not an error code.
const ERROR_CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;

function stripTrailingSlash(origin: string): string {
  return origin.endsWith('/') ? origin.slice(0, -1) : origin;
}

/**
 * NextAuth's error code, or null if the query carried something else.
 *
 * This is the ONE value that crosses from the query string into the redirect,
 * and it is safe to carry for a reason that does not generalise: it is a short
 * closed-charset identifier, not a URL, so it cannot name a host or a scheme.
 * The hub's login page acts on `AccessDenied` and ignores codes it does not
 * recognise, which is why forwarding it is worth doing at all — dropping it
 * leaves a refused sign-in indistinguishable from a plain request to sign in.
 */
export function safeErrorCode(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const code = raw.trim();
  return ERROR_CODE_RE.test(code) ? code : null;
}

/**
 * The hub login URL to send the browser to: `<hub>/login` with the constant
 * callbackUrl and, when there is one, the forwarded error code.
 */
export function buildHubLoginUrl(
  hubOrigin: string,
  params: { error?: string | null } = {},
): string {
  const query = new URLSearchParams();
  // URLSearchParams percent-encodes the slashes, giving exactly the
  // `callbackUrl=%2Fapi%2Fsso%2Flogvault` the hub writes itself.
  query.set('callbackUrl', HUB_SSO_CALLBACK_PATH);

  const error = safeErrorCode(params.error);
  if (error) query.set('error', error);

  return `${stripTrailingSlash(hubOrigin)}/login?${query.toString()}`;
}

/**
 * The full Location for a sign-in / error bounce: the hub's login page on the
 * hostname the browser is actually using, port 3000 (NetVault always runs on
 * 3000 regardless of this app's own port).
 */
export function hubLoginLocation(req: NextRequest): string {
  // Same call, same explicit port and same legacy fallback as the page-route
  // guard in proxy.ts. NOCVAULT_HUB_URL is read HERE rather than at module
  // scope only so it is a fallback and not a baked-in constant.
  const hubFallback = process.env.NOCVAULT_HUB_URL || 'http://localhost:3000';
  const hubOrigin = resolveOrigin(req, 3000, hubFallback);

  return buildHubLoginUrl(hubOrigin, { error: req.nextUrl.searchParams.get('error') });
}
