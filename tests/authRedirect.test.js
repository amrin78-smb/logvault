'use strict';

/**
 * Tests for the sign-in / error redirect target (frontend/src/lib/authRedirect.ts).
 *
 * THE BUG THIS PINS, measured live on production:
 *     GET /api/auth/signin
 *  -> 302 Location: http://127.0.0.1:13000/login?callbackUrl=https%3A%2F%2F<ip>%3A3004
 *
 * That Location goes to a BROWSER, and `http://127.0.0.1:13000` is the HUB's
 * server-side loopback — dead from a browser. auth.ts pinned both
 * `pages.signIn` and `pages.error` to `${NOCVAULT_HUB_URL}/login`, and NextAuth
 * v4 evaluates `pages` ONCE at module load, so neither could ever follow the
 * request. NOCVAULT_HUB_URL is deliberately the loopback (a server-to-server
 * hub call through the public TLS front door fails ERR_TLS_CERT_ALTNAME_INVALID
 * against a certificate that names the site, not the IP) — so the variable is
 * right and the REDIRECT was wrong.
 *
 * The fix routes both pages through local request-aware handlers that call
 * resolveOrigin(), exactly as the page gate in frontend/src/proxy.ts already
 * did. These tests assert that the host comes from the REQUEST and never from
 * the env var, and that the post-login destination is a constant — so no
 * client-supplied value can appear in the redirect at all.
 *
 * All hosts below are placeholders (example.com / example.net). Nothing
 * production-specific belongs in a test.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { registerHooks } = require('node:module');
const { pathToFileURL } = require('node:url');

const FRONTEND_SRC = path.join(__dirname, '..', 'frontend', 'src');

// ── loading the modules under test ──────────────────────────────────────────
//
// The files under test are frontend TypeScript that imports `next/server`,
// `next-auth/jwt` and the `@/` path alias. Plain `node --test` can resolve none
// of the three: `next` lives under frontend/ and ships no `exports` map, so a
// bare ESM `import 'next/server'` fails with ERR_MODULE_NOT_FOUND, and `@/` is
// a tsconfig path only Next and tsc know about. These hooks supply all three,
// so the modules load EXACTLY AS WRITTEN — no source is edited at load time.
// Node strips the TypeScript types itself, so what runs is the real file.
//
// (An earlier version of this file instead deleted publicUrl.ts's
// `import { NextRequest } from 'next/server'` line from the source as it
// loaded. That worked — the import is type-only — but it hid the real module
// graph, so a genuinely broken import in a file under test could have passed
// here. Resolving the specifier to a stub is the same amount of code and keeps
// the graph honest. publicUrl.ts itself is untouched either way: there is a
// standing decision not to modify the satellites' resolveOrigin.)
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'next/server') {
      return { url: pathToFileURL(path.join(__dirname, 'helpers', 'next-server.stub.mjs')).href,
               shortCircuit: true, format: 'module' };
    }
    if (specifier === 'next-auth/jwt') {
      return { url: pathToFileURL(path.join(__dirname, 'helpers', 'next-auth-jwt.stub.mjs')).href,
               shortCircuit: true, format: 'module' };
    }
    // The tsconfig `@/*` alias -> frontend/src/*.
    if (specifier.startsWith('@/')) {
      return { url: pathToFileURL(path.join(FRONTEND_SRC, specifier.slice(2) + '.ts')).href,
               shortCircuit: true };
    }
    // tsconfig uses moduleResolution "bundler", so the house style for a
    // same-directory import is extensionless (`./publicUrl`). Plain node ESM
    // needs the extension; adding one in the source would be writing for the
    // test runner instead of for Next. Scoped to .ts importers so it cannot
    // touch this file's own requires — registerHooks() applies to require()
    // as well as import().
    const fromTs = (context.parentURL || '').endsWith('.ts');
    if (fromTs && /^\.{1,2}\//.test(specifier) && !path.extname(specifier)) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
});

// Proves the hub host is derived from the request: if any assertion below ever
// reads the env var instead, it reads THIS, which is not a host any test expects.
process.env.NOCVAULT_HUB_URL = 'http://127.0.0.1:13000';

const {
  SIGNIN_PATH,
  ERROR_PATH,
  HUB_SSO_CALLBACK_PATH,
  safeErrorCode,
  buildHubLoginUrl,
  hubLoginLocation,
  isSessionCookieName,
  hasSessionCookie,
} = require('../frontend/src/lib/authRedirect.ts');

const ENV_HUB = 'http://127.0.0.1:13000';

/**
 * A minimal stand-in for NextRequest: resolveOrigin() and hubLoginLocation()
 * use only `headers.get()` and `nextUrl`.
 */
function fakeReq(url, headers = {}) {
  return { headers: new Headers(headers), nextUrl: new URL(url) };
}

/** The sign-in bounce as NextAuth drives it: ?callbackUrl=<absolute>. */
function signinReq(callbackUrl, headers) {
  const u = new URL(`http://internal.invalid:3004${SIGNIN_PATH}`);
  if (callbackUrl !== undefined) u.searchParams.set('callbackUrl', callbackUrl);
  return fakeReq(u.toString(), headers);
}

// What the TLS terminator actually sends. `x-forwarded-port` is present only to
// make these requests realistic: nothing in the redirect path reads it any more
// (the hub port is always the explicit 3000, and nothing derives LogVault's own
// port since the callbackUrl became a constant).
//
// ⛔ AND ITS PRESENCE HERE IS NOT A TRIPWIRE — an earlier version of this
// comment claimed it was. Every assertion below is about the HUB origin, whose
// port is passed explicitly, so a future change that read `x-forwarded-port`
// to derive THIS APP's own origin would break none of them. If you add such a
// derivation, you must add its own test; read the port-precedence entry in
// .ai-codex/gotchas.md first, because the obvious ordering is the wrong one.
const PUBLIC_HEADERS = {
  'x-forwarded-host': 'logs.example.com',
  'x-forwarded-proto': 'https',
  'x-forwarded-port': '3004',
  host: 'internal.invalid:3004',
};

// ── the bug itself ─────────────────────────────────────────────────────────

test('signin bounces to the REQUEST host on :3000, never to NOCVAULT_HUB_URL', () => {
  const location = hubLoginLocation(signinReq('https://logs.example.com:3004/', PUBLIC_HEADERS));

  const parsed = new URL(location);
  assert.equal(parsed.origin, 'https://logs.example.com:3000');
  assert.equal(parsed.pathname, '/login');
  // The whole point: the hub's loopback must appear nowhere in the Location.
  assert.ok(!location.includes('127.0.0.1'), location);
  assert.ok(!location.includes(ENV_HUB), location);
});

test('the error page bounces the same way — it was pinned to the loopback too', () => {
  // NextAuth's error redirect carries ?error=<code> and never a callbackUrl
  // (next-auth/core/index.js), so the error route is exercised with that shape.
  const req = fakeReq(
    `https://internal.invalid:3004${ERROR_PATH}?error=CredentialsSignin`,
    PUBLIC_HEADERS,
  );
  const location = hubLoginLocation(req);

  const parsed = new URL(location);
  assert.equal(parsed.origin, 'https://logs.example.com:3000');
  assert.equal(parsed.pathname, '/login');
  assert.equal(parsed.searchParams.get('error'), 'CredentialsSignin');
  assert.ok(!location.includes('127.0.0.1'), location);
});

test('a plain Host header (no reverse proxy) is honoured just the same', () => {
  const location = hubLoginLocation(
    signinReq('http://logs.example.com:3004/alerts', { host: 'logs.example.com:3004' }),
  );
  assert.equal(new URL(location).origin, 'http://logs.example.com:3000');
});

test('the scheme follows x-forwarded-proto, so an HTTPS site is never sent to http', () => {
  const location = hubLoginLocation(
    signinReq('https://logs.example.com:3004/', {
      host: 'internal.invalid:3004',
      'x-forwarded-host': 'logs.example.com',
      'x-forwarded-proto': 'https',
    }),
  );
  assert.ok(location.startsWith('https://logs.example.com:3000/login'), location);
});

// ── the post-login destination is a CONSTANT ───────────────────────────────

test('the callbackUrl is the hub SSO issuer path, not anything from the request', () => {
  const location = hubLoginLocation(signinReq('https://logs.example.com:3004/', PUBLIC_HEADERS));
  assert.equal(new URL(location).searchParams.get('callbackUrl'), '/api/sso/logvault');
});

test('the spelling matches the hub verbatim, percent-encoded exactly as the hub writes it', () => {
  // net-vault app/api/sso/logvault/route.ts, when IT finds no session:
  //   new URL('/login?callbackUrl=%2Fapi%2Fsso%2Flogvault', ownOrigin)
  // A mismatch here is a contract break with the other repository.
  assert.equal(HUB_SSO_CALLBACK_PATH, '/api/sso/logvault');
  const location = hubLoginLocation(signinReq(undefined, PUBLIC_HEADERS));
  assert.equal(location, 'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault');
});

test('the callbackUrl clears the hub login page\'s own relative-target guard', () => {
  // net-vault app/(auth)/login/page.tsx discards anything that is not relative,
  // or that starts with '//', '/sso' or '/login', falling back to /launcher.
  const cb = HUB_SSO_CALLBACK_PATH;
  assert.ok(cb.startsWith('/'), cb);
  assert.ok(!cb.startsWith('//'), cb);
  assert.ok(!cb.startsWith('/sso'), cb);
  assert.ok(!cb.startsWith('/login'), cb);
});

// ── no client value can reach the redirect ─────────────────────────────────
//
// These are the open-redirect tests. They assert the property BY CONSTRUCTION
// (the host is never taken from input) rather than that a sanitiser cleaned a
// hostile value — a stronger guarantee than the sanitising draft they replace.

test('a foreign absolute callbackUrl is ignored outright, not re-based', () => {
  const location = hubLoginLocation(
    signinReq('https://evil.example.net/steal?token=abc', PUBLIC_HEADERS),
  );

  assert.equal(new URL(location).searchParams.get('callbackUrl'), HUB_SSO_CALLBACK_PATH);
  assert.ok(!location.includes('evil.example.net'), location);
  assert.ok(!location.includes('steal'), location);
});

test('no hostile callbackUrl shape survives, because none of them is read', () => {
  const hostile = [
    'https://evil.example.net/steal',
    '//evil.example.net/steal',
    '/\\evil.example.net/steal',
    'javascript:alert(1)',
    'data:text/html,<script>',
    'mailto:a@example.com',
    `https://logs.example.com:3004${SIGNIN_PATH}`,
    'http://user:pass@evil.example.net/',
    `/${'a'.repeat(4000)}`,
  ];
  for (const raw of hostile) {
    const location = hubLoginLocation(signinReq(raw, PUBLIC_HEADERS));
    assert.equal(
      location,
      'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault',
      `callbackUrl=${raw}`,
    );
  }
});

test('a MALFORMED host header is rejected, and the legacy fallback used instead', () => {
  // ⛔ SCOPE, BECAUSE THE OLD TITLE OVERSTATED IT ("a hostile host header cannot
  // steer the redirect"). This covers only a host that FAILS resolveOrigin's
  // hostname-shape check. A WELL-FORMED spoofed Host genuinely does steer the
  // redirect — `Host: evil.example.net` yields
  // `http://evil.example.net:3000/login?...`, measured live — because
  // resolveOrigin trusts the host it is reached on by design. That is
  // pre-existing, suite-wide behaviour of publicUrl.ts (which is explicitly out
  // of scope here and shared with ddivault/spanvault), it predates these two
  // routes, and the page gate at `/` was already reachable the same way. Do not
  // read this test as proof that host spoofing is handled.
  const location = hubLoginLocation(
    signinReq(undefined, { host: 'evil.example.net/@logs.example.com' }),
  );
  assert.ok(!location.includes('evil.example.net'), location);
  assert.equal(location, `${ENV_HUB}/login?callbackUrl=%2Fapi%2Fsso%2Flogvault`);
});

// ── error codes: the ONE value carried from the query ──────────────────────

test('only a real NextAuth error code is forwarded', () => {
  assert.equal(safeErrorCode('AccessDenied'), 'AccessDenied');
  assert.equal(safeErrorCode('CredentialsSignin'), 'CredentialsSignin');
  assert.equal(safeErrorCode(null), null);
  assert.equal(safeErrorCode(''), null);
  assert.equal(safeErrorCode('   '), null);
  // Not a code: punctuation, markup, spaces, a URL, or an essay.
  for (const raw of [
    '<script>alert(1)</script>',
    'two words',
    'a'.repeat(65),
    'a/b',
    'https://evil.example.net',
  ]) {
    assert.equal(safeErrorCode(raw), null, raw);
  }
});

test('a junk error code is dropped from the Location, not echoed', () => {
  const req = fakeReq(
    `https://internal.invalid:3004${ERROR_PATH}?error=${encodeURIComponent('https://evil.example.net')}`,
    PUBLIC_HEADERS,
  );
  const location = hubLoginLocation(req);
  assert.equal(new URL(location).searchParams.get('error'), null);
  assert.ok(!location.includes('evil.example.net'), location);
});

test('signin forwards an error code when NextAuth attaches one', () => {
  // next-auth appends `&error=<code>` to the signin redirect for a failed
  // credentials sign-in, so the signin route sees both parameters.
  const u = new URL(`https://internal.invalid:3004${SIGNIN_PATH}`);
  u.searchParams.set('callbackUrl', 'https://logs.example.com:3004/');
  u.searchParams.set('error', 'CredentialsSignin');

  const parsed = new URL(hubLoginLocation(fakeReq(u.toString(), PUBLIC_HEADERS)));
  assert.equal(parsed.searchParams.get('error'), 'CredentialsSignin');
  assert.equal(parsed.searchParams.get('callbackUrl'), HUB_SSO_CALLBACK_PATH);
});

// ── the legacy fallback is unchanged ───────────────────────────────────────

test('a request with no usable Host still falls back to NOCVAULT_HUB_URL', () => {
  // resolveOrigin()'s documented behaviour, kept verbatim: never worse than
  // before. This is the ONLY path on which the env var is read, and a browser
  // request always carries a Host.
  const req = fakeReq(`http://internal.invalid:3004${SIGNIN_PATH}`);
  assert.equal(hubLoginLocation(req), `${ENV_HUB}/login?callbackUrl=%2Fapi%2Fsso%2Flogvault`);
});

// ── composition ───────────────────────────────────────────────────────────

test('buildHubLoginUrl does not double up slashes on a trailing-slash origin', () => {
  assert.equal(
    buildHubLoginUrl('https://logs.example.com:3000/'),
    'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault',
  );
});

// ── the WIRING: pages + the two handlers ───────────────────────────────────
//
// ⛔ THESE EXIST BECAUSE EVERYTHING ABOVE PASSED WITH THE BUG FULLY RESTORED.
// An adversarial review of this file reverted `pages` in frontend/src/auth.ts
// to `${process.env.NOCVAULT_HUB_URL}/login` AND rewrote both route handlers to
// redirect to that env var, and the suite stayed 16/16 green: it tested
// authRedirect.ts, and the bug lived in the two files that CALL it. A test that
// still passes with the bug reintroduced is worth nothing, so the wiring is now
// pinned too — the handlers by calling them, `pages` by reading the source.

/** Source with comments stripped, so a comment quoting the OLD shape cannot satisfy a regex. */
function sourceWithoutComments(relPath) {
  return fs
    .readFileSync(path.join(FRONTEND_SRC, relPath), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

test('auth.ts pins pages.signIn/.error to the LOCAL RELATIVE paths, with no env var', () => {
  const src = sourceWithoutComments('auth.ts');

  const pages = src.match(/pages:\s*\{([\s\S]*?)\n\s*\}/);
  assert.ok(pages, 'pages block not found in frontend/src/auth.ts');
  const block = pages[1];

  // The values themselves, verbatim.
  assert.match(block, /signIn:\s*SIGNIN_PATH\b/);
  assert.match(block, /error:\s*ERROR_PATH\b/);
  assert.equal(SIGNIN_PATH, '/auth/signin');
  assert.equal(ERROR_PATH, '/auth/error');

  // ⛔ The exact shape of the bug: an env var, a template literal, or any
  // absolute URL inside the pages block. Each of these is what a well-meaning
  // "simplification" puts back.
  assert.doesNotMatch(block, /process\.env/, 'pages must not read an env var');
  assert.doesNotMatch(block, /NOCVAULT_HUB_URL/, 'pages must not name the hub env var');
  assert.doesNotMatch(block, /https?:\/\//, 'pages must not hold an absolute URL');
  assert.doesNotMatch(block, /\$\{/, 'pages must not be built by interpolation');

  // And no other `pages.*` entry may creep in pointing off-origin (signOut,
  // verifyRequest, newUser all have the identical module-load trap).
  for (const [, value] of block.matchAll(/^\s*(\w+):\s*(.+?),?\s*$/gm)) {
    assert.doesNotMatch(value, /https?:\/\/|process\.env/, `pages entry must stay local: ${value}`);
  }
});

test('BOTH route handlers 307 to the request-derived hub, not to the env var', async () => {
  // The handlers are the other half the old suite never executed. Called for
  // real, with next/server stubbed, so a handler that stopped calling
  // hubLoginLocation() would fail here.
  for (const relPath of ['app/auth/signin/route.ts', 'app/auth/error/route.ts']) {
    const mod = await import(pathToFileURL(path.join(FRONTEND_SRC, relPath)).href);

    // force-dynamic, or a build could bake one request's host into the answer.
    assert.equal(mod.dynamic, 'force-dynamic', `${relPath} must export force-dynamic`);

    for (const method of ['GET', 'HEAD']) {
      assert.equal(typeof mod[method], 'function', `${relPath} must export ${method}`);
      const res = await mod[method](
        fakeReq(`https://internal.invalid:3004/auth/x?error=AccessDenied`, PUBLIC_HEADERS),
      );
      assert.equal(res.status, 307, `${relPath} ${method}`);
      const location = res.headers.get('location');
      assert.equal(
        location,
        'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault&error=AccessDenied',
        `${relPath} ${method}`,
      );
      assert.ok(!location.includes('127.0.0.1'), `${relPath} ${method}: env-var loopback leaked`);
    }
  }
});

// ── the page gate's loop guard (proxy.ts) ──────────────────────────────────
//
// The gate attaches the post-login callbackUrl ONLY for a visitor with no
// session cookie at all. getToken() also returns null when a cookie EXISTS and
// cannot be READ (an http NEXTAUTH_URL on an https deployment flips
// `secureCookie`; a rotated NEXTAUTH_SECRET does it too), and returning THOSE
// users with a callbackUrl loops forever: hub mints a token -> /sso sets a
// cookie -> the gate still cannot read it -> hub. Nothing counts hops on either
// side, so the browser spins to ERR_TOO_MANY_REDIRECTS. With no callbackUrl the
// hub falls back to /launcher, so the misconfiguration STOPS VISIBLY.

const SESSION_COOKIE = 'nexvault.session-token';

/**
 * A NextRequest stand-in for the page gate: nextUrl + headers + cookies.
 *
 * `getAll()` returning `{ name, value }` objects is what NextRequest's
 * RequestCookies gives, and what the gate now maps over — a prefix test cannot
 * be done through `has(name)`, which is the whole reason the guard reads the
 * cookie LIST rather than asking about four fixed names.
 */
function gateReq(cookieNames = [], headers = PUBLIC_HEADERS, url = 'https://internal.invalid:3004/explorer') {
  return {
    nextUrl: new URL(url),
    headers: new Headers(headers),
    cookies: { getAll: () => cookieNames.map((name) => ({ name, value: 'x' })) },
  };
}

async function gateLocation(req) {
  const { default: proxy } = await import(pathToFileURL(path.join(FRONTEND_SRC, 'proxy.ts')).href);
  const res = await proxy(req);
  assert.equal(res.status, 307, 'the page gate redirects with a 307');
  return res.headers.get('location');
}

test('NO session cookie: the callbackUrl is attached, so sign-in returns to LogVault', async () => {
  const location = await gateLocation(gateReq([]));
  assert.equal(location, 'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault');
});

test('a PRESENT but unreadable session cookie gets NO callbackUrl — the loop guard', async () => {
  // Every name next-auth could have written, including the CHUNKED forms: a
  // session over 4096 bytes is split into `<name>.0`, `<name>.1` …
  // (SessionStore/#chunk in next-auth/core/lib/cookie.js) and getToken()
  // reassembles from that set, so a bare has('<name>') does not see it — hence
  // a prefix predicate, and hence `.1`/`.7` here and not just `.0`.
  // `__Secure-` is insurance, NOT live: next-auth spreads authOptions.cookies
  // over defaultCookies(useSecureCookies), and auth.ts overrides the name with
  // a literal, so the prefixed form is never written on this app.
  for (const name of [
    SESSION_COOKIE,
    `${SESSION_COOKIE}.0`,
    `${SESSION_COOKIE}.1`,
    `${SESSION_COOKIE}.7`,
    `__Secure-${SESSION_COOKIE}`,
    `__Secure-${SESSION_COOKIE}.0`,
  ]) {
    const location = await gateLocation(gateReq([name]));
    assert.equal(
      location,
      'https://logs.example.com:3000/login',
      `cookie ${name} must suppress the callbackUrl`,
    );
    assert.ok(!location.includes('callbackUrl'), `cookie ${name}: callbackUrl must be absent`);
  }
});

test('the predicate matches the cookie and its chunks, and NOTHING that merely looks like it', () => {
  // ⛔ THE LOOKALIKE IS THE POINT OF THE SHAPE. A bare startsWith(base) would
  // count `nexvault.session-tokenfoo` — somebody else's cookie — as a session
  // of ours and silently suppress the callbackUrl for a visitor who has never
  // signed in. Exact-or-`<base>.` is as wide as next-auth's own reader and no
  // wider.
  for (const name of [SESSION_COOKIE, `${SESSION_COOKIE}.0`, `${SESSION_COOKIE}.1`, `${SESSION_COOKIE}.12`]) {
    assert.equal(isSessionCookieName(name, SESSION_COOKIE), true, name);
  }
  for (const name of [
    `${SESSION_COOKIE}foo`,          // a bare startsWith would accept this
    `${SESSION_COOKIE}-2`,
    `${SESSION_COOKIE}_0`,
    `x${SESSION_COOKIE}`,
    'nexvault.session',
    'theme',
    '',
  ]) {
    assert.equal(isSessionCookieName(name, SESSION_COOKIE), false, name);
  }

  // The sweep over a whole cookie jar, including the insurance `__Secure-` form.
  assert.equal(hasSessionCookie([], SESSION_COOKIE), false);
  assert.equal(hasSessionCookie(['theme', 'logvault-sidebar-collapsed'], SESSION_COOKIE), false);
  assert.equal(hasSessionCookie([`${SESSION_COOKIE}foo`], SESSION_COOKIE), false);
  assert.equal(hasSessionCookie(['theme', `${SESSION_COOKIE}.3`], SESSION_COOKIE), true);
  assert.equal(hasSessionCookie([`__Secure-${SESSION_COOKIE}.0`], SESSION_COOKIE), true);
});

test('a LOOKALIKE cookie does not suppress the callbackUrl at the gate either', async () => {
  // The same property through the real proxy(), not just the predicate.
  const location = await gateLocation(gateReq([`${SESSION_COOKIE}foo`, `${SESSION_COOKIE}-2`]));
  assert.equal(location, 'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault');
});

test('auth.ts still OVERRIDES the session cookie name, so the guard reads the right one', () => {
  // ⛔ THE INVERSE OF SPANVAULT'S ASSERTION, AND IT HAS TO BE. SpanVault pins
  // that it has NO `cookies:` block (adding one would change the name the guard
  // reads); LogVault pins that its override is STILL THERE and still this
  // literal. Removing it would hand next-auth's defaults back — which means
  // `__Secure-nexvault.session-token` on an https install — and the guard, the
  // TOKEN_OPTS.cookieName in proxy.ts and getToken() would all have to move
  // together. Fail here instead of changing behaviour silently.
  const src = sourceWithoutComments('auth.ts');
  const cookies = src.match(/cookies:\s*\{([\s\S]*?)\n\s{2}\}/);
  assert.ok(cookies, 'the cookies block is gone from frontend/src/auth.ts — see this test');
  assert.match(cookies[1], /sessionToken:\s*\{/);
  assert.match(cookies[1], /name:\s*'nexvault\.session-token'/);

  // proxy.ts must be asking about that same name.
  const proxySrc = fs.readFileSync(path.join(FRONTEND_SRC, 'proxy.ts'), 'utf8');
  assert.match(proxySrc, /cookieName:\s*'nexvault\.session-token'/);
});

test('an UNRELATED cookie does not suppress the callbackUrl', async () => {
  // The guard must key on the session cookie, not on "the browser sent cookies".
  const location = await gateLocation(gateReq(['theme', 'logvault-sidebar-collapsed']));
  assert.equal(location, 'https://logs.example.com:3000/login?callbackUrl=%2Fapi%2Fsso%2Flogvault');
});

test('the gate derives the hub from the request here too, never from the env var', async () => {
  // Plain Host, no proxy headers: the scheme falls back to the request's own
  // (http here), exactly as resolveOrigin documents.
  const location = await gateLocation(
    gateReq([], { host: 'logs.example.com:3004' }, 'http://logs.example.com:3004/explorer'),
  );
  assert.equal(new URL(location).origin, 'http://logs.example.com:3000');
  assert.ok(!location.includes('127.0.0.1'), location);

  // And behind the terminator, https is carried by x-forwarded-proto.
  const tls = await gateLocation(gateReq([]));
  assert.equal(new URL(tls).origin, 'https://logs.example.com:3000');
});

test('the gate and the sign-in bounce send the SAME callbackUrl', async () => {
  // They are two paths to one hub login; a drift between them is the bug the
  // shared HUB_SSO_CALLBACK_PATH constant exists to prevent.
  const gate = new URL(await gateLocation(gateReq([])));
  const bounce = new URL(hubLoginLocation(signinReq(undefined, PUBLIC_HEADERS)));
  assert.equal(gate.searchParams.get('callbackUrl'), bounce.searchParams.get('callbackUrl'));
  assert.equal(gate.searchParams.get('callbackUrl'), HUB_SSO_CALLBACK_PATH);
});

// ── the routes must not be gated by the page guard ─────────────────────────

test('proxy.ts excludes both bounce paths from the page-route auth guard', (t) => {
  // A gated bounce route is an infinite redirect: no session -> redirect to
  // /auth/signin -> no session -> redirect to /auth/signin. This compiles the
  // matcher with the SAME path-to-regexp Next itself uses, so it is Next's
  // answer and not a hand-rolled approximation of it.
  let pathToRegexp;
  try {
    ({ pathToRegexp } = require('../frontend/node_modules/next/dist/compiled/path-to-regexp'));
  } catch {
    t.skip('frontend deps not installed (npm ci in frontend/) — matcher not compiled');
    return;
  }

  const proxySrc = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'src', 'proxy.ts'), 'utf8');
  const pageMatcher = proxySrc.match(/^\s*'(\/\(\(\?!api\|.*)',\s*$/m);
  assert.ok(pageMatcher, 'could not find the page-route matcher in proxy.ts');

  const re = pathToRegexp(pageMatcher[1]);
  assert.equal(re.test(SIGNIN_PATH), false, `${SIGNIN_PATH} must NOT be matched by the page guard`);
  assert.equal(re.test(ERROR_PATH), false, `${ERROR_PATH} must NOT be matched by the page guard`);
  // The exclusion is precise: ordinary pages, and any other /auth/* path, stay gated.
  assert.equal(re.test('/'), true);
  assert.equal(re.test('/explorer'), true);
  assert.equal(re.test('/auth/other'), true);
});
