/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXTAUTH_URL: process.env.NEXTAUTH_URL,
    // Suite-standard hub URL var. Falls back to the legacy NETVAULT name so SSO
    // keeps working during the NSSM env migration if only the old var is set.
    NEXT_PUBLIC_NOCVAULT_HUB_URL:
      process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || process.env.NEXT_PUBLIC_NETVAULT_HUB_URL,
  },

  // NOTE: /api/* is proxied to the Express API by the edge middleware in
  // src/proxy.ts (NextResponse.rewrite), which stamps verified X-User-Id /
  // X-User-Role headers from the session token. No next.config rewrite is used
  // for /api/* — a static rewrite cannot strip client-supplied headers or
  // attach per-request session identity. /api/auth/* is handled by next-auth.

  // ── No intermediary caching of the app itself (perf-incident fix, 2026-07) ──
  // A live incident traced a live server flapping between an old cached build
  // and the current one, on the SAME browser/Incognito window, in a way a hard
  // refresh could never fix — because neither a hard refresh nor Incognito mode
  // has any effect on a cache that lives on NETWORK infrastructure between the
  // browser and this server (a corporate proxy/security appliance), not in the
  // browser itself. The page/document responses here carried no explicit
  // Cache-Control at all, which is exactly the shape an RFC 7234-compliant
  // intermediary is permitted to cache heuristically. Force every page response
  // to be non-cacheable so no intermediary can legally store a stale copy.
  //
  // The SECOND rule below deliberately OVERRIDES the first, narrower, for
  // /_next/static/* — Next.js's own long-term caching of these hashed,
  // content-addressed build assets is correct and intentional (a new build
  // always produces new filenames, so caching them forever is safe) and must
  // NOT be disabled; Next.js merges matching header rules and the LAST
  // matching rule wins for a duplicate key, so rule order here matters.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, private' },
          { key: 'Pragma', value: 'no-cache' },
        ],
      },
      {
        source: '/_next/static/:path*',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
