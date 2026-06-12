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
};

module.exports = nextConfig;
