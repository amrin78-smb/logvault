/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXTAUTH_URL: process.env.NEXTAUTH_URL,
    // Suite-standard hub URL var. Falls back to the legacy NETVAULT name so SSO
    // keeps working during the NSSM env migration if only the old var is set.
    NEXT_PUBLIC_NOCVAULT_HUB_URL:
      process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || process.env.NEXT_PUBLIC_NETVAULT_HUB_URL,
  },

  // NOTE: /api/* is no longer rewritten directly to the Express API. The
  // authenticated proxy route at src/app/api/[...path]/route.ts forwards each
  // request to http://localhost:3005 after attaching the user's RBAC headers
  // (X-User-Id / X-User-Role). /api/auth/* is handled by the next-auth route.
  // A rewrite cannot attach per-request session headers, so it was removed.
};

module.exports = nextConfig;
