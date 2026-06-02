/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXTAUTH_URL: process.env.NEXTAUTH_URL,
    // Suite-standard hub URL var. Falls back to the legacy NETVAULT name so SSO
    // keeps working during the NSSM env migration if only the old var is set.
    NEXT_PUBLIC_NOCVAULT_HUB_URL:
      process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL || process.env.NEXT_PUBLIC_NETVAULT_HUB_URL,
  },

  // Proxy all /api/* requests (except /api/auth) to the Express API on port 3005
  async rewrites() {
    return [
      {
        source:      '/api/:path((?!auth).*)',
        destination: 'http://localhost:3005/api/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
