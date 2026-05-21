/** @type {import('next').NextConfig} */
const nextConfig = {
  // Allow NextAuth to work on local HTTP network
  env: {
    NEXTAUTH_URL:              process.env.NEXTAUTH_URL,
    NEXT_PUBLIC_NETVAULT_HUB_URL: process.env.NEXT_PUBLIC_NETVAULT_HUB_URL,
  },
};

module.exports = nextConfig;
