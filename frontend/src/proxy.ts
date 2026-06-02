// frontend/src/proxy.ts
import { withAuth } from 'next-auth/middleware';
import { NextResponse } from 'next/server';

export default withAuth(
  function proxy(req) {
    return NextResponse.next();
  },
  {
    callbacks: {
      authorized: ({ token }) => !!token,
    },
    pages: {
      signIn: process.env.NOCVAULT_HUB_URL
        ? `${process.env.NOCVAULT_HUB_URL}/login`
        : 'http://localhost:3000/login',
    },
  }
);

// Only protect the actual page routes
// Do NOT intercept /api/* — those are proxied to port 3005
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sso).*)',
  ],
};
