// frontend/src/middleware.ts
import { withAuth } from 'next-auth/middleware';
import { NextResponse } from 'next/server';

export default withAuth(
  function middleware(req) {
    // If authenticated, allow through
    return NextResponse.next();
  },
  {
    callbacks: {
      authorized: ({ token }) => !!token,
    },
    pages: {
      signIn: `${process.env.NETVAULT_HUB_URL || 'http://localhost:3000'}/login`,
    },
  }
);

// Protect all routes except NextAuth API routes and static files
export const config = {
  matcher: [
    '/((?!api/auth|_next/static|_next/image|favicon.ico).*)',
  ],
};
