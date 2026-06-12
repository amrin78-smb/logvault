'use client';
import { SessionProvider } from 'next-auth/react';
import type { Session } from 'next-auth';

// Hydrated with the server-fetched session so useSession() resolves the user's
// identity on first paint — no client round-trip to /api/auth/session, which
// was the main cause of the "slow to detect who logged in" loading flash.
export default function AuthProvider({
  children,
  session,
}: {
  children: React.ReactNode;
  session: Session | null;
}) {
  return <SessionProvider session={session}>{children}</SessionProvider>;
}
