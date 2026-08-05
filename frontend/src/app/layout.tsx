import type { Metadata } from 'next';
import { getServerSession } from 'next-auth/next';
import { authOptions }      from '@/auth';
import './globals.css';
import { ThemeProvider }   from '@/components/ThemeContext';
import { ToastProvider }   from '@/components/Toast';
import AuthProvider        from '@/components/AuthProvider';
import IdleTimeout         from '@/components/IdleTimeout';
import { LicenseProvider, LicenseGate } from '@/components/LicenseGuard';
import UpdateNotifier      from '@/components/UpdateNotifier';
import UpdateFailureBanner from '@/components/UpdateFailureBanner';
import { CORNERS_INIT_SCRIPT } from '@/lib/corners';

export const metadata: Metadata = {
  title: 'LogVault — Syslog Analyzer',
  description: 'NocVault Network Syslog Analyzer',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Fetch the session server-side so AuthProvider can hydrate SessionProvider —
  // removes the client /api/auth/session round-trip on every page load.
  const session = await getServerSession(authOptions);
  return (
    <html lang="en">
      <head>
        {/* Corner-style no-flash: stamps data-corners on <html> synchronously,
            before first paint, so a square-corners user never sees a frame of
            rounded UI. Must stay a blocking inline script — a next/script or a
            useEffect runs after paint, which is the flash we're avoiding.
            NOTE: the light/dark theme has no equivalent yet (ThemeContext applies
            it in a useEffect, so the theme still flashes). Giving it the same
            treatment is a separate change — deliberately not bundled here. */}
        <script dangerouslySetInnerHTML={{ __html: CORNERS_INIT_SCRIPT }} />
      </head>
      <body>
        <AuthProvider session={session}>
          <LicenseProvider>
            <ThemeProvider>
              <ToastProvider>
                {/* LicenseGate hard-blocks EVERY route with the full-screen lock when the
                    license is disabled/unlicensed — the notifier/idle-timeout and
                    page content only render when the app is actually licensed.
                    LicenseBanner is rendered inside page.tsx (below the sticky Header,
                    in the content column) so it sits in normal flow beneath the header —
                    matching DDIVault — instead of above it. */}
                <LicenseGate>
                  <UpdateNotifier />
                  <UpdateFailureBanner />
                  <IdleTimeout />
                  {children}
                </LicenseGate>
              </ToastProvider>
            </ThemeProvider>
          </LicenseProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
