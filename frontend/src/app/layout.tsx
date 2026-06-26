import type { Metadata } from 'next';
import { getServerSession } from 'next-auth/next';
import { authOptions }      from '@/auth';
import './globals.css';
import { ThemeProvider }   from '@/components/ThemeContext';
import { ToastProvider }   from '@/components/Toast';
import AuthProvider        from '@/components/AuthProvider';
import IdleTimeout         from '@/components/IdleTimeout';
import { LicenseProvider, LicenseBanner, LicenseGate } from '@/components/LicenseGuard';
import UpdateNotifier      from '@/components/UpdateNotifier';

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
      <body>
        <AuthProvider session={session}>
          <LicenseProvider>
            <ThemeProvider>
              <ToastProvider>
                {/* LicenseGate hard-blocks EVERY route with the full-screen lock when the
                    license is disabled/unlicensed — the banner/notifier/idle-timeout and
                    page content only render when the app is actually licensed. */}
                <LicenseGate>
                  <LicenseBanner />
                  <UpdateNotifier />
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
