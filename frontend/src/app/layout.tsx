import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider }   from '@/components/ThemeContext';
import { ToastProvider }   from '@/components/Toast';
import AuthProvider        from '@/components/AuthProvider';
import IdleTimeout         from '@/components/IdleTimeout';
import { LicenseProvider, LicenseBanner } from '@/components/LicenseGuard';
import UpdateNotifier      from '@/components/UpdateNotifier';

export const metadata: Metadata = {
  title: 'LogVault — Syslog Analyzer',
  description: 'NocVault Network Syslog Analyzer',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <LicenseProvider>
            <ThemeProvider>
              <ToastProvider>
                <LicenseBanner />
                <UpdateNotifier />
                <IdleTimeout />
                {children}
              </ToastProvider>
            </ThemeProvider>
          </LicenseProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
