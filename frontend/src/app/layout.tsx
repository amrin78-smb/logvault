import type { Metadata } from 'next';

export const metadata: Metadata = {
  title:       'LogVault — Syslog Analyzer',
  description: 'NexVault LogVault: On-premises syslog collection and analysis',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
        <style>{`
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { background: #0f1117; color: #e2e8f0; }
          ::-webkit-scrollbar { width: 6px; height: 6px; }
          ::-webkit-scrollbar-track { background: #161b27; }
          ::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 3px; }
        `}</style>
      </head>
      <body>{children}</body>
    </html>
  );
}
