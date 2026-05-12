import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'LogVault — Syslog Analyzer',
  description: 'NexVault LogVault: On-premises syslog collection and analysis',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
        <style>{`
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
          :root {
            --bg:       #f0f2f5;
            --surface:  #ffffff;
            --surface2: #f8f9fb;
            --nav-bg:   #0f1b2d;
            --nav-text: #a8b9cc;
            --nav-active: #ffffff;
            --nav-accent: #2563eb;
            --border:   #e2e6ea;
            --text:     #1a202c;
            --text2:    #4a5568;
            --text3:    #718096;
            --accent:   #2563eb;
            --accent2:  #1d4ed8;
            --green:    #16a34a;
            --yellow:   #ca8a04;
            --orange:   #ea580c;
            --red:      #dc2626;
            --purple:   #7c3aed;
            --cyan:     #0891b2;
          }
          body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; }
          ::-webkit-scrollbar { width: 6px; height: 6px; }
          ::-webkit-scrollbar-track { background: var(--bg); }
          ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        `}</style>
      </head>
      <body>{children}</body>
    </html>
  );
}
