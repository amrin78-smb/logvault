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
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
        <style>{`
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
          :root {
            --bg:        #0d1117;
            --surface:   #161c26;
            --surface2:  #1c2333;
            --border:    #30363d;
            --border2:   #21262d;
            --text:      #e6edf3;
            --text2:     #8b949e;
            --text3:     #6e7681;
            --accent:    #58a6ff;
            --accent2:   #1f6feb;
            --green:     #3fb950;
            --yellow:    #d29922;
            --orange:    #db6d28;
            --red:       #f85149;
            --purple:    #a371f7;
            --cyan:      #39d353;
          }
          body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; }
          ::-webkit-scrollbar { width: 6px; height: 6px; }
          ::-webkit-scrollbar-track { background: var(--bg); }
          ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
          ::-webkit-scrollbar-thumb:hover { background: var(--text3); }
        `}</style>
      </head>
      <body>{children}</body>
    </html>
  );
}
