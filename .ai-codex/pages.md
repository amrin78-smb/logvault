# LogVault Page Tree

Whole app is effectively ONE page — `page.tsx` renders a client-side tab switcher (`Tab` type: dashboard|explorer|livetail|alerts|health|security|intelligence|hosts|reports|settings); tabs are NOT separate Next.js routes, they're conditional renders driven by component state. Only 2 real routes besides that.

[server] / — layout.tsx — root layout: session, ThemeProvider, ToastProvider, AuthProvider, IdleTimeout, LicenseGate, UpdateNotifier, UpdateFailureBanner
[client] / — page.tsx (default export) — the entire app: header, sidebar nav, and all 10 tabs' content, switched by client state
[client] /sso — SSOHandler (in frontend/src/app/sso/page.tsx, its own route file) — SSO landing page, calls next-auth signIn() then redirects
[server] /api/auth/[...nextauth] — NextAuth route handler (re-exports GET/POST from @/auth)

## Dashboard tab contents (all rendered inline by page.tsx, not routes)
KPI tiles, SeverityChart, TimelineChart, TopTalkers, TopDestinations, VendorBreakdown, DashboardWidgets' 10 exports (TopSecurityEvents/TopBlockedDestinations/TopConnectionFailures/VPNStatus/ActiveAlertsSummary/InterfaceEventsSummary/FirewallActions/CapacityIngestionHealth/WhatsChanged/RiskiestEntities), ThreatIntel's KnownBadSources, StorageWidget

## Other tabs — code-split via next/dynamic (ssr:false), loaded on first click
LogExplorer, LiveTail, AlertEvents, NetworkHealth, SecurityAnalysis, IntelligenceConsole, KnownHosts, ReportsTab, Settings
