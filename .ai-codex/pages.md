# LogVault Page Tree

Whole app is effectively ONE page — `page.tsx` renders a client-side tab switcher (`Tab` type: dashboard|explorer|alerts|health|security|intelligence|entities|hosts|reports|settings); tabs are NOT separate Next.js routes, they're conditional renders driven by component state. Only 2 real routes besides that. (SIEM Phase 3+4, v2.26.0 added 3 tabs; v2.30.0 MERGED `soc`+`threatmap` INTO the `security` tab as sub-views — `security` now holds a `SecView` state of overview|detections|map, rendering SocOverview / SecurityAnalysis / ThreatMap. Only the ACTIVE sub-view mounts, which is what cut the tab from ~15 concurrent requests to ~5. `LEGACY_TAB_MAP` still maps the old `soc`/`threatmap` ids from a `nocvault:navigate` event onto the right sub-view.)

[server] / — layout.tsx — root layout: session, ThemeProvider, ToastProvider, AuthProvider, IdleTimeout, LicenseGate, UpdateNotifier, UpdateFailureBanner
[client] / — page.tsx (default export) — the entire app: header, sidebar nav, and all 13 tabs' content, switched by client state
[client] /sso — SSOHandler (in frontend/src/app/sso/page.tsx, its own route file) — SSO landing page, calls next-auth signIn() then redirects
[server] /api/auth/[...nextauth] — NextAuth route handler (re-exports GET/POST from @/auth)

## Dashboard tab contents (all rendered inline by page.tsx, not routes)
KPI tiles, SeverityChart, TimelineChart, TopTalkers, TopDestinations, VendorBreakdown, DashboardWidgets' 10 exports (TopSecurityEvents/TopBlockedDestinations/TopConnectionFailures/VPNStatus/ActiveAlertsSummary/InterfaceEventsSummary/FirewallActions/CapacityIngestionHealth/WhatsChanged/RiskiestEntities), ThreatIntel's KnownBadSources, StorageWidget

## Other tabs — code-split via next/dynamic (ssr:false), loaded on first click
SocOverview (security>overview), LogExplorer (owns LiveTail as a Search/Live mode since 2.31.0), AlertEvents, NetworkHealth, SecurityAnalysis (security>detections), ThreatMap (security>map), IntelligenceConsole, EntityProfile (entities), KnownHosts, ReportsTab, Settings

## SIEM Phase 3+4 surfaces (v2.26.0) — all compute-on-read via /api/soc/*
- SocOverview (soc tab) — SOC single-pane: fetches /api/soc/overview + /api/soc/digest (deterministic narrative digest, no AI/email); composes SeverityChart, KPI totals, top countries, riskiest entities, security signals, TopSecurityEvents, and an active-incidents list. An incident row opens KillChainTimeline (modal).
- KillChainTimeline — modal (opened from SocOverview), fetches /api/soc/killchain/:alertId; groups the alert's underlying log events into MITRE tactic phases (ordered by MITRE_TACTIC_ORDER from mitre.tsx).
- EntityProfile (entities tab) — UEBA entity explorer: list from /api/ueba/top, profile from /api/ueba/entity/:type/:value, 14-day trend from /api/soc/entity-timeline; risk-factor explainability, recent anomalies, events-by-category.
- ThreatMap (security tab, "Threat Map" sub-view) — dependency-free equirectangular SVG world attack map from /api/stats/geo; bundled COUNTRY_CENTROIDS (141), bubbles by count + ranked list with trend.
