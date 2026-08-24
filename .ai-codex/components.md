# LogVault Components (frontend/src/components/)

Every file has `'use client'` at the top — this app has no server components below the root layout. `(c)` marker kept per spec but is redundant here (all are client).

(c) AlertBanner  (no props — self-fetching)
(c) AlertDetailPanel  alert, onClose, onAcknowledge
(c) AlertEvents  initialTechnique?, hours?, onTechniqueConsumed?
(c) AuthProvider  children (NextAuth SessionProvider wrapper)
(c) TopSecurityEvents  hours, onNavigate? — from DashboardWidgets.tsx
(c) TopBlockedDestinations  hours, onNavigate? — from DashboardWidgets.tsx
(c) TopConnectionFailures  hours, onNavigate? — from DashboardWidgets.tsx
(c) VPNStatus  hours, onNavigate? — from DashboardWidgets.tsx
(c) ActiveAlertsSummary  onNavigate — from DashboardWidgets.tsx
(c) FirewallActions  hours — from DashboardWidgets.tsx
(c) InterfaceEventsSummary  hours, onNavigate — from DashboardWidgets.tsx
(c) CapacityIngestionHealth  openExplorer? — from DashboardWidgets.tsx
(c) WhatsChanged  openExplorer? — from DashboardWidgets.tsx
(c) RiskiestEntities  openExplorer?, onNavigate? — from DashboardWidgets.tsx
(c) ErrorBoundary  children (class component, catches render errors)
(c) Header  (no props — self-fetching: collector status poll, unacked count poll)
(c) Heatmap  data, title?, cellHeight? — generic day×hour heatmap renderer
(c) IdleTimeout  (no props — self-fetching idle_timeout_minutes from /api/settings)
(c) IntelligenceConsole  openExplorer?, hours — UEBA/anomaly console
(c) KnownHosts  (no props — self-fetching)
(c) LicenseProvider  children — from LicenseGuard.tsx
(c) useLicense()  hook — from LicenseGuard.tsx
(c) LicenseGate  children — from LicenseGuard.tsx
(c) LicenseBanner  (no props) — from LicenseGuard.tsx
(c) LicenseDisabledScreen  mode? — from LicenseGuard.tsx
(c) LiveTail  (no props — WebSocket-driven, browser-only). NOT a tab since 2.31.0: rendered by LogExplorer as its "Live Tail" mode via next/dynamic ssr:false. page.tsx no longer imports it.
(c) LogDetailPanel  log, onClose, onFilterIP, onFilterVendor, onFilterSeverity
(c) LogExplorer  initialFilter?, onFilterUsed?
(c) NetworkHealth  hours, onHoursChange, refreshInterval, onRefreshChange
(c) RecentCritical  hours, onRowClick?
(c) ReportsTab  (no props — self-contained) — catalog of 5 report types mirrors api/reports.js's REPORTS registry; the local REPORTS array here is presentation only (title/desc/colour/icon). All figures, columns and charts come from the server payload — never compute a report number in this component, or the screen and the CSV/PDF export start to drift.
(c) SecurityAnalysis  hours, onHoursChange, refreshInterval, onRefreshChange, onTechnique, onDrill
(c) SocOverview  hours, openExplorer, openAlerts — SIEM Phase 4 SOC single-pane (soc tab); fetches /api/soc/overview + /api/soc/digest; opens KillChainTimeline
(c) KillChainTimeline  alertId, onClose — modal; fetches /api/soc/killchain/:alertId; groups events into MITRE tactic phases (mitre.tsx)
(c) EntityProfile  hours, openExplorer — SIEM Phase 3 UEBA entity explorer (entities tab); /api/ueba/top + /api/ueba/entity/:type/:value + /api/soc/entity-timeline
(c) ThreatMap  hours, openExplorer — SIEM Phase 3 world attack map (threatmap tab); /api/stats/geo + bundled COUNTRY_CENTROIDS (bubbles) + bundled worldLand.json (continent outlines, Natural Earth 110m), inline SVG equirectangular, no map dep
(c) Settings  (no props — self-contained, largest component file)
(c) SeverityChart  summary, onSeverityClick?, compact?
(c) StorageWidget  (no props — self-fetching)
(c) ThemeProvider  children — from ThemeContext.tsx
(c) countryFlag(code)  — helper fn, from ThreatIntel.tsx
(c) KnownBadBadge  score?, compact? — from ThreatIntel.tsx
(c) GeoInline  row — from ThreatIntel.tsx
(c) KnownBadSources  onNavigate? — from ThreatIntel.tsx
(c) TimeRangePicker  hours, onHoursChange, refreshInterval, onRefreshChange, onRefreshNow
(c) TimelineChart  hours, compact?
(c) ToastProvider  children — from Toast.tsx
(c) TopDestinations  hours, onHostClick?
(c) TopTalkers  hours, onHostClick?, compact?
(c) Trend  value, prev, invert? — small up/down indicator, used across widgets
(c) UpdateFailureBanner  (no props — polls /api/system/last-update-status every 5min; admin/super_admin only via useSession(), dismissible per-timestamp)
(c) UpdateNotifier  (no props — polls /api/system/update-available)
(c) VendorBreakdown  hours, onVendorClick?, compact?
(c) mitreInfo/mitreUrl/mitreTitle(id)  — helper fns, from mitre.tsx
(c) MitrePopover  id — from mitre.tsx
(c) MitreBadges  ids?, compact? — from mitre.tsx
(c) sevLabel/sevStyle(severity)  — helper fns, from severity.tsx
(c) SevBadge  label — from severity.tsx
(c) vendorColor(vendor)/riskBand(score)  — helper fns, from palette.tsx (vendor identity + entity risk-band colors, companion to severity.tsx)
(c) RiskBadge  score, suffix? — from palette.tsx
(c) pctColor/Skeleton/TableSkeleton/CardSkeleton/EmptyState  — generic UI primitives, from ui.tsx
(c) usePaged/Pagination/PagedTableBody — client-side paging (ui.tsx, PAGE_SIZE 25). Use <PagedTableBody items={x} unit="rows"> as a drop-in for a <tbody> holding a long list; it owns its own page state and renders the pager in a <tfoot>, so it works inside components that have early returns. Applied to 19 tables + KnownHosts. Safe because every list endpoint is already capped server-side (15-500 rows) — EXCEPT /api/hosts, which is unbounded and still ships all 38k rows.

## Violations
None found — no component is defined inside another component's function body (checked both `function X(` and `const X = (` nested-indentation patterns across all 37 files).

(c) CornersToggle — Rounded/Square segmented row rendered INSIDE the avatar dropdown in Header.tsx, below the Light/Dark Mode item. Not in Settings (that tab is role-gated and this is a per-browser preference every role must reach) and not in the top bar (it looked wrong there). Reads its value in useEffect, never at render — the <html> attribute does not exist during SSR, so reading at render is a hydration mismatch. NOTE: ui.tsx Skeleton default radius prop is now var(--radius-sm), not 6 — a numeric default would silently opt every skeleton out of the square switch.
