# LogVault API Routes

Two surfaces:
- **Express API** (`api/server.js`, port 3005 internal-only) — the real API, 74 routes. Express has no `dynamic` export concept; force-dynamic check N/A for all of these.
- **Next.js routes** (`frontend/src/app/api/`) — 1 route, NextAuth only.

Auth model (frontend/src/proxy.ts): every `/api/*` request is proxied to Express with `X-User-Id`/`X-User-Role` stamped from the verified session token. Only 5 EXACT paths bypass the session check: `/api/health`, `/api/stats`, `/api/license-status`, `/api/system/update-available`, `/api/system/last-update-status` — sub-paths (e.g. `/api/stats/summary`) are NOT covered by the `/api/stats` allow-list entry and still require a session. `[auth]` below = requires session; `[admin]`/`[super-admin]` = also gated by `requireAdmin`/`requireSuperAdmin` in api/rbac.js.

## Next.js (frontend/src/app/api/)
GET/POST /api/auth/[...nextauth] [public] [external] — NextAuth handler, exports from @/auth

## Express — Dashboard stats (api/server.js)
GET /api/stats/summary [auth] [db] — severity breakdown, reads syslog_stats_rollup
GET /api/stats/timeline [auth] [db] — time-bucketed severity series; ≤6h reads raw, >6h reads rollup
GET /api/stats/top-talkers [auth] [db] — top source IPs, reads syslog_talker_rollup + live known_hosts enrichment
GET /api/stats/top-destinations [auth] [db] — top destination IPs, reads syslog_dest_rollup + live enrichment
GET /api/stats/by-vendor [auth] [db] — per-vendor log/critical/error counts, reads syslog_stats_rollup
GET /api/stats/top-security-events [auth] [db] — classified event-type counts, reads syslog_security_event_rollup
GET /api/stats/top-failures [auth] [db] — connection-failure dest IPs, reads syslog_dest_event_rollup (event_class='failure')
GET /api/stats/top-blocked [auth] [db] — blocked/denied dest IPs, reads syslog_dest_event_rollup (event_class='blocked')
GET /api/stats/mitre-coverage [auth] [db] — ATT&CK technique coverage (event + alert-derived), GIN-indexed
GET /api/stats/vpn-summary [auth] [db] — VPN total/failures/successes/ssl_alerts, reads syslog_vpn_rollup
GET /api/stats/alerts-summary [auth] [db] — unacked count + 24h total + 3 most recent, for dashboard widget
GET /api/alerts/unacked-count [auth] [db] — lightweight header-bell badge count
GET /api/stats/top-services [auth] [db] — Fortinet service breakdown, reads syslog_fortinet_field_rollup
GET /api/stats/firewall-actions [auth] [db] — Fortinet action breakdown, reads syslog_fortinet_field_rollup
GET /api/stats/storage [auth] [db] — DB/table size, row counts (approx via reltuples), 7d growth; getCached 60s TTL
GET /api/stats/heatmap [auth] [db] — day-of-week × hour-of-day activity heatmap, metric=all|auth_failed
GET /api/stats/geo [auth] [db] — country-level event geo breakdown
GET /api/stats/forecast [auth] [db] — 30d volume trend/projection + silent-device detection, reads rollups
GET /api/stats/whats-changed [auth] [db] — new countries/users/sources/services vs 30d baseline, reads syslog_distinct_value_rollup
GET /api/stats/disk [auth] [external] — C: drive usage via PowerShell Get-PSDrive
GET /api/stats [public] [db] — bare aggregate summary for the NocVault launcher (unauthenticated)

## Express — Log search/export
GET /api/logs [auth] [db] — full-text/filtered log search (q, vendor, severity, host, category, technique, threat)
GET /api/logs/recent-critical [auth] [db] — severity ≤3 events, last N hours
GET /api/logs/export [auth] [db] — CSV export of filtered logs

## Express — Alert rules & events
GET /api/alerts/rules [admin] [db] — full alert_rules list
GET /api/alert-rules [admin] [db] — lightweight rule list (id/name/notify_email) for Settings
PUT /api/alert-rules/:id/notify [admin] [db] — update per-rule email recipients
POST /api/alerts/rules [admin] [db] — create alert rule
PATCH /api/alerts/rules/:id [admin] [db] — enable/disable rule
GET /api/alerts/events [auth] [db] — fired alerts, optional ?hours window
PATCH /api/alerts/events/:id/acknowledge [auth] [db] — ack one alert
PATCH /api/alerts/events/acknowledge-all [auth] [db] — bulk ack (all open, or specific ids)
GET /api/alerts/events/recent-unacked [auth] [db] — top 5 unacked, for AlertBanner
GET /api/alerts/events/:id/logs [auth] [db] — underlying syslog rows behind a fired alert (correlation-rule lookback window)

## Express — Known hosts / sites
GET /api/search [auth] [db] — global header search: grouped preview across known_hosts, alert_events and syslog_entries. Site-scoped per group (known_hosts.site_id / getAlertSiteFilter / getSiteFilter). Min 2 chars. Log branch is HARD-BOUNDED to 24h + LIMIT 5 because it runs per keystroke against 10.5M rows/43GB — do not widen either bound.
GET /api/hosts [auth] [db] — known_hosts list
PUT /api/hosts [admin] [db] — upsert a manual host entry
GET /api/sites [admin] [db] [external] — sites from NetVault CMDB, for manual site-assignment dropdown
POST /api/hosts/sync-netvault [super-admin] [db] [external] — pull devices/sites from NetVault DB

## Express — Threat intel
GET /api/threats/known-bad [auth] [db] [external] — known-bad/high-abuse hosts + 24h hit counts, reads syslog_known_bad_hit_rollup

## Express — Network Health
GET /api/health/interfaces [auth] [db] — interface up/down events
GET /api/health/flaps [auth] [db] — interface flap detection
GET /api/health/stp [auth] [db] — STP/loop events
GET /api/health/macflaps [auth] [db] — MAC flapping events
GET /api/health/config-changes [auth] [db] — device config-change events
GET /api/health/routing [auth] [db] — OSPF/BGP/EIGRP neighbor events
GET /api/health/device-status [auth] [db] — per-device status table, reads syslog_device_status_rollup (24h fields) + live 1h subquery (logs_1h — deliberately NOT rollup-derived, see gotchas.md)
GET /api/health/summary [auth] [db] — 5-metric dashboard mini-widget (interface/stp/mac/config/routing counts)

## Express — Security
GET /api/security/summary [auth] [db] — auth-fail/deny/vpn/ips/after-hours/brute-force/known-bad counts. Since 2.30.0 the SQL lives in api/securityKpis.js (gatherSecurityKpis) and is SHARED with soc.js gatherSecurity — do not re-inline it, the two copies had already drifted. Cached 60s per (hours, rbac scope)
GET /api/security/auth-failures [auth] [db] — auth failure event list
GET /api/security/brute-force [auth] [db] — brute-force detection (repeated auth fail from one source)
GET /api/security/firewall-denies [auth] [db] — Fortinet action='blocked' events (NOT 'deny' — see gotchas.md)
GET /api/security/vpn-events [auth] [db] — VPN connect/disconnect/fail events
GET /api/security/ips-events [auth] [db] — IPS/UTM threat events
GET /api/security/after-hours [auth] [db] — auth/config events outside 07:00-19:00
GET /api/security/wireless-auth [auth] [db] — wireless auth events
GET /api/security/top-targeted-users [auth] [db] — most-attacked usernames
GET /api/security/failed-logins-by-country [auth] [db] [external] — geo-mapped failed logins

## Express — Anomalies (Phase 2 UEBA)
GET /api/anomalies [auth] [db] — anomaly_events list, filters hours/type/severity/acknowledged
GET /api/anomalies/summary [auth] [db] — 24h totals + unacked + by-type/severity breakdown
PATCH /api/anomalies/:id/acknowledge [auth] [db] — ack one anomaly
PATCH /api/anomalies/acknowledge-all [auth] [db] — bulk ack

## Express — UEBA
GET /api/ueba/top [auth] [db] — top entities by risk score, reads entity_risk
GET /api/ueba/entity/:type/:value [auth] [db] — per-entity drill-down: risk detail + 7d activity (syslog_entity_activity_rollup) + baseline
GET /api/ueba/baseline-status [auth] [db] — baseline-readiness indicator, never 500s

## Express — Reports (api/reports.js, mounted at /api/reports)
GET /api/reports/ [auth] [db] — list available report types
GET /api/reports/:type [auth] [db] — generate report (format=json|csv|pdf), logs to report_run_history

## Express — SOC console (api/soc.js, mounted at /api/soc)
GET /api/soc/overview [auth] [db] — one composed dashboard payload (severity + totals + top entities/countries + active incidents + security counters); reuses stats/summary, ueba/top, stats/geo, alerts, security/summary, threats/known-bad SQL; cached 30s per rbac scope
GET /api/soc/digest [auth] [db] — deterministic templated NLG digest (no LLM, no email); headline + 5 sections (incidents/anomalies/entities/threats/volume) each with worst-finding severity; cached 30s per rbac scope
GET /api/soc/killchain/:alertId [auth] [db] — underlying syslog entries behind a fired alert, chronological; reuses /api/alerts/events/:id/logs lookback query (window from rule.threshold_window, cap 200); 404 if not found/not site-visible
GET /api/soc/entity-timeline/:type/:value [auth] [db] — daily activity series (syslog_entity_activity_rollup) + anomalies for one entity over ?days=14; :type in device|user|srcip

## Express — Hosts sync / audit / settings / system
GET /api/settings [auth] [db] — app_settings key/value read
POST /api/settings [super-admin] [db] — app_settings write
POST /api/settings/test-email [super-admin] [external] — send test SMTP email with unsaved settings
GET /api/audit [super-admin] [db] — audit_log query (?actor, ?limit)
GET /api/license-status [public] [external] — license state from NocVault hub (24h server-cached)
GET /api/health [public] [db] — liveness + version + logs_last_hour
GET /api/system/update-available [public] [external] — git-commit-hash update check (git transport, not GitHub API)
GET /api/system/update-status [super-admin] [external] — in-progress update status
GET /api/system/last-update-status [public] [db=file] — reads logs/last-update-status.json written by Update-LogVault.ps1's Write-StatusJson (BOM-stripped defensively); {exists:false} if the file doesn't exist yet. Feeds UpdateFailureBanner.
POST /api/system/update [super-admin] [external] — trigger update via detached SYSTEM scheduled task; 409 if logs/update.lock shows one is already running (PID still alive) — mirrors Update-LogVault.ps1's own concurrency-guard lock file
GET /api/ws-ticket [auth] — RBAC-scoped ticket for the Live Tail WebSocket

## Needs force-dynamic
N/A — no Next.js API routes in this app touch the DB (the one Next.js route, NextAuth, doesn't). Everything DB-backed is Express, which has no equivalent caching concern at the framework level (see CLAUDE.md's Cache-Control incident write-up for the actual caching gotcha that DID bite this app).
