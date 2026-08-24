# LogVault Library Exports

## Backend (api/)

api/rbac.js
  rbacMiddleware(req, res, next) — attaches req.rbac from X-User-Id/X-User-Role headers (proxy-verified, never trust client-supplied) [SENSITIVE]
  requireAdmin(req, res, next) — 403 unless role is admin/super_admin
  requireSuperAdmin(req, res, next) — 403 unless role is super_admin
  getSiteFilter(rbac, startParamIndex, tableAlias) — RBAC clause for raw syslog_entries reads (subquery join to known_hosts)
  getStatsSiteFilter(rbac, startParamIndex, tableAlias) — same as getSiteFilter, alias defaults to stats-query shape
  getAlertSiteFilter(rbac, startParamIndex, tableAlias) — RBAC clause scoped by alert_events.source_host → known_hosts
  getRollupSiteFilter(rbac, startParamIndex) — RBAC clause for rollup-table reads (plain site_id column, no join — site_id pre-resolved at rollup-build time)

api/auditLog.js
  writeAudit(pool, req, action, details) — insert into append-only audit_log; detail must never carry secrets/full payloads

api/csv.js
  escapeCsvCell(value) — CSV injection-safe cell escaping for /api/logs/export

api/licenseCheck.js
  getLicense(forceRefresh) — fetch/cache license state from NocVault hub, 24h server cache [SENSITIVE][external]
  getLicenseState(license) — derive {mode, canWrite, disabled} from raw license object
  fetchLicense() — raw HTTP call to hub license endpoint [SENSITIVE][external]

api/netvaultSync.js
  syncFromNetVault(pool) — pull devices into known_hosts from NetVault's DB [external]
  getNetvaultSites(pool) — fetch site list from NetVault's DB [external]

api/pdfCharts.js
  renderTrendChart(...) — chart image generation for PDF reports

api/reports.js
  createReportsRouter(pool) — Express router factory mounted at /api/reports; REPORTS registry defines report types, logRun() best-effort-logs to report_run_history (wrapped in try/catch so a logging failure never breaks an export). Types: security-summary, site-activity, mitre-coverage, web-usage (2.32.0), blocked-threat (2.32.0), custom (2.33.0). CUSTOM_DIMENSIONS is the custom builder's whitelist — 15 (dimension -> table/column/metric) entries, all literals in the file, so generated SQL is fixed at author time and only VALUES are ever bound; the user never supplies a table, column or SQL. Each entry targets a pre-aggregated rollup (tens-to-hundreds of ms, never the raw 57 GB table) and was validated against live data before being offered. supportsCategory marks the only two tables carrying a category column — a category filter on any other dimension is REJECTED with 400, never silently ignored. **Anti-drift contract:** each type exposes ONE gather(db, query, rbac) -> {columns, rows, summary, charts}, and the router feeds that single payload to the JSON, CSV and PDF renderers alike — the screen and the export cannot disagree because they are not separate implementations. Never compute a report figure in the frontend, and never add a second query path for the PDF (that is exactly how SpanVault's screen/PDF numbers drifted apart).

api/soc.js
  createSocRouter(pool) — Express router factory mounted at /api/soc; composes existing stats/security/ueba/anomaly/alert/threat aggregates into SOC-console payloads (overview, deterministic NLG digest, alert killchain, entity timeline). No new tables — compute-on-read only. Uses ./rbac site filters + a local anomalySiteFilter/getCached/rbacCacheKey copy (those are module-private in server.js)

## Frontend (frontend/src/lib/)

publicUrl.ts
  resolveOrigin(req, port, legacyFallback) — derive origin URL from request, with legacy env-var fallback
  getHubUrl() — NocVault hub URL for cross-app nav (Launcher link, SSO redirect) — reflects CURRENT window.location, not a module-level constant, so always call at use-time not import-time

## Frontend auth config (frontend/src/auth.ts, not in lib/ but same role)

auth.ts
  authOptions — NextAuth config: SSO/credentials providers, JWT session strategy, apps claim (per-user app-access) [SENSITIVE]

## Version source of truth

next.config.js reads root package.json's version directly (`require('../package.json').version`) and injects it as NEXT_PUBLIC_APP_VERSION — this is the ONLY correct source for the displayed app version. Do NOT import version from frontend/package.json (a separate, unrelated file nothing in the release process bumps — see gotchas.md).

(lib) frontend/src/lib/corners.ts — rounded/square corner switch. getCorners/applyCorners/toggleCorners/CORNERS_KEY/CORNERS_EVENT/CORNERS_INIT_SCRIPT. Key logvault-corners, event logvault:corners, attribute data-corners="square" on <html>; rounded = ABSENCE of the attribute (no [data-corners="rounded"] rule exists). Overrides --radius/--radius-sm/--radius-pill ONLY, so ANY hardcoded numeric borderRadius opts that component out SILENTLY — always use the token. LogVault styles inline, so this is easy to reintroduce.

(api) api/countryAlias.js — COUNTRY_ALIASES / countryAliasCte(). Reconciles the two country-name spellings in this DB: FortiGate writes ISO long forms into structured_data.srccountry/dstcountry ("Russian Federation", "Korea, Republic of"), known_hosts stores GeoIP common names ("Russia", "South Korea"), so an exact-match join silently resolves no country_code — the country ranks correctly but loses its flag, and on the Threat Map its bubble too (centroids are keyed by alpha-2). countryAliasCte() emits a `country_alias(raw, common)` VALUES CTE; join it as LEFT JOIN country_alias ca ON ca.raw = <name>, then LEFT JOIN code_map cm ON cm.country_name = COALESCE(ca.common, <name>) — COALESCE means an unaliased name still joins on itself, so it can only ADD matches. Used by /api/stats/geo (server.js) and gatherTopCountries (soc.js). NEVER display the aliased name: the drill-through free-text searches the raw logs, so showing "Russia" where the logs say "Russian Federation" returns nothing.
