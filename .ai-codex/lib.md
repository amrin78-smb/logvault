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
  createReportsRouter(pool) — Express router factory mounted at /api/reports; REPORTS array defines report types, logRun() best-effort-logs to report_run_history (wrapped in try/catch so a logging failure never breaks an export)

## Frontend (frontend/src/lib/)

publicUrl.ts
  resolveOrigin(req, port, legacyFallback) — derive origin URL from request, with legacy env-var fallback
  getHubUrl() — NocVault hub URL for cross-app nav (Launcher link, SSO redirect) — reflects CURRENT window.location, not a module-level constant, so always call at use-time not import-time

## Frontend auth config (frontend/src/auth.ts, not in lib/ but same role)

auth.ts
  authOptions — NextAuth config: SSO/credentials providers, JWT session strategy, apps claim (per-user app-access) [SENSITIVE]

## Version source of truth

next.config.js reads root package.json's version directly (`require('../package.json').version`) and injects it as NEXT_PUBLIC_APP_VERSION — this is the ONLY correct source for the displayed app version. Do NOT import version from frontend/package.json (a separate, unrelated file nothing in the release process bumps — see gotchas.md).
