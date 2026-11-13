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
  escapeCsvCell(value) — CSV injection-safe cell escaping (formula guard for a leading = + - @ TAB CR, then RFC-4180 quoting). Ported from DDIVault, with one deliberate divergence: \r is also in the quoting test, because syslog messages carry bare CRs
  buildLogsExportCsv(rows) — the /api/logs/export body (header + rows). Lives here ON PURPOSE: server.js used to hand-roll its own esc() with no formula guard while never importing this module, so an attacker-planted `=cmd|...` syslog message was emitted raw. Keeping the column layout next to the escaper means a new column cannot reintroduce a parallel escaper
  LOGS_EXPORT_HEADER — the export's header line (no trailing newline)

api/paging.js
  safePage(val, limit) -> {page, offset, clamped} — clamps the OFFSET (not the page number) to MAX_OFFSET_ROWS. `page` on /api/logs had a floor but no ceiling, so ?page=100000000 walked the whole received_at index across every partition, and a float page (?page=1e20) 500'd as an invalid bigint
  MAX_OFFSET_ROWS — the row cap (100000)

api/ackScope.js
  parseAckId(raw) -> int|null — one acknowledge id; digits only, 1..int4max (parseInt('7abc') is a DIFFERENT valid row, so a loose parse is not a parse)
  parseAckIds(body) -> {ids}|{error} — the bulk-ack id list; an empty/missing list is an ERROR, never "all"
  buildAckUpdate(table, ids, ackBy, siteFilter) -> {sql, params} — the site-scoped acknowledge UPDATE for alert_events/anomaly_events. The caller passes the filter so the choice stays beside its read twin: alert_events MUST use getAlertSiteFilter (source_host), NOT getSiteFilter (source_ip collapses to zero rows) [SENSITIVE]

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

## Backend (collector/)

collector/safeRegex.js
  unsafePatternReason(pattern, flags) -> reason|null — the WRITE-time gate for operator-supplied alert-rule regexes: syntax, then a static nested-quantifier/huge-repeat screen, then a RAMPED empirical probe (10/14/18/22/26-char adversarial inputs, 15ms per step). The ramp is what keeps the screen itself bounded
  staticScreen / probe / syntaxError — the three stages, separately testable
  hostPatternToRegexSource(matchHost) — '%' -> '.*', the expansion the collector compiles. Screen THIS, not the raw match_host, or you validate a different pattern than the one that runs
  testWithBudget(pattern, input, label, flags) -> {matched, skipped, ms} — MATCH-time: compile-once cache + per-message time budget; the first message that blows MATCH_BUDGET_MS quarantines the pattern so later messages skip it. `skipped` means NOT EVALUATED — treat as a non-match, never as a match
  isQuarantined / quarantineReport / compile / _resetState
  Required by BOTH api/server.js (write gate) and collector/collector.js (hot path). Does not import anything. [SENSITIVE]

collector/suiteSmtp.js
  resolveSmtp(localCfg) -> {source:'hub'|'local', cfg} — the suite SMTP transport resolver (Phase 2 of net-vault/docs/nocvault-smtp-centralization-plan.md). Reads netvault.smtp_config over the NETVAULT_DB_* pool this app already has, caches 5 min (negative results too), and merges: host/port/secure/username/password from the HUB, From identity + the smtp_enabled master switch from LOCAL. NEVER THROWS and NEVER REJECTS — falls back to localCfg and warns ONCE per process on: 42P01 undefined_table (a hub not yet updated — expected in the field), any other query/connection error, NEXTAUTH_SECRET missing while a password is stored, and a password that fails to decrypt
  getHubSmtp() -> hubCfg|null — the cached hub read on its own; null means "no usable hub transport", for any reason
  decryptSecret(encrypted, secret) -> string|null — AES-256-GCM `ivHex:tagHex:cipherHex`, key = sha256(secret). **CONTRACT: byte-identical to ddivault/collector/credStore.js and net-vault/lib/credStore.ts** — change one, change all three. tests/suiteSmtp.test.js pins a fixed vector produced by ddivault's credStore
  _resetCache() — test seam (clears the cache AND the warn-once set); CACHE_TTL
  ⛔ Does NOT throw at module load when NEXTAUTH_SECRET is absent, unlike the credStore it copies — it is required by collector/collector.js, so a load-time throw would stop syslog ingestion over a mail setting. The reasoning is written out at the top of the file; do not "fix" it back [SENSITIVE]

collector/emailer.js
  sendAlertEmail / shouldSendEmail / testEmail — unchanged contracts
  getSmtpStatus(pool) -> {source, host?, port?, secure?} — what GET /api/settings reports. Deliberately narrow: NEVER returns a username or password (getSmtpSettings, which does, stays module-private)
  getSmtpSettings is now hub-aware via suiteSmtp.resolveSmtp; buildTransport() uses cfg.secure VERBATIM when cfg.secureExplicit is set (a hub config) and only then falls back to the historical `port === 465` derivation

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
