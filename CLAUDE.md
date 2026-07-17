# LogVault — Claude Development Guide

## What is LogVault

LogVault is a syslog analyzer and log management platform, part of the **NocVault Network Intelligence Suite**. It collects syslog from network devices (Fortinet, Cisco, Palo Alto, Aruba, Sangfor, Forcepoint, Check Point, Juniper, Windows, SonicWall), parses and stores them in PostgreSQL, and provides a real-time dashboard, log explorer, alerting, universal event taxonomy, risk scoring, and asset enrichment via NetVault integration.

**Live deployment:** `http://192.168.6.111:3004`  
**GitHub repo:** `https://github.com/amrin78-smb/logvault`  
**Primary customer:** Thai Union Group — ~2,500 network devices across APAC, EMEA, NAM

---

## Installer parity (IMPORTANT — read before any deploy-affecting change)

This app is provisioned two ways that BOTH must stay in sync: the per-app updater
`installer/Update-LogVault.ps1` (upgrades) and the shared **suite installer**
`../netvault/installer/Install-NocVault-Suite.ps1` (fresh install of the whole NocVault
suite — it lives in the **netvault** repo, a sibling of this one). Any change — even a
small one — that affects how the app is provisioned MUST be reflected in BOTH, in the
same change, or fresh installs silently break. This includes: a new/renamed env var the
app reads, a new scheduled task, a new or changed schema file (or required DB
extension/grant), a new NSSM service or changed entrypoint/port, a new firewall port, a
new cross-DB grant, or a new build step. Update and commit the suite installer in the
netvault repo too; if you can't, flag it explicitly so it isn't missed.

**Post-install test script (keep in sync too):** the suite ships a fresh-install smoke
tester at `../netvault/installer/Test-NocVault-Suite.ps1` (it lives in the netvault repo and
verifies services, ports, health/versions, schema, the collectors end-to-end, the tamper
model and cross-DB grants). If you build a feature that a fresh install should be verified
for — a new NSSM service or port, a new DB table/column/seed/extension/grant, a new collector
data path, a new scheduled task, or a new health/endpoint contract — update BOTH the suite
installer AND this test script (both in the netvault repo) in the same change, so fresh
installs stay verifiable.

**Graphical installer/uninstaller/tester (GUI `.exe` wrappers) — IMPORTANT.** The suite ships
Windows GUI wrappers in the netvault repo (`../netvault/installer/`:
`Install-`/`Uninstall-`/`Test-NocVault-Suite-GUI.ps1`, compiled to `NocVault-Suite-Setup.exe` /
`-Uninstall.exe` / `-Test.exe` via `Build-Setup-Exe.ps1` with ps2exe). **These `.exe`s are thin
GUI shells only — all the real logic lives in the `.ps1` scripts they drive**
(`Install-`/`Uninstall-`/`Test-NocVault-Suite.ps1`, launched with `-Unattended`/`-Force`). So for
normal install/uninstall/test changes (a new step, schema, service, grant, env var, port, task)
you just edit the `.ps1` — **no exe rebuild needed**. The ONE exception: if you add or rename a
`param()` on one of those `.ps1` scripts, the matching `*-GUI.ps1` must be updated to pass the
new argument AND the exe rebuilt (`Build-Setup-Exe.ps1`). Always check the parameter surface
when editing an installer script.

---

## Known Security Debt (scheduled, not yet done)

Tracked npm-audit finding deliberately deferred (triaged 2026-06-26). NOT fixable with a
safe `npm audit fix` — needs a breaking change, so schedule as deliberate, tested work.
**NEVER run `npm audit fix --force`.**

- **nodemailer → v9 (root).** The current v8 line carries a high advisory
  (GHSA-p6gq-j5cr-w38f: the message-level `raw` option bypasses
  `disableFileAccess`/`disableUrlAccess` → file-read/SSRF). The only fix is the breaking
  major **9.0.1**. Not currently reachable — SMTP config is admin-only and
  `collector/emailer.js` never uses the `raw` option — so low risk on the internal LAN.
  Upgrade to nodemailer 9.x in a maintenance window and re-test the email alert path.

(The frontend Next.js + ws/qs backend advisories were cleared in 2.18.2.)

---

## NocVault Suite Context

| Product | Purpose | Port |
|---|---|---|
| **NetVault** | Network asset management (devices, sites, circuits) | 3000 |
| **LogVault** | Syslog analyzer | 3004 / 3005 |
| **SpanVault** | Network monitoring | TBD |
| **DDIVault** | DNS, DHCP, IPAM monitoring | 3006 / 3007 |

All products:
- Run on Windows Server `192.168.6.111`
- Share the same PostgreSQL 16 instance (separate databases)
- Share the same user authentication via NetVault's `users` table
- Use SSO — log in once at NetVault hub, access all apps without re-authenticating

---

## Tech Stack

### Backend (plain JavaScript — NOT TypeScript)
- **Runtime:** Node.js v20.19.0
- **API:** Express.js — `api/server.js` on port 3005 (internal only)
- **Collector:** `collector/collector.js` — listens on UDP/TCP 514 and 1514
- **Database:** PostgreSQL 16 — database `logvault`, user `logvault_user`
- **Auth DB:** PostgreSQL 16 — database `netvault`, user `netvault` (read-only, for SSO)
- **Service manager:** NSSM

### Frontend (TypeScript)
- **Framework:** Next.js 16
- **Styling:** Inline styles ONLY — no Tailwind, no CSS modules
- **Charts:** Recharts
- **Auth:** NextAuth.js with JWT strategy

### CRITICAL: Never use TypeScript syntax in `.js` files
```javascript
// WRONG — will crash Node.js
function foo(bar: string): void { }
const x = value as string;

// CORRECT
function foo(bar) { }
const x = value;
```

---

## Project Structure

```
C:\Apps\logvault\                    ← repo root = app root
  api\
    server.js                        ← Express REST API (port 3005)
    rbac.js                          ← RBAC middleware + getSiteFilter/getStatsSiteFilter/getAlertSiteFilter
    licenseCheck.js                  ← License enforcement (getLicense/getLicenseState)
    auditLog.js                      ← Audit trail writer (audit_log table)
    netvaultSync.js                  ← NetVault asset sync for API
  collector\
    collector.js                     ← Syslog collector (514/1514)
    correlationEngine.js             ← Alert correlation rules
    netvaultSync.js                  ← NetVault asset sync for collector
    dnsLookup.js                     ← Reverse DNS lookup utility
    emailer.js                       ← SMTP email alerting
    geoEnrich.js                     ← GeoIP + AbuseIPDB threat enrichment
    mitreMapper.js                   ← MITRE ATT&CK technique tagging
    taxonomy.js                      ← Universal event category assignment
    riskScorer.js                    ← 0-100 risk score per log entry
    analytics\                       ← Phase 2 intelligence: UEBA / anomaly detection
      baselineBuilder.js             ← Per-entity behavioral baselines
      anomalyDetector.js             ← Deviation-from-baseline anomaly scoring
      uebaRollup.js                  ← Entity risk rollup
      relayHosts.js                  ← Shared relay/log-source exclusion list (UEBA_RELAY_HOSTS)
  parsers\
    fortinet.js
    cisco.js
    paloalto.js
    aruba.js
    sangfor.js
    forcepoint.js
    checkpoint.js
    juniper.js
    windows.js
    sonicwall.js
    generic.js
  frontend\
    src\
      app\
        page.tsx                     ← Main app (sidebar + tab routing)
        layout.tsx                   ← Root layout with AuthProvider
        globals.css                  ← CSS variables + design tokens
        sso\page.tsx                 ← SSO landing page
        api\auth\[...nextauth]\route.ts
      components\                   ← ~30 components: LogExplorer/LogDetailPanel, DashboardWidgets,
                                       AlertEvents/AlertDetailPanel/AlertBanner, IntelligenceConsole
                                       (UEBA), SecurityAnalysis, ThreatIntel, LicenseGuard,
                                       UpdateNotifier, KnownHosts, Settings, Header, plus shared
                                       mitre.tsx / ui.tsx / severity.tsx modules
      lib\
        publicUrl.ts                 ← resolveOrigin()/getHubUrl() — request-derived hub URL
      auth.ts                       ← NextAuth config (SSO + credentials, carries the `apps` claim)
      proxy.ts                      ← Edge middleware: /api/* proxy + RBAC headers + page/API auth guard
      types\next-auth.d.ts
    package.json                    ← Frontend dependencies
    next.config.js                  ← env passthrough only — /api/* proxying lives in proxy.ts, not here
    .next\                          ← Built output (next start)
  scripts\
    schema.sql                      ← SINGLE SOURCE OF TRUTH for DB schema
    cleanup.js                      ← Data retention cleanup
    verify-integrity.js             ← Tamper-chain verifier
  installer\
    Update-LogVault.ps1             ← Deployment update script
  logs\                             ← NSSM service logs
  package.json                      ← Root dependencies (collector + API)
  .env.local                        ← Server-specific config (NOT committed)
```

---

## Development Workflow — ALWAYS FOLLOW THIS

```
1. Make ALL changes here in Claude Code
2. Run: cd frontend && npm run build  (verify no build errors)
3. If build passes: cd .. && git add -A
4. git commit -m "descriptive message"
5. git push origin main
6. On Windows Server: & "C:\Apps\logvault\installer\Update-LogVault.ps1" -InstallDir "C:\Apps\logvault"
```

**NEVER edit files directly on the Windows Server.**  
**NEVER commit broken code.**  
**ALWAYS fix build errors before committing.**

---

## Update Script

```powershell
& "C:\Apps\logvault\installer\Update-LogVault.ps1" -InstallDir "C:\Apps\logvault"
```

The script:
1. Stops services with `sc.exe` (never `Stop-Service` — causes terminal hang)
2. Backs up `.env.local` to memory
3. `git reset --hard origin/main` + `git clean`
4. Restores `.env.local`
5. `npm install` (root + frontend)
6. `npm run build` — if fails, services NOT restarted (old version keeps running)
7. Starts services in order: Collector → API → App
8. Verifies status + health check

### Backend-only changes (skip frontend rebuild)
```powershell
nssm stop LogVault-API
cd C:\Apps\logvault
git pull origin main
nssm start LogVault-API
Start-Sleep -Seconds 3
Invoke-WebRequest -Uri "http://localhost:3005/api/health" -UseBasicParsing | Select-Object -ExpandProperty Content
```

---

## Database

> **Secrets are never committed.** All passwords and `NEXTAUTH_SECRET` are supplied
> at runtime via NSSM `AppEnvironmentExtra` (prod) or `.env.local` (dev). The values
> below are shown as `<set-in-NSSM-env>` placeholders — get the real values from the
> server's NSSM config / `.env.local`, never hardcode them.

### Connection details
```
Host:     localhost
Port:     5432
Database: logvault
User:     logvault_user
Password: <set-in-NSSM-env>
```

### NetVault DB (read-only, for SSO + asset sync)
```
Database: netvault
User:     netvault
Password: <set-in-NSSM-env>
```

### Read-only access for Claude Code / development
A dedicated read-only role is available for ad-hoc querying during development
(SELECT only — never use it in app code, which uses `logvault_user`). The password
is **never committed**: it lives in `.db-readonly.env` (gitignored) on Amrin's local
machine. `.db-readonly.env.example` (committed) shows the variable layout; copy it to
`.db-readonly.env` and fill in the real password.
```
Host:      192.168.6.111
Port:      5432
User:      claude_readonly
Password:  see .db-readonly.env (gitignored)
Databases: logvault, netvault, ddivault, spanvault
```
Read the password at runtime from `.db-readonly.env` (do not hardcode or echo it),
then connect, e.g.:
```bash
set -a; . ./.db-readonly.env; set +a
PGPASSWORD="$DB_READONLY_PASS" psql -h "$DB_READONLY_HOST" -p "$DB_READONLY_PORT" \
  -U "$DB_READONLY_USER" -d logvault -c "SELECT 1;"
```
> Requires the server's `pg_hba.conf` to permit `claude_readonly` from the dev host.

### Run psql commands
```powershell
$env:PGPASSWORD = "<set-in-NSSM-env>"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -d logvault -c "YOUR SQL HERE"
```

### Schema rules — CRITICAL
- `scripts/schema.sql` is the **single source of truth**
- Every `ALTER TABLE`, `CREATE TABLE`, `CREATE INDEX` run manually on the server **MUST** also be added to `schema.sql`
- Use `IF NOT EXISTS` everywhere — schema must be idempotent (safe to run multiple times)
- New `app_settings` keys must use: `INSERT INTO app_settings (key, value) VALUES ('key', 'default') ON CONFLICT (key) DO NOTHING;`
- After any manual schema change on server, immediately update `schema.sql` in Claude Code and commit

### Tables
```sql
syslog_entries    -- All log entries (main table) — PARTITIONED BY RANGE (received_at), daily
                  --   composite PK (id, received_at); category TEXT + risk_score SMALLINT;
                  --   prev_hash/entry_hash BYTEA (tamper-evident chain). APPEND-ONLY for app role.
alert_rules       -- Alert rule definitions
alert_events      -- Fired alert instances
known_hosts       -- IP → hostname/vendor/site mapping
app_settings      -- Key/value app configuration
audit_log         -- Immutable trail of privileged actions (append-only). Written by api/auditLog.js
```

`syslog_entries.category` holds the universal taxonomy value (authentication, vpn,
firewall, interface, routing, configuration, security, wireless, system, dns, web,
email, dlp, network). `syslog_entries.risk_score` is a 0-100 score from
`collector/riskScorer.js`. Both are written by the collector and indexed.

### Partitioning & retention (Phase 3)
- `syslog_entries` is `PARTITION BY RANGE (received_at)` with **daily** partitions
  (`syslog_entries_pYYYYMMDD`) plus a `syslog_entries_default` safety partition so an
  INSERT never fails if a daily partition is missing. PK is composite `(id, received_at)`
  (partition key must be in the PK); `id` stays globally unique via `syslog_entries_id_seq`.
  An `idx_syslog_id` keeps `WHERE id = $1` fast across partitions.
- Two `SECURITY DEFINER` functions (owned by `postgres`, EXECUTE granted to `logvault_user`)
  manage partitions: `ensure_syslog_partitions(days_ahead)` pre-creates future days,
  `drop_old_syslog_partitions(retention_days)` drops aged daily partitions (never the default).
- **Retention is now partition DROP, not bulk DELETE.** The logic lives in
  `scripts/cleanup.js`, which exports `runCleanup(pool)` (ensure 7 days of partitions ahead,
  `drop_old_syslog_partitions(RETENTION_DAYS)`, auto-ack old alerts, delete old acked alerts).
- **Cleanup runs IN-PROCESS in the collector** — no external Windows scheduled task needed.
  `collector/collector.js` requires `runCleanup` and runs it ~60s after startup, then every
  24h, reusing the collector's pool (never exits on error). `scripts/cleanup.js` is still
  runnable standalone (`node scripts/cleanup.js`) via its `require.main` CLI block for a
  manual/ad-hoc run.
- **Fresh installs** get the partitioned table straight from `schema.sql`. **Existing live
  DBs** must be converted with `scripts/migration-phase3-partitioning.sql` — MANUAL run as
  `postgres`, in a maintenance window, with a `pg_dump` backup first (ATTACHes the existing
  table as one legacy partition, no row copy).
- **The update script applies `scripts/schema.sql` as `postgres` on every run** (idempotent;
  mirrors the spanvault/ddivault pattern via `Resolve-Psql` + `--quiet`, psql-optional). It
  connects as the `postgres` superuser using `POSTGRES_PASSWORD` from `.env.local` — NOT as
  `logvault_user`, because `schema.sql` defines `SECURITY DEFINER` partition functions that
  must be owned by `postgres` and self-`REVOKE`s UPDATE/DELETE from `logvault_user`. If
  `POSTGRES_PASSWORD` or psql is missing, the step warns and skips (never fails the update).
  **Migration scripts (e.g. `migration-phase3-partitioning.sql`) must still be run MANUALLY
  with a `pg_dump` backup first** — the update script applies `schema.sql` only.

### Tamper prevention & log integrity (Phase 3)
- `syslog_entries` and `audit_log` are **append-only for `logvault_user`**:
  `REVOKE UPDATE, DELETE` (applied after the GRANT ALL block). The collector only INSERTs,
  the API only SELECTs. NEVER add `UPDATE`/`DELETE FROM syslog_entries` in app code — it will
  fail. (One-off `scripts/backfill-categories.js` must run as `postgres` if ever re-run.)
- The collector writes a **tamper-evident HMAC-SHA256 hash chain** (`prev_hash`, `entry_hash`)
  per row, keyed by `LOG_INTEGRITY_KEY`. If the key is unset, the chain is disabled (columns
  NULL) and a single startup warning is logged — non-breaking. Canonical input per row:
  `received_at(ISO)|source_ip|severity|vendor|message|raw_message`, prefixed with the prior
  row's hash. `scripts/verify-integrity.js` walks the chain and reports the first break.
  Legacy (pre-migration) rows keep NULL hashes — the chain starts fresh post-migration.

### Durable ingest spool (Phase 3)
- The collector mirrors every entry to a disk write-ahead spool (`SPOOL_DIR` or
  `logs/spool/`, rotating NDJSON segments, fsync'd) before/alongside the in-memory buffer, and
  **replays un-flushed segments on boot** before opening sockets — so a crash/restart/DB-outage
  no longer loses logs. Segments are unlinked once all their entries are confirmed flushed.

### Permissions — fresh install requirement
```sql
GRANT ALL ON ALL TABLES IN SCHEMA public TO logvault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO logvault_user;
-- then (append-only tamper prevention — order matters, runs AFTER the GRANTs):
REVOKE UPDATE, DELETE ON syslog_entries FROM logvault_user;
REVOKE UPDATE, DELETE ON audit_log      FROM logvault_user;
```

---

## NSSM Services

| Service | Executable | Port | Notes |
|---|---|---|---|
| `LogVault-Collector` | node collector/collector.js | 514, 1514 | No HTTP port |
| `LogVault-API` | node api/server.js | 3005 | Internal only |
| `LogVault-App` | next start -p 3004 | 3004 | Public facing |

### Service startup order
`postgresql` → `LogVault-Collector` → `LogVault-API` → `LogVault-App`

### Environment variables (set via NSSM AppEnvironmentExtra)

**LogVault-Collector:**
```
NODE_ENV=production
DB_HOST=localhost
DB_PORT=5432
LV_DB_NAME=logvault
LV_DB_USER=logvault_user
LV_DB_PASS=<set-in-NSSM-env>
NETVAULT_DB_HOST=localhost
NETVAULT_DB_PORT=5432
NETVAULT_DB_NAME=netvault
NETVAULT_DB_USER=netvault
NETVAULT_DB_PASS=<set-in-NSSM-env>
LOG_INTEGRITY_KEY=<set-in-NSSM-env>   # HMAC key for the tamper-evident hash chain; unset = chain disabled
SPOOL_DIR=                            # optional; defaults to <repo>/logs/spool for the durable ingest spool
RETENTION_DAYS=30                     # optional; days of syslog_entries partitions to retain (scripts/cleanup.js, runs in-process)
UEBA_RELAY_HOSTS=FGT200E_TUS          # optional; comma-separated relay/log-source hostnames excluded from UEBA 'device' entity scoring
```

> `LOG_INTEGRITY_KEY` must be the SAME value when running `scripts/verify-integrity.js`,
> otherwise verification will report false breaks. Treat it like any other secret (NSSM env,
> never committed). Rotating it starts a new chain segment — old rows verify only with the
> old key.

**LogVault-API:**
```
NODE_ENV=production
DB_HOST=localhost
DB_PORT=5432
LV_DB_NAME=logvault
LV_DB_USER=logvault_user
LV_DB_PASS=<set-in-NSSM-env>
LV_APP_URL=http://192.168.6.111:3004
NOCVAULT_HUB_URL=http://192.168.6.111:3000
NETVAULT_DB_HOST=localhost
NETVAULT_DB_PORT=5432
NETVAULT_DB_NAME=netvault
NETVAULT_DB_USER=netvault
NETVAULT_DB_PASS=<set-in-NSSM-env>
```

> `NOCVAULT_HUB_URL` lets the API reach the NocVault hub for license enforcement
> (`api/licenseCheck.js` → `GET {hub}/api/license`). If unset, it falls back to
> `http://localhost:3000`, which only works when the hub is on the same server.

**LogVault-App:**
```
NODE_ENV=production
NEXTAUTH_URL=http://192.168.6.111:3004
NEXTAUTH_SECRET=<set-in-NSSM-env>
NOCVAULT_HUB_URL=http://192.168.6.111:3000
NEXT_PUBLIC_NOCVAULT_HUB_URL=http://192.168.6.111:3000
NETVAULT_DB_HOST=localhost
NETVAULT_DB_PORT=5432
NETVAULT_DB_NAME=netvault
NETVAULT_DB_USER=netvault
NETVAULT_DB_PASS=<set-in-NSSM-env>
LV_APP_PORT=3004
```

---

## Authentication — SSO

LogVault has NO local login. All auth goes through NetVault hub.

**Flow:**
1. User visits `http://192.168.6.111:3004`
2. `proxy.ts` detects no session → redirects to `http://192.168.6.111:3000/login`
3. User logs in at NetVault
4. NetVault calls `/api/sso/logvault` → generates JWT → redirects to `http://192.168.6.111:3004/sso?token=xxx`
5. LogVault SSO page validates JWT → creates NextAuth session
6. User is now logged in

**Key files:**
- `frontend/src/auth.ts` — NextAuth config, reads from `netvault.users` table
- `frontend/src/proxy.ts` — protects all pages (replaces middleware.ts)
- `frontend/src/app/sso/page.tsx` — SSO landing (must be wrapped in Suspense)

**Shared secret:** `<set-in-NSSM-env>` (the `NEXTAUTH_SECRET` value — never committed; supplied via NSSM env / `.env.local`)

**Cookie name:** `nexvault.session-token` — DO NOT CHANGE (breaks existing sessions)

**Hub URL:** these env vars are now the LAST-RESORT fallback only, not the
primary source (added 2026-07). Server-side call sites (`proxy.ts` and any new
route needing the hub's origin) should call `resolveOrigin(req, 3000,
<the env-var fallback chain>)` from `frontend/src/lib/publicUrl.ts` — it
derives the hub's origin from the CURRENT request's `x-forwarded-host`/`host` +
`x-forwarded-proto` (validated against a hostname-shape regex) instead of a
static env var, so hub links keep working when the suite is reached via a
hostname different from the install-time server IP (e.g. a customer's own
local-DNS name). Client-side call sites use a `getHubUrl()` helper
(`window.location`-derived) in the same file instead of reading
`NEXT_PUBLIC_NOCVAULT_HUB_URL` directly. Never hardcode `192.168.6.111:3000`.

### Env var standard (NocVault suite — updated)

The hub URL env var was standardized across all NocVault suite products to drop the
product-specific `NETVAULT_` prefix in favor of the suite-wide `NOCVAULT_` prefix:

| Old name | New name | Used in |
|---|---|---|
| `NETVAULT_HUB_URL` | `NOCVAULT_HUB_URL` | server-side (`auth.ts`, `proxy.ts`) |
| `NEXT_PUBLIC_NETVAULT_HUB_URL` | `NEXT_PUBLIC_NOCVAULT_HUB_URL` | client-side (`Header.tsx`, `IdleTimeout.tsx`, `sso/page.tsx`) |

> **Deployment note:** the NSSM `AppEnvironmentExtra` for `LogVault-App` MUST be updated
> to the new names (see the install/update steps). Until it is, `HUB_URL` falls back to
> `http://localhost:3000` and SSO will break. The NetVault DB vars (`NETVAULT_DB_*`) are
> unchanged — only the hub URL var was renamed.

Sign-out is done via a **manual CSRF flow** (`/api/auth/csrf` → POST `/api/auth/signout`),
not the next-auth `signOut` helper, in both `Header.tsx` and `IdleTimeout.tsx` — this keeps
the shared SSO cookie flow intact.

---

## Role-Based Access Control (RBAC)

Users, roles, and site assignments are managed **in NetVault**. LogVault only
**enforces** them — there are no RBAC tables in the LogVault DB.

### Roles (`netvault.users.role`)

| Role | Sees |
|---|---|
| `super_admin` | Everything. Only role that can modify Settings / trigger NetVault sync |
| `admin` | Everything (all sites, all logs) — but not Settings writes |
| `user` | Only logs from devices in their assigned sites (`netvault.user_sites`) |

### How identity reaches the API — edge middleware (NOT cookie decode, NOT a route.ts proxy)

`next-auth` v4 with `session.strategy: 'jwt'` stores the session cookie as an
**encrypted JWE** (A256GCM, key derived from `NEXTAUTH_SECRET`). A plain
`jsonwebtoken.decode()` **cannot** read it — it returns `null`. So the Express
API does **not** parse the cookie, and `cookie-parser` / `jsonwebtoken` are
**not** added to the backend.

Identity flows through Next.js **edge middleware** — `frontend/src/proxy.ts`
(`export default async function proxy(req)`). This is the SECOND refactor of
this mechanism: an original `next.config.js` rewrite couldn't attach headers,
so it was replaced by a per-request `getServerSession()` proxy route at
`frontend/src/app/api/[...path]/route.ts`; that route.ts file no longer
exists — it was replaced by this edge middleware (one cheap `getToken()` JWE
decode + `NextResponse.rewrite()`, instead of a full session decrypt inside an
extra Node hop on every call). See `proxy.ts`'s own header comment for the
full history.

```
Browser → /api/*  →  proxy.ts (edge middleware, matcher excludes /api/auth/*)
                       getToken({ req, cookieName: 'nexvault.session-token', ... })
                       strips any client-supplied X-User-* headers, then sets
                       X-User-Id + X-User-Role from the VERIFIED token
                       NextResponse.rewrite() → Express API (localhost:3005)
                     → rbacMiddleware reads those headers → req.rbac
```

- No session + path not on the small `PUBLIC_API_PATHS` allow-list
  (`/api/license-status`, `/api/health`, `/api/stats`,
  `/api/system/update-available`) → `proxy.ts` returns a `401` itself, before
  Express is ever hit. An earlier version proxied unauthenticated calls
  through anyway (relying on Express to "fail closed"), but that only holds
  for routes that actually check `req.rbac` — a route with no guard was wide
  open. Rejecting at the edge removed that whole bug class.
- `/api/auth/*` is excluded by `proxy.ts`'s `config.matcher` and served by the
  more-specific next-auth route.
- The API is internal-only (port 3005, never firewalled open), so `proxy.ts`
  is the sole trusted caller of `X-User-Id`/`X-User-Role`.

> **There is no `frontend/src/app/api/[...path]/route.ts` file and no
> `next.config.js` rewrite for `/api/*`.** `frontend/src/proxy.ts` is the
> *only* path browser API calls take to Express — it verifies the token at
> the edge, forwards `X-User-Id` + `X-User-Role` to `http://localhost:3005`,
> and relays the upstream status (so e.g. a `402` license response passes
> through). New API endpoints work automatically; do **not** recreate the old
> route.ts proxy or re-add an `/api/*` rewrite.

### `api/rbac.js`

- `rbacMiddleware` — sets `req.rbac = { userId, role, isSuperAdmin, isAdmin, allowedSiteIds }`.
  `allowedSiteIds` is `null` for admins (no filter), `[]` for a user with no
  sites (sees nothing), or an array of site IDs. User→site lookups are cached 5 min.
- `requireAdmin` — 403s the `user` role (allows `admin`/`super_admin`). Applied to
  `/api/alerts/rules` (GET/POST/PATCH), `/api/alert-rules`, `PUT /api/hosts`, `/api/sites`.
- `requireSuperAdmin` — 403s non-super-admins. Applied to `POST /api/settings`,
  `POST /api/settings/test-email`, `POST /api/hosts/sync-netvault`.
- Fails **open** on lookup errors (logs, then treats as admin/no-filter) so a
  NetVault DB blip never locks everyone out.

### `getSiteFilter(rbac, startParamIndex, tableAlias)` helper

Returns `{ clause, params, nextParamIndex }` to append to a query:

```javascript
// Simple WHERE-append (alias 'se', or pass the table name when there is no alias)
const sf = getSiteFilter(req.rbac, 2, 'se');
const { rows } = await pool.query(`
  SELECT ... FROM syslog_entries se
  WHERE se.received_at > NOW() - make_interval(hours => $1)
  ${sf.clause}
`, [hours, ...sf.params]);

// conditions-array style (e.g. /api/logs) — strip the leading "AND "
const sf = getSiteFilter(req.rbac, p, 'se');
if (sf.clause) { conditions.push(sf.clause.replace(/^AND\s+/i, '')); params.push(...sf.params); p = sf.nextParamIndex; }
```

- `clause` is `''` for admins (no filter), `AND 1=0` for a user with no sites,
  or an `IN (SELECT ip_address FROM known_hosts WHERE site_id = ANY($n::int[]))`
  subquery. **Never breaks an existing query** — if `req.rbac` is undefined it
  returns an empty clause.
- Site filtering links logs → sites via
  `syslog_entries.source_ip → known_hosts.ip_address → known_hosts.site_id`.
- Applied to detail-level queries: `/api/logs`, `/api/logs/export`, and the
  event-side of alert-detail / security-drilldown endpoints.

### `getStatsSiteFilter(rbac, startParamIndex, tableAlias)` — permissive variant for dashboard aggregates

Same shape/params as `getSiteFilter`, but a row is visible when its `source_ip`
belongs to one of the user's sites **OR** `source_ip` is NOT assigned to any
site in `known_hosts` (unregistered/unassigned devices stay visible to
everyone). Needed because these widgets are firewall-centric — the strict
`getSiteFilter` matched ZERO rows for every non-admin when the relaying
firewall device itself has no site assigned, even though `super_admin` (no
filter) saw data. Applied to `/api/stats/summary`, `/api/stats/timeline`,
`/api/stats/top-talkers`, `/api/stats/top-blocked`, `/api/stats/top-failures`,
`/api/stats/top-security-events`, and other dashboard-aggregate endpoints.

### `getAlertSiteFilter(rbac, startParamIndex, tableAlias = 'ae')` — alert-branch site scoping

`alert_events` are scoped by the **relay hostname, not `source_ip`**: the
clause filters on `ae.source_host → known_hosts.hostname → known_hosts.site_id`
(same clause shapes as `getSiteFilter`: `''` / `AND 1=0` / an `IN (...)`
subquery). `alert_events.source_ip` is the internal actor IP and is almost
never registered in `known_hosts` with a site, so filtering on it would
collapse alert visibility to zero for every site-scoped user. Scoping by the
firewall/relay hostname instead keeps alert visibility consistent with the
event branch (same physical device, same site mapping) without leaking
another site's data. Applied to `/api/alerts/events` and other alert-derived
endpoints (e.g. MITRE coverage).

### When you add a site-scope check, audit every sibling route too

Across the NocVault suite recently, an IDOR/site-scoping bug was fixed on one
route while the identical missing-check bug sat untouched on a sibling route
with the exact same shape (same resource type, same site-scoped entity) —
caught only later, by a separate audit. This pattern has recurred at least 3
times suite-wide. **The rule:** the moment you add or fix a site-scope check
(`getSiteFilter`, `getStatsSiteFilter`, or `getAlertSiteFilter` — see below)
on one endpoint in `api/server.js`, grep for every other route touching the
same table/entity and confirm each one calls the equivalent helper. A fix
that only patches the reported route, and not its siblings, is not done.

### Per-user app access (separate from role/site RBAC)

Independent of the role/site RBAC above, NetVault SSO can also restrict
**which apps** a user is allowed to open at all. The allowed-apps list rides
in the SSO JWT as `apps: string[]` (absent/empty = default-all — **fail
open**, so tokens minted before this feature never lock anyone out). `auth.ts`
carries the claim into LogVault's own NextAuth session (`jwt`/`session`
callbacks persist `token.apps`/`session.user.apps`); the direct
email/password login path resolves the same claim itself via
`resolveDirectLoginApps()` (queries `netvault.user_apps`), **failing closed**
on a DB error to a non-empty deny-all sentinel (`['__db_error_deny_all__']`)
— note it can't be an empty array, because `appAllowed([])` means allow-all,
so a closed failure must be a non-empty array holding no real app slug — so
that path can't silently grant unrestricted access. `proxy.ts`'s `appAllowed(apps, slug)` enforces it:
- **Page routes:** a session whose `apps` claim omits `logvault` is redirected
  to `${hub}/launcher?denied=logvault`.
- **API routes:** the same check runs in the `/api/*` proxy branch — a denied
  session gets a JSON `403 { error: 'forbidden', reason: 'app_access_denied' }`
  instead of a redirect (a `fetch()` caller can't follow a redirect to a login
  page). Added after an audit found page navigation was gated but a direct
  API call with the same cookie sailed through.
- `netvault` (the hub) is always allowed regardless of the claim.

**General rule for any future access-control gate:** verify it against BOTH
the page-rendering path and any API/proxy path reachable with the same
session, in the same change. A UI redirect is not a security boundary by
itself — "page guarded, API wide open" is the default failure mode when a
gate is added to only one of the two paths, and it's exactly the bug fixed
above.

### Frontend

- `page.tsx` reads `session.user.role`: hides the **Settings** tab for
  non-admins and shows a navy "access is restricted to your assigned sites"
  banner for `user`.
- `Header.tsx` shows a coloured role badge (Super Admin = red, Admin = blue,
  User = grey).

> RBAC enforcement is server-side; the frontend hiding is cosmetic only.

---

## NocVault Design System

```css
/* globals.css */
:root {
  --primary:        #C8102E;   /* TU Red — buttons, accents, active nav */
  --primary-dark:   #a00d24;
  --navy:           #1a2744;   /* Header + sidebar background */
  --bg-primary:     #f4f6f9;   /* Page background (suite slate) */
  --bg-card:        #ffffff;   /* Card background */
  --border:         #e2e8f0;
  --border-light:   #f1f5f9;
  --text-primary:   #0f172a;
  --text-secondary: #334155;
  --text-muted:     #64748b;
  --shadow-sm:      0 1px 3px rgba(0,0,0,0.05), 0 1px 2px rgba(0,0,0,0.04);
}
[data-theme="dark"] {
  --bg-primary:     #0d1220;
  --bg-card:        #1a2235;
  --border:         #2d3a52;
  --border-light:   #243050;
  --text-primary:   #f1f5f9;
  --text-secondary: #cbd5e1;
  --text-muted:     #94a3b8;
  --bg-hover:       #253352;
}
```

**Sidebar nav icons** use the suite-standard **colored icon chips**: each nav item's icon
sits in a 28×28 rounded chip (`borderRadius: 8`), tinted per-route via the module-level
`NAV_COLORS` map. Only the **active** item is colored (chip bg + icon `currentColor`);
inactive items use the neutral faint-white chip (`rgba(255,255,255,0.07)` bg /
`rgba(255,255,255,0.45)` icon). Nav icon SVGs are 16×16 and inherit color from the chip
(no per-icon active coloring). Nav labels are **14px** (`var(--text-md)`), active `#ffffff` /
inactive `rgba(255,255,255,0.55)`. Shared across the NocVault suite (netvault/ddivault/spanvault).

**Header icon-buttons** (notifications bell + dark-mode toggle) are **38×38 / `borderRadius: 8`**
with 18×18 icons — suite-standard sizing. The avatar is a 34px circle (`var(--primary)`).

**Sidebar:** Navy `#1a2744`, active item = red left border `#C8102E` + red-tinted bg.
Collapsible 240↔64px (suite-standard): a chevron toggle at the bottom flips the width
(0.18s ease) and persists to `localStorage['logvault-sidebar-collapsed']`; collapsed hides
labels/section-label/ingestion-card/version and centers icons (`title` tooltips show
labels). The sidebar is **pinned to the viewport** (`position: sticky; top: 72px;
height: calc(100vh - 72px); align-self: flex-start`) so the footer/version stays at the
bottom of the screen, not the bottom of the scrolled page. Lives inline in
`frontend/src/app/page.tsx` (logvault has no separate Sidebar component). Matches
netvault/ddivault/spanvault — keep the collapse behaviour in sync across the suite.

**Header** (`components/Header.tsx`) is **72px** tall and **sticky** (`position: sticky;
top: 0; zIndex: 200`) so the top bar stays visible while scrolling, like the rest of the
suite. The `72px` value is the single source for both the sticky-header height and the
sidebar's `top`/`height` offsets — if the header height changes, update both in lockstep.  
**Cards:** white, `1px solid var(--border)`, `border-radius: 10px`, `box-shadow: var(--shadow-sm)`  
**Tables:** `var(--bg-primary)` header, uppercase labels, `var(--text-muted)` color  
**Buttons:** Red `#C8102E`, hover `#a00d24`  
**Font:** `system-ui, -apple-system, sans-serif`

## Typography & design tokens (suite standard)

Body font is **Inter** (loaded via CSS `@import`, no `next/font`); monospace is the
single shared token **`var(--font-mono)`** (`'JetBrains Mono', 'Fira Code', 'Consolas',
'Courier New', monospace`) — used for all log lines, IPs, ports, versions, code.

All font sizes use the **7-step type scale** defined in `globals.css` `:root` (sizes do
not change per theme, so they live in `:root` only):

| Token | px | Use |
|---|---|---|
| `--text-xs` | 11px | table headers, badges, micro-labels |
| `--text-sm` | 12px | secondary labels, captions |
| `--text-base` | 13px | buttons, inputs, table body |
| `--text-md` | 14px | body text, card titles (base body size on `html`/`body`) |
| `--text-lg` | 16px | section / panel headings |
| `--text-xl` | 20px | page titles |
| `--text-2xl` | 28px | stat numbers / display |

**Rules:**
- **NEVER hardcode a font size or a color that duplicates a token.** Use the scale token
  (`fontSize: 'var(--text-base)'`, not `fontSize: 13`) and the existing color tokens
  (`var(--text-muted)`, `var(--bg-card)`, `var(--primary)`, etc.) so dark mode works.
- Display / hero numbers **>= 34px** (e.g. update-overlay spinner, lock-screen glyph) may
  stay literal — they are intentional one-off display sizes.
- **Stat-tile numbers / panel-row labels must use `var(--text-*)` tokens, never dark/grey
  literals** (e.g. `#1a202c`, `#374151`, `var(--text-secondary)` on a fixed light tint),
  so they survive dark mode. Likewise, a tile/row **background** that sits behind tokenized
  text must adapt: use `var(--bg-primary)`/`var(--bg-card)` for neutral surfaces, or a
  **semi-transparent** `rgba(r,g,b,0.12)` status tint (not a hardcoded light hex like
  `#fef2f2`/`#f0fdf4`) so the surface layers correctly over the dark card and the text stays
  legible in both themes.
- **Exception:** the severity (`SEV_COLORS`) and vendor (`VENDOR_COLORS`) palettes in
  `LogExplorer.tsx` / `LogDetailPanel.tsx` (and chart series color arrays / status-badge
  color pairs) are intentional semantic palettes with no matching token — leave them.
- This is the **NocVault SUITE-WIDE standard**: the same scale and `--font-mono` token are
  used in **spanvault, ddivault, and netvault**. Keep them in sync.

### Adaptive surface & status-tint tokens (suite standard)

`globals.css` defines a shared set of **adaptive tint tokens** in both `:root` and
`[data-theme="dark"]`:

| Token | Light | Dark | Use |
|---|---|---|---|
| `--surface-subtle` | `#f8fafc` | `rgba(255,255,255,0.04)` | neutral near-white tiles/rows/headers/dropdowns |
| `--tint-info` / `--tint-info-fg` | `#eff6ff` / `#1d4ed8` | `rgba(59,130,246,0.13)` / `#93c5fd` | blue info chips/banners |
| `--tint-success` / `--tint-success-fg` | `#f0fdf4` / `#15803d` | `rgba(34,197,94,0.13)` / `#86efac` | green success chips/tiles |
| `--tint-warn` / `--tint-warn-fg` | `#fffbeb` / `#b45309` | `rgba(217,119,6,0.15)` / `#fcd34d` | amber/orange warn chips/banners |
| `--tint-danger` / `--tint-danger-fg` | `#fef2f2` / `#b91c1c` | `rgba(220,38,38,0.13)` / `#fca5a5` | red danger chips/banners/rows |
| `--tint-purple` / `--tint-purple-fg` | `#f5f3ff` / `#6d28d9` | `rgba(139,92,246,0.15)` / `#c4b5fd` | purple chips/banners/rows (brute-force, routing subcats) |

**Rule:** any tinted or neutral **surface that sits behind text** (tiles, table
rows/headers, badge/chip backgrounds, banners, dropdowns) MUST use these tokens — never a
hardcoded light hex like `#fef2f2`/`#f0fdf4`/`#f8f9fb`. The light hex does not adapt, so in
dark mode near-white text becomes unreadable and light chips float on dark cards. For a
**self-contained badge pair** (a hardcoded bg AND a matching dark text defined together, e.g.
`{ bg:'#fef2f2', color:'#dc2626' }`) swap **both** — bg→`--tint-*`, text→`--tint-*-fg`. For a
surface holding already-tokenized text, just swap the bg. Chart series/dot/line colors and the
severity/vendor palettes are left as-is — those are data signals (the raw color IS the signal).
`--primary-light` also has a dark override (`rgba(200,16,46,0.18)`).
This is the **suite-wide standard** — the same tokens exist in **ddivault** and **spanvault**.

### Dropdown / select readability in dark mode (suite standard)

- **Native form controls** (`<select>` option popups, native scrollbars, date/number
  spinners) are rendered by the browser/OS and can't be styled with normal CSS background
  rules. They are themed via the CSS **`color-scheme`** property: `color-scheme: light` in
  `:root`, `color-scheme: dark` in `[data-theme="dark"]`. A base `select { … }` /
  `option { … }` rule using `var(--bg-card)` + `var(--text-primary)` is added as
  belt-and-suspenders. Without `color-scheme`, native `<select>` option lists render with a
  light background and near-invisible text in dark mode.
- **Custom dropdown / menu / combobox / popover panels** must use `var(--bg-card)` +
  `border: 1px solid var(--border)` for the panel surface, with `var(--surface-subtle)` (or
  the appropriate `--tint-*`) for hover/active rows and `var(--text-primary)`/`--text-secondary`
  for option text — **never** a hardcoded light hex (`#fff`, `#f8fafc`, `#eff6ff`, etc.).
- This is the **suite-wide standard** — **ddivault** and **spanvault** get the same treatment.

**Neutral palette (suite slate ramp):** LogVault's neutral tokens — `--text-primary/-secondary/-muted`,
`--border`, `--border-light`, `--bg-primary`, `--bg-card` (light + dark) — are aligned to the
suite **slate** ramp, matching spanvault/ddivault/netvault (page bg `#f4f6f9` light / `#0d1220`
dark). Hardcoded gray-ramp hexes in components were swept onto these tokens so dark mode and
app-switching stay consistent. The `--primary` brand red, `--navy*`, status colors
(`--green/--yellow/--red/...`), and the `SEV_COLORS`/`VENDOR_COLORS` palettes are intentionally
NOT part of the neutral ramp — leave them.

---

## API Rules — CRITICAL

```javascript
// NEVER interpolate user input into SQL
// WRONG:
pool.query(`WHERE time > NOW() - INTERVAL '${hours} hours'`)

// CORRECT:
pool.query(`WHERE time > NOW() - make_interval(hours => $1)`, [hours])

// PostgreSQL counts $1 as ONE parameter even if it appears twice
// Use JOIN instead of nested subquery with same parameter

// Input validation
function safeHours(val, max = 720) {
  const n = Math.min(parseInt(val || '24') || 24, max);
  return isNaN(n) || n <= 0 ? 24 : n;
}

// Generic errors to client — never leak stack traces
app.use((err, req, res, _next) => {
  console.error('[API Error]', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// CORS restricted to frontend only
app.use(cors({ origin: 'http://localhost:3004' }));

// Crash resilience in every .js service file
process.on('uncaughtException', (err) => {
  console.error('[FATAL]', err.message, err.stack);
  process.exit(1); // NSSM restarts automatically
});
process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled rejection:', reason);
});
```

---

## next.config.js — no API rewrite (proxying lives in proxy.ts)

`next.config.js` does **not** proxy `/api/*` — there is no `rewrites()` block. All
`/api/*` requests are intercepted by the edge middleware in `frontend/src/proxy.ts`
(`NextResponse.rewrite()`), which is also what stamps the verified `X-User-Id` /
`X-User-Role` headers before forwarding to the Express API on port 3005 — a static
`next.config.js` rewrite can't attach per-request session headers or strip
client-spoofed ones. `next.config.js` itself only passes `NEXTAUTH_URL` and
`NEXT_PUBLIC_NOCVAULT_HUB_URL` (with a legacy `NEXT_PUBLIC_NETVAULT_HUB_URL`
fallback) through via its `env` block.

Port 3005 does not need to be open in the firewall — the browser never calls it
directly, only `proxy.ts` does (server-side).

If `/api/*` calls start 404ing (or 401ing unexpectedly), check `frontend/src/proxy.ts`'s
`config.matcher` and `PUBLIC_API_PATHS`, **not** `next.config.js`.

### Adding a new intentionally-public (no-session) API route

LogVault gates unauthenticated `/api/*` calls with **two** independent
allow-lists that must be updated TOGETHER, in the same change, or the route
passes one gate and still gets blocked by the other:

1. **`frontend/src/proxy.ts`'s `PUBLIC_API_PATHS`** — otherwise the edge
   middleware 401s the request before Express is ever reached.
2. **`api/server.js`'s `enforceLicense()` `exemptPaths`** — otherwise the
   route 402s whenever the license is in a disabled state (grace-expired, or
   an active key that explicitly excludes this module).

There is no third gate here: `api/rbac.js`'s `rbacMiddleware` only *attaches*
`req.rbac`, it never blocks by itself — individual routes opt into blocking
via `requireAdmin`/`requireSuperAdmin` per-route, there's no global write-gate
in front of everything. Sibling app SpanVault has a THIRD, independent gate in
its equivalent middleware stack, so don't assume this 2-gate list is
universal across the suite — recheck the sibling app's own proxy/license/RBAC
files before porting a "make this route public" change over there.

---

## Dynamic Settings — No Restart Pattern

Settings stored in `app_settings` are reloaded automatically every 5 minutes. Never require a service restart for settings changes.

```javascript
// Pattern used in collector and emailer
let settingsCache = {};
let settingsLoadedAt = 0;
const SETTINGS_TTL = 5 * 60 * 1000;

async function getSettings() {
  if (Date.now() - settingsLoadedAt < SETTINGS_TTL) return settingsCache;
  const { rows } = await pool.query(`SELECT key, value FROM app_settings`);
  settingsCache = Object.fromEntries(rows.map(r => [r.key, r.value]));
  settingsLoadedAt = Date.now();
  return settingsCache;
}
```

---

## Dashboard-widget hourly rollups (perf pass, added 2.20.x)

Four dashboard widget endpoints (`/api/stats/summary`, `/api/stats/timeline` for
`hours > 6`, `/api/stats/top-talkers`, `/api/stats/by-vendor`) read from two small
pre-aggregated tables — `syslog_stats_rollup` and `syslog_talker_rollup`
(`scripts/schema.sql`, extensive design-rationale comments live right above the
`CREATE TABLE` statements — read those before changing anything here) — instead of
scanning raw `syslog_entries`. This was a real, measured production problem, not a
guess: a live `EXPLAIN ANALYZE` audit found a 24h severity-distribution query reading
~560MB from disk on every cache-miss (DB-wide cache hit ratio was 61%, healthy is
>99%) and the top-talkers query taking 1.6s with ~300MB spilled to disk temp files
(`work_mem` too small for the sort). `/api/stats/top-destinations`,
`/api/stats/top-security-events`, `/api/stats/top-failures`, `/api/stats/top-blocked`,
and `/api/reports`' `mitre-coverage`/`security-summary` still query raw
`syslog_entries` — they rely on message-text `ILIKE` patterns and destination-IP
fields the rollup doesn't cover; they still benefit from the Postgres `work_mem` fix
below, just not from the rollup itself.

**`srcip` column.** `syslog_entries` also gained a real, indexed `srcip TEXT` column —
the collector (`collector/collector.js`'s `processMessage()`) now computes it ONCE at
insert time (`COALESCE(structured_data.srcip, source_ip)`, same formula every widget
used to compute ad hoc per row at read time) instead of every query re-extracting it
from JSONB. It's also round-tripped through the disk spool (`serializeEntry`/
`deserializeEntry`) so a crash-restart replay doesn't silently drop it.

**Maintenance model — recompute-window, NOT increment-on-insert.** The collector's
`runRollupMaintenance()` (a separate 5-minute timer, does not touch the existing 24h
`runCleanup` timer) DELETEs and re-INSERTs ONLY the current + previous hour bucket
every cycle — a full re-aggregation of just ~2 hours of raw data, cheap. Hours older
than that are never touched again once written. This is deliberately idempotent and
self-healing: a missed cycle, a collector restart, or a double-run can never
double-count or drift, because each cycle always recomputes from the raw source of
truth rather than adding a delta to a running total. **Do not "optimize" this into an
increment-on-insert model** — it looks like an obvious efficiency win and quietly
reintroduces double-counting/drift risk on every collector restart or retry.

**RBAC.** `site_id` in BOTH rollup tables is resolved via
`known_hosts.ip_address = source_ip` — the RELAY/firewall device, exactly matching how
`getStatsSiteFilter()` in `api/rbac.js` scopes dashboard aggregates — **never** via
`srcip` (the actor), even in `syslog_talker_rollup` where `srcip` is the grouping key.
Mixing these up would silently break site-scoped users' visibility. Reading a rollup
uses a new, simpler helper, `getRollupSiteFilter(rbac, startParamIndex)` (`api/rbac.js`)
— a plain `site_id = ANY($n) OR site_id IS NULL` column filter, since the join to
`known_hosts` already happened at rollup-build time; verified byte-for-byte equivalent
to `getStatsSiteFilter`'s three branches (admin/no-filter, no-sites-user, scoped-user).
**`top-talkers` keeps a SEPARATE, LIVE join to `known_hosts`** (keyed on the actor's
`srcip`, not `source_ip`) purely for DISPLAY enrichment (hostname/vendor
fallback/country/ASN/abuse score) — this is intentionally NOT baked into the rollup, so
threat/geo data always reflects current enrichment rather than a stale snapshot. One
disclosed precision trade-off: `top-talkers`' `last_seen` is now `MAX(hour_bucket)`
(hour-granularity), not an exact timestamp — acceptable for a live-refreshing widget;
don't "fix" this by joining back to raw `syslog_entries`, that defeats the whole point.

**No `PRIMARY KEY` on either rollup table — this is deliberate, not an oversight.** A
Postgres `PRIMARY KEY` implicitly forces `NOT NULL` on every one of its columns, which
would reject every row for an unassigned device (`site_id IS NULL` is a legitimate,
common value here, not an edge case). Each table instead has a `COALESCE`-wrapped
`UNIQUE INDEX` (e.g. `... (hour_bucket, severity, category, vendor, COALESCE(site_id,
-1))`) — same duplicate-row protection, without conflicting with the nullable column.

**Deploy sequencing — READ BEFORE DEPLOYING.** Schema, collector, and API changes all
land in one git push/update. The moment the updated API is live, these 4 endpoints
read from the rollup tables — which are EMPTY for every hour except whatever the live
5-minute job has caught since deploy. Run `node scripts/backfill-rollups.js` (as
`postgres` — reads `POSTGRES_PASSWORD` from `.env.local`, needed because part (a)
UPDATEs the append-only `syslog_entries` table) **immediately after deploying**, before
relying on the dashboard — it backfills `srcip` + both rollup tables for the last 30
days (~5.8M rows, batched by day; takes a few minutes, logs progress). Until it
finishes, widgets will show partial/mostly-empty data for ranges beyond the last couple
of hours — not a bug, just the expected pre-backfill window. Idempotent — safe to
re-run if interrupted (`BACKFILL_DAYS` env var overrides the 30-day default).

**Postgres tuning (Phase 0, applied manually — Claude has no DB-write access to
production).** `work_mem` was only 16MB, which is what forced the ~300MB disk-spill
sort in the pre-rewrite `top-talkers` query (now moot for that specific query, but
still applies to the raw-table endpoints listed above, and to any future heavy query).
Recommended: `ALTER ROLE logvault_user SET work_mem = '64MB';` run once as `postgres`
— scoped to LogVault's own DB role only (not `ALTER SYSTEM`, which would affect
NetVault/DDIVault/SpanVault too, sharing the same Postgres instance). Takes effect on
the role's next new connection, no server restart needed. `shared_buffers` (currently
1GB, DB-wide cache hit ratio was 61%) is a further, separate lever contingent on
confirming actual server RAM — not applied here, deliberately left as a follow-up.

**Phase 2 (added 2.22.x): Top Security Events, Top Blocked, Top Connection
Failures, VPN Status.** The paragraph above ("`/api/stats/top-security-events`,
`/api/stats/top-failures`, `/api/stats/top-blocked` ... still query raw
`syslog_entries`") described the state BEFORE this phase — it's now
out of date for those three (plus `/api/stats/vpn-summary`, not listed
there originally). A live production report of dashboard widgets taking
"20 seconds or more" led to an `EXPLAIN ANALYZE` audit that found
`top-security-events` alone taking **17-29 seconds**: its `severity <= 4`
filter matches **~100% of a typical day's rows** (259,276 of 259,393 rows
in one live partition), so the filter has essentially zero selectivity —
Postgres correctly chose a sequential scan over any index, because for a
predicate this unselective an index scan really would be slower. No index
design can fix that; only pre-aggregation can. `top-blocked` (~6.5s),
`top-failures` (~2.3s), and `vpn-summary` (~2.9s) had the same root shape
(live `ILIKE`/action classification over the full raw window on every
widget load) at smaller scale.

Three new purpose-built rollup tables (`scripts/schema.sql`, "PHASE 2 HOURLY
ROLLUP TABLES" — read the comments there before changing anything):
- **`syslog_security_event_rollup`** — `(hour_bucket, event_type, site_id) →
  log_count`. `event_type` is the exact same classification `CASE` the
  endpoint used to run live (SSL Alert / SSL Exit Error / IPSec Phase 1
  Error / Login Failed / Traffic Denied / IPS Threat / VPN Negotiate /
  `structured_data.subtype` / Other), pre-filtered to `severity <= 4` at
  rollup-build time since the endpoint never varies that threshold.
- **`syslog_dest_event_rollup`** — `(hour_bucket, event_class, dstip,
  service, vendor, site_id) → log_count`, shared by Top Blocked
  (`event_class = 'blocked'`) and Top Connection Failures (`event_class =
  'failure'`) — one table instead of two near-duplicates, since both widgets
  group by the same shape and differ only in classification predicate + the
  `event_class` value. Geo/threat enrichment (country/ASN/abuse score/
  known-bad) is **not** stored here — same as `top-talkers`/
  `top-destinations`, it stays a LIVE join to `known_hosts` on `dstip` at
  read time, so enrichment always reflects current threat-intel data, not a
  rollup-time snapshot.
- **`syslog_vpn_rollup`** — `(hour_bucket, site_id) → total, failures,
  successes, ssl_alerts`. Unlike the other two, this stores pre-computed
  SUMS rather than a dimension to `GROUP BY` — the 4 metrics are
  independent, overlapping classifications of the same row (a message can
  match both `fail` and `ssl-alert` at once), mirroring the source query's
  four `COUNT(*) FILTER(...)` clauses exactly. The endpoint just `SUM`s each
  column across the window.

Same maintenance model as Phase 1 (recompute-window DELETE+INSERT for
current+previous hour, every 5 minutes, in `collector/collector.js`'s
`recomputePhase2RollupBucket()` — called from `recomputeRollupBucket()`
alongside the Phase 1 tables) and same `getRollupSiteFilter()` RBAC read
pattern. `scripts/backfill-rollups.js` was extended (not replaced) to also
backfill these 3 tables for the same 30-day window, in the same per-hour
loop as the Phase 1 tables — **run it again after this deploy** even if
you've run it before; it's idempotent (DELETEs a bucket before
re-INSERTing), so re-running is always safe and just recomputes the Phase 1
tables' numbers a second time as a side effect.

`/api/stats/storage`'s `total_rows` (StorageWidget, purely informational
display, never used for filtering/pagination) switched from an exact
`COUNT(*)` over the full multi-GB partitioned table (~5s live) to
`pg_class.reltuples` (planner statistics, refreshed by autovacuum/`ANALYZE`)
summed across the partition tree — the same approximate-count trade-off
Postgres's own `\dt+`/`pg_stat_user_tables` make. `rows_24h`/`rows_7d` stay
exact `COUNT(*)` — those are already cheap, bounded scans via the
`received_at` index over only 1-7 days of partitions.

`/api/stats/top-destinations` and `/api/reports`' `mitre-coverage`/
`security-summary` still query raw `syslog_entries` — still true, unchanged
by this phase.

**Deploy sequencing for THIS phase — same rule as Phase 1, read it again.**
Apply `scripts/schema.sql` (creates the 3 new tables) before deploying the
new `collector`/`api` code, then run `node scripts/backfill-rollups.js`
immediately after deploying — until it finishes, these 4 widgets will show
partial/empty data for any range beyond whatever the live 5-minute job has
caught since deploy (same expected-empty-until-backfilled window as Phase 1,
not a bug).

**Security/Network Health tabs (added 2.21.x) — a DIFFERENT class of fix.** Unlike the
dashboard's clean severity/category/vendor dimensions, these tabs' ~20 query shapes
(`/api/security/*`, `/api/health/*`) are too varied for a rollup-table rewrite to be
worth the risk. Live `EXPLAIN ANALYZE` investigation found two distinct problems, each
needing a different fix:

1. **`message ILIKE '%...%'` fallback clauses next to an already-reliable
   `structured_data->>'subcategory'` check are dead weight — verify with a live
   recall check before assuming one is needed.** Several security queries carried a
   `subcategory IN (...) OR message ILIKE '%login failed%' OR message ILIKE
   '%authentication fail%'`-shaped condition — a defensive fallback from before all
   vendor parsers reliably populated `subcategory` (2.9.0). A live 30-day production
   check (`WHERE ILIKE-pattern AND subcategory NOT IN (...)`) found **zero** rows the
   ILIKE fallback caught that `subcategory` didn't already cover, for every pattern
   checked (login_failed/auth_failed, login_success). The fallback wasn't just
   pointless — it was actively expensive: it forces the planner into a 3-way
   `BitmapOr` (subcategory expression index + 2x message-trigram index) evaluated per
   partition, ballooning planning time alone to 100-350ms (see `idx_syslog_subcategory`
   / `idx_syslog_message_trgm`). Removed from `/api/security/summary` (3 of its 8
   sub-queries), `/api/security/auth-failures`, `/api/security/brute-force` (both
   CTEs), `/api/security/failed-logins-by-country` — each verified to return
   byte-identical results over the full 30-day retention window before and after.
   Measured: ~90-340ms → a stable ~8ms. **`/api/health/config-changes`'s ILIKE
   fallback was deliberately left untouched** — its current dataset has zero matching
   rows, so there's no live data to empirically prove the simplification is exactly
   equivalent; don't remove it without that proof. The broader `%vpn%`/`%login%`
   catch-alls in `/api/security/after-hours` were also left alone — they weren't
   verified and may genuinely catch content no subcategory captures.
2. **`/api/health/device-status`'s slowness is NOT an unused/broken index** — a common
   trap this could look like. The `idx_syslog_received_source` covering index IS being
   used correctly for the big, stable partition. The real cost: this endpoint computes
   4 overlapping time-windowed `COUNT(*) FILTER` aggregates across a 6-column
   `GROUP BY`, which has to touch nearly every row in the 24h window regardless of
   indexing — the same *class* of problem as the original dashboard widgets, just
   shaped per-device instead of per-severity/category. Not yet fixed; the natural next
   step (not yet built) is a small per-device rollup table on the same 5-minute
   maintenance cadence as the two rollups above — see if this needs picking up before
   assuming "add an index" will help here, it won't.

**Frontend code-splitting (added 2.22.0) — a THIRD, independent axis of "feels
slow."** Fast backend queries alone don't guarantee a fast-feeling page: `frontend/src/app/page.tsx` is a single client component that switches between 10
tabs via `useState<Tab>` (not separate Next.js routes), and every tab's component
used to be a plain static `import` at the top of the file — meaning the FULL app
(~1.4MB of JS: Log Explorer, Live Tail, Alerts, Network Health, Security,
Intelligence, Known Hosts, Reports, Settings, all of it) loaded and parsed on
every visit, even if the user only ever looks at Dashboard. `next/dynamic` was
used **zero times** anywhere before this. Fixed by converting the 9 non-Dashboard
tab imports to `dynamic(() => import(...), { ssr: false, loading: () => tabLoading })`
— each is now its own on-demand chunk (verified post-build: grepping each
component's distinctive code confirms it's isolated to its own dedicated chunk
file, separate from the Dashboard's own widgets). **Dashboard's own widgets
(`SeverityChart`, `TimelineChart`, `DashboardWidgets` exports, etc.) were
deliberately left as regular static imports** — they're needed immediately since
Dashboard is the default tab, so lazy-loading them would only add loading-state
complexity for content shown right away; only defer what genuinely isn't needed
on first paint. `ssr: false` is safe here (not just an optimization) because
`tab` state always starts at `'dashboard'` and only changes via client
interaction, so none of these branches are ever true during the server-render
pass regardless — and `LiveTail` specifically needs it, since it depends on
browser-only WebSocket APIs that would error under SSR.

If a future non-Dashboard tab component grows a new heavy dependency, it's
already isolated in its own chunk — no further action needed. If a NEW tab is
ever added, default to `next/dynamic` for it from the start rather than a
static import, unless (like Dashboard) it's the tab shown on initial load.

**Live incident: EVERY response was missing `Cache-Control` (fixed 2.22.1) —
neither a hard refresh nor Incognito/InPrivate mode can fix a bug this
causes.** A live production incident showed the app intermittently flapping
between a current build and an old (~2.18.x) one, on the SAME browser AND in
a fresh Incognito window, surviving repeated hard refreshes. Direct `curl`
testing from outside the affected network showed the origin server
responding correctly and consistently every single time — the bug only
reproduced from inside the customer's own corporate network. Root cause:
neither `api/server.js`'s Express responses nor `next.config.js`'s page
responses set an explicit `Cache-Control` header — only a weak `ETag`. A
response with a validator but no explicit caching directive is exactly the
shape RFC 7234 permits a compliant cache to store heuristically, and a
transparent corporate proxy/security appliance sitting in the network path
(common on corporate LANs) can and will do exactly that — invisibly to any
test that doesn't route through that same proxy. **The diagnostic tell:**
if a bug reproduces consistently for a user but never for a direct
server-side `curl` test, and neither a hard refresh nor an Incognito window
changes anything, suspect a cache living on network infrastructure BETWEEN
the browser and the server, not the browser's own cache — no client-side
action can ever fix that class of bug, only the server explicitly forbidding
caching can. Fixed with two matching pieces: a global Express middleware
(near the very top of `api/server.js`, before CORS) setting `Cache-Control:
no-store, no-cache, must-revalidate, private` + `Pragma: no-cache` on every
API response, and a `next.config.js` `headers()` export applying the same to
every page/document response — **deliberately excluding** `/_next/static/*`
(a second, more specific rule overrides the broad one back to Next's own
long-lived `immutable` caching there, since those filenames are
content-hashed and safe/correct to cache forever; Next.js merges matching
header rules and the LAST matching rule wins for a duplicate key, so rule
order matters). Don't ever loosen either of these without a very specific
reason — this class of bug is expensive to diagnose and easy to reintroduce
silently by adding a new response path that forgets to set these headers.

**Follow-up (2.22.2): headers alone don't evict what a proxy already cached.**
Even after 2.22.1 shipped, the SAME symptom (stale version number, stale
"OFFLINE" collector-status badge) kept recurring on the affected network days
later, deterministically on every hard refresh. The 2.22.1 fix only stops a
compliant cache from storing a *new* response — it cannot reach into a
proxy's existing store and evict an entry that was cached *before* the fix
existed (when the response genuinely had no `Cache-Control` at all). If that
proxy's TTL for the cached entry is long (or effectively indefinite because
its heuristic caching had nothing but a weak `ETag` to go on), the stale
entry can outlive the fix by days with zero server-side symptom — direct
`curl`/localhost checks against the origin looked completely correct the
whole time, because they never round-tripped through the same proxy. Fixed
`Header.tsx`'s `pollHealth`/`pollUnacked` and `page.tsx`'s `fetchHealth` (the
three call sites feeding the version number and the collector-status pill)
to append a `?_=${Date.now()}` cache-busting query param on every request —
a proxy (or browser) cache is keyed on URL, so a URL it has never seen before
can never be served from its existing store, regardless of whether that
cache honors `Cache-Control` correctly or not. **Lesson: `Cache-Control:
no-store` prevents future staleness; it does not retroactively fix a
resource that was already cached under the old (headerless) behavior.** For
any endpoint whose staleness is directly user-visible (status indicators,
version numbers) and that lives on a customer network with an unknown/opaque
caching layer in the path, prefer cache-busting the request itself over
relying solely on response headers — it's the only fix that's correct
regardless of what any intermediary does.

**The actual root cause (2.22.3): there was no network cache at all — a
build ever read the WRONG file for its version number.** After 2.22.1 *and*
2.22.2 both shipped and the symptom still hadn't gone away — deterministically
on every hard refresh, even with the browser cache manually cleared —
`view-source:` on the live page proved the raw, pre-JavaScript server-rendered
HTML itself literally contained `v2.18.12`, baked directly into the response.
That's not something any HTTP cache (browser or proxy) can explain; it means
the value really was `2.18.12` at the moment the page was rendered. Root
cause: `page.tsx` read its version-number fallback via
`import { version } from '../../package.json'`, which resolves to
**`frontend/package.json`** — a second, entirely separate `version` field
from the root `package.json` that every release in this document actually
bumps (`npm version patch` at the repo root). Nothing had ever kept
`frontend/package.json`'s version field in sync; it had been stuck at
`2.18.12` since long before this incident, undetected because it's cosmetic
and every other release note/behavior was correct. `page.tsx` renders this
build-time fallback on first paint (SSR, before hydration), then overwrites
it with the live `/api/health` response a moment later — so on a fast
connection you'd see the wrong number flash for a fraction of a second before
it self-corrected, which glanced at quickly, or caught in a screenshot, or
hit on a slow/first load where hydration takes longer, looks exactly like the
app "reverting" to an old version. **This is almost certainly what the
original version-flapping symptom actually was, days before any caching
theory entered the picture** — the Cache-Control headers (2.22.1) and
request cache-busting (2.22.2) were reasonable, defensible responses to the
*evidence available at the time* (intermittent staleness, un-reproducible
via direct curl) and are good practice regardless, but they were treating a
symptom of this bug, not the cause. Fixed by making the version number come
from exactly one place: `next.config.js` now reads the root `package.json`
directly (`require('../package.json').version`) and injects it as
`NEXT_PUBLIC_APP_VERSION`; `page.tsx` reads that env var instead of importing
any package.json itself. This can't drift out of sync again because there is
only one source left to read from.

**Lesson for next time:** when a bug reproduces consistently in the browser
but the server-side evidence (`curl`, localhost checks) looks clean, the
instinct to suspect network infrastructure is reasonable — but before
committing to that theory, check `view-source:` (or the actual HTTP response
body) directly for the suspicious value FIRST. If the raw response already
contains the wrong value, the bug is server-side (wrong data/wrong build),
not a caching layer, no matter how deterministic or hard-refresh-proof it
looks — determinism and hard-refresh-immunity are consistent with a stale
*value* just as much as a stale *cache entry*, and checking the raw response
is a five-second test that would have shortened this whole diagnosis
considerably.

---

## Alert System

### Deduplication rules
- Same rule + same source IP → update existing open alert (increment match_count), not insert new row
- 30-minute suppression window per rule + source IP
- Correlation engine cooldown: 30 minutes

### Alert firing
- `collector/collector.js` → `checkAlertRules()` → `fireAlert()`
- `collector/correlationEngine.js` → fires correlation alerts
- `collector/emailer.js` → sends email if rule has `notify_email` set and SMTP configured

### Alert rule matching
Rules match on: severity array, vendor array, host pattern (ILIKE), message regex pattern, threshold count + window. Threshold fires on `fresh.length >= rule.threshold_count` (not `===`).

### Alert acknowledgement
`alert_events.acknowledged_by` records the acting user's **NetVault user id (as text)**,
taken from `req.rbac.userId` (the `X-User-Id` header set by the proxy). Resolving it to a
display name requires a join to `netvault.users.id`. Set on both the single-ack and
bulk-ack endpoints in `api/server.js`.

### Parser source-field contract (srcip/user/subcategory)

Every parser MUST, for auth/VPN/failed-login events, emit:
- `structured_data.srcip` — the **REAL client/source IP** (the remote user/attacker), **never the syslog sender** (the relaying firewall/device). For VPN/auth logs that lack a native srcip, map the remote-IP field (e.g. Fortinet `remip`) into `srcip`.
- `structured_data.dstip` — the destination IP where available.
- `structured_data.user` — the username from the event.
- `structured_data.subcategory` — one of `'login_failed'` / `'login_success'` / `'auth_failed'`.
- `category` set to `'vpn'` or `'authentication'` as appropriate.

Correlation rules in `collector/correlationEngine.js` (BRUTE_FORCE_SUCCESS, VPN_BRUTE_FORCE, PORT_SCAN, IPS_REPEATED_ATTACK) are **vendor-agnostic** (not gated to any vendor) and group by `structured_data.srcip || source_ip`, so attacks attribute to the real attacker IP. Keep new/updated parsers conforming to this contract so correlation works for every vendor.

As of 2.9.0, **ALL vendor parsers** (Cisco, Palo Alto, Check Point, SonicWall, Juniper, Windows, Aruba, Sangfor, Forcepoint, and the generic fallback — not just Fortinet) implement this contract and capture the full per-vendor security field set (IPS/threat signatures + severity, web-filter URLs/categories, VPN/auth identity, traffic service/proto/bytes/geo).

---

## NetVault Asset Enrichment

Collector syncs NetVault devices every 15 minutes into `known_hosts`:
- Pulls: device name, IP, brand, model, site name, device status, lifecycle status
- Maps brand names to syslog vendors (Fortinet → fortinet, Palo Alto → paloalto etc)
- NetVault entries take priority — DNS lookup won't overwrite NetVault data

```javascript
// Brand → vendor mapping
const BRAND_TO_VENDOR = {
  'fortinet': 'fortinet', 'cisco': 'cisco',
  'palo alto': 'paloalto', 'aruba': 'aruba', 'sangfor': 'sangfor'
};
```

---

## DNS Reverse Lookup

- Enabled/disabled via Settings → DNS Lookup
- DNS server IP configurable (or uses system default)
- Settings reload dynamically every 5 minutes — no restart needed
- Looks up every new unique IP seen in logs
- Caches results for 1 hour
- Never overwrites NetVault-synced hostnames
- Works for both internal IPs and external IPs (e.g. 8.8.8.8 → dns.google)

---

## Firewall Rules

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 3004 | TCP | Inbound | LogVault frontend (public) |
| 514 | UDP + TCP | Inbound | Syslog collection |
| 1514 | UDP + TCP | Inbound | Syslog alternate port |
| 3005 | — | — | DO NOT OPEN — internal API only |

---

## Known Bugs — Never Repeat

| Bug | Fix |
|---|---|
| Cross-app links hardcoded to install-time IP | Use `resolveOrigin()`/`getHubUrl()` from `frontend/src/lib/publicUrl.ts`, not a raw `process.env.NOCVAULT_HUB_URL` read |
| TypeScript in `.js` files | Never use type annotations in server/collector JS files |
| `${hours}` in SQL | Use `make_interval(hours => $1)` |
| Same `$1` twice in query | Use JOIN not nested subquery |
| Wide-open CORS | Restrict to `localhost:3004` |
| Stack traces to client | Always return generic `Internal server error` |
| `any` types unchecked | Define proper interfaces in TypeScript |
| `.env.local` not at runtime | Set vars in NSSM `AppEnvironmentExtra` |
| Next.js API 404 / 401 | Check `proxy.ts`'s `config.matcher` + `PUBLIC_API_PATHS` — NOT `next.config.js` (there is no `/api/*` rewrite; proxying is edge middleware) |
| `middleware.ts` deprecated | Use `proxy.ts` in Next.js 16 |
| `useSearchParams` without Suspense | Wrap in `<Suspense>` |
| Port 3005 exposed | Internal only — never open in firewall |
| `Stop-Service` hanging terminal | Use `sc.exe stop` always |
| Em-dash in PS1 files | Use `-` not `—` in PowerShell scripts |
| `new Date()` in render | Use `useMemo` |
| Component defined inside component | Always define components at module level |
| Alert spam (70+ rows) | 30-min suppression + upsert existing open alert |
| Known hosts too long | Collapsible with show 10 / show all |
| Alert threshold `===` (never fires on burst) | Compare `fresh.length >= rule.threshold_count` — count can jump past threshold in one tick |
| Hardcoded credential fallback (`\|\| 'secret'`) in code | Read secrets from `process.env` only; fail fast if missing — never bake a literal default |
| Cookie `secure: false` hardcoded | Derive from `NEXTAUTH_URL.startsWith('https')` so HTTPS auto-enables Secure without breaking HTTP |
| App-access gate on the page route only | Enforce `appAllowed()` in BOTH `proxy.ts` branches — the page-route guard AND the `/api/*` proxy branch. Page-only gating leaves the whole API reachable by any valid session cookie (2.19.1) |

---

## Log Service Commands

```powershell
# Status
nssm status LogVault-Collector
nssm status LogVault-API
nssm status LogVault-App

# Restart individual service
nssm restart LogVault-Collector
nssm restart LogVault-API

# View logs
Get-Content "C:\Apps\logvault\logs\collector.log" -Tail 30
Get-Content "C:\Apps\logvault\logs\api-err.log"   -Tail 30
Get-Content "C:\Apps\logvault\logs\app.log"        -Tail 30

# Health check
Invoke-WebRequest -Uri "http://localhost:3005/api/health" -UseBasicParsing | Select-Object -ExpandProperty Content

# Check ingestion
$env:PGPASSWORD = "<set-in-NSSM-env>"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U logvault_user -d logvault -c "SELECT COUNT(*) FROM syslog_entries WHERE received_at > NOW() - INTERVAL '1 hour';"
```

---

## app_settings Keys Reference

| Key | Default | Purpose |
|---|---|---|
| `app_name` | LogVault | App display name |
| `app_subtitle` | Syslog & Log Analysis | Subtitle in header |
| `primary_color` | #C8102E | Button/accent color |
| `sidebar_color` | #1a2744 | Sidebar background |
| `logo_url` | (empty) | Custom logo URL |
| `dns_server` | (empty) | DNS server for reverse lookup |
| `dns_lookup_enabled` | true | Enable/disable DNS lookup |
| `smtp_host` | (empty) | SMTP server hostname |
| `smtp_port` | 587 | SMTP port |
| `smtp_user` | (empty) | SMTP username |
| `smtp_pass` | (empty) | SMTP password |
| `smtp_from` | (empty) | From email address |
| `smtp_enabled` | false | Enable email alerts |
| `email_notify_enabled` | true | Master on/off switch for alert emails, independent of `smtp_enabled` |
| `email_notify_severities` | `["0","1","2","3"]` | JSON array of severities that trigger an email. Empty array = all severities |
| `email_notify_categories` | `[]` | JSON array of taxonomy categories to email on. Empty = all categories |
| `email_notify_vendors` | `[]` | JSON array of vendors to email on. Empty = all vendors |
| `email_notify_min_risk` | 40 | Minimum `risk_score` (0-100) required to send an email. `0` = no minimum |
| `email_notify_digest_mode` | instant | Digest-mode selector, stored/exposed in Settings; `collector/emailer.js` does not yet branch on it — every eligible alert is sent instantly regardless of this value |
| `email_notify_digest_hour` | 8 | Hour (0-23) reserved for a future daily digest send; not yet consumed by the emailer |
| `email_notify_recipients` | (empty) | Comma-separated recipients added to every alert email, in addition to each rule's own `notify_email` |
| `email_notify_cooldown_mins` | 30 | Minimum minutes between emails for the same alert rule, tracked in-memory (resets on collector restart) — separate from the alert dedup/suppression window |
| `collector_allowed_sources` | (empty) | Comma-separated IPs/CIDRs the collector accepts syslog from. **Empty = allow ALL** (default). IPv4/CIDR only — non-IPv4 sources fail open. |
| `collector_rate_limit_enabled` | false | Enable per-source-IP ingestion rate limiting |
| `collector_rate_limit_pps` | 0 | Max packets/sec per source IP. `0` = unlimited (sentinel). Only applies when `collector_rate_limit_enabled` is true |
| `abuseipdb_api_key` | (empty) | AbuseIPDB API key for threat scoring of external IPs. Empty = GeoIP only (ip-api.com, no key). Read by the collector via the 5-min DNS-settings cache; never logged. |

> **Collector ingestion hardening (default-permissive).** The allow-list and rate-limit
> above are off by default so they never drop live traffic until an operator opts in. Both
> reload via the 5-min dynamic-settings cache (no restart). The collector logs a 60-second
> aggregate of packets dropped by each guard (never per-packet, to avoid log spam).

---

## Features Completed

| Feature | Notes |
|---|---|
| Syslog collection UDP/TCP 514 + 1514 | Fortinet, Cisco, Palo Alto, Aruba, Sangfor, Forcepoint, Check Point, Juniper, Windows, SonicWall, Generic parsers |
| Universal event taxonomy | `collector/taxonomy.js` assigns standard `category` to every entry (auth, vpn, firewall, security, …) |
| Risk scoring | `collector/riskScorer.js` computes 0-100 `risk_score` per entry; shown as badge in Log Detail panel |
| Category filter | Log Explorer category chips + `category` API filter |
| Real-time dashboard | Severity, top talkers, blocked destinations, connection failures, VPN stats, timeline |
| Smart Log Explorer | Preset searches, vendor/severity chips, host filter, active filter tags |
| Log detail slide-over panel | Parsed fields, copy buttons, quick actions, related logs |
| Alert rules + correlation engine | Threshold rules + 8 correlation rules |
| Alert deduplication + suppression | 30-min cooldown, upsert existing open alerts |
| NetVault asset enrichment | Auto-sync every 15 min, brand/model/site/status |
| DNS reverse lookup | Dynamic settings, 1hr cache, no restart needed |
| Email alerting | SMTP configurable in Settings, per-rule notify_email |
| SSO authentication | Via NetVault hub JWT |
| Dark mode | Via ThemeContext |
| Settings page | Branding, DNS, SMTP |
| Storage & capacity widget | Real disk usage via PowerShell Get-PSDrive |
| Known hosts | NetVault sync + manual, collapsible list |
| NocVault rebrand | Throughout UI (cookie name unchanged) |
| GeoIP + threat intel enrichment | `collector/geoEnrich.js` enriches external IPs at ingest (ip-api.com geo + optional AbuseIPDB scoring) into `known_hosts`; country/ASN on dashboard widgets, "Known-Bad Sources" widget, `GET /api/threats/known-bad`. Private IPs never sent externally; never blocks ingestion. **Enriches BOTH source_ip AND the destination IP** (`structured_data.dstip`/`dst_ip`/`destination_ip`) — in firewall logs (Fortinet etc.) the external IP is the destination while source_ip is the internal device. Because dst external IPs are stored in `known_hosts`, the `top-blocked` / `top-failures` widgets join geo/threat on `host(known_hosts.ip_address) = structured_data->>'dstip'` (they display the destination IP); `top-talkers` still joins on `source_ip` |
| Time-partitioned storage | `syslog_entries` daily RANGE partitions + DROP-partition retention; cleanup runs in-process in the collector every 24h (no scheduled task) |
| Tamper-evident log integrity | HMAC-SHA256 hash chain (`prev_hash`/`entry_hash`); `verify-integrity.js`; append-only app role |
| Durable ingest spool | Disk write-ahead spool, replay on boot — no log loss on crash/restart/DB outage |
| Audit trail | `audit_log` append-only table + `api/auditLog.js`; settings/export/ack/sync/update actions; `GET /api/audit` (super-admin) |
| Collector ingestion hardening | Opt-in source allow-list + per-source rate limit (default off) |
| MITRE ATT&CK mapping | Technique tags on alerts (`alert_rules.mitre_techniques` + 8 correlation rules via `MITRE_BY_RULE`) and on events at ingest (`collector/mitreMapper.js` → `structured_data.mitre`, technique-level); `/api/logs?technique=` filter; ATT&CK Coverage tactic-matrix in the Security tab; `GET /api/stats/mitre-coverage` (RBAC-filtered); shared catalog `frontend/src/components/mitre.tsx`; `scripts/backfill-mitre-tags.js`. Tuned for Fortinet/Cisco; Windows/Palo Alto/other vendor structured signals deferred until those logs arrive. **T1110/brute-force is determined at the correlation altitude, NOT per-event** (mirrors the T1133 decision): a single failed login is never tagged T1110 — event-level T1110 is kept only when one message itself attests repetition/lockout ("account locked", "password spray", "repeated/multiple/N failed"), otherwise brute force comes from BRUTE_FORCE_SUCCESS / VPN_BRUTE_FORCE correlation rules. The **Fortinet parser maps VPN `remip` → `srcip`** (the real remote client IP for SSL-VPN/auth logs that have no native srcip) and captures `user`/`srccountry`/`reason`/`logdesc` into `structured_data`, so the real remote source is surfaced and VPN brute-force correlation can group by the attacker IP. `scripts/fix-mitre-t1110-single.js` backfills (strips) the old single-failure T1110 tags |
| Per-app license-module gating | `api/licenseCheck.js` / `getLicenseState()` locks LogVault when an ACTIVE NocVault license explicitly lists modules and omits `logvault` (`enforceLicense` middleware returns 402); fail-open for trial/grace/expired/hub-unreachable so trials and legacy keys are never bricked (v2.18.0-2.18.1) |
| Phase 1/2 intelligence — UEBA, anomaly detection, risk explainability | `collector/analytics/` (`baselineBuilder.js`, `anomalyDetector.js`, `uebaRollup.js`) builds per-entity behavioral baselines, flags deviations, and rolls up entity risk (relay hosts excluded via `UEBA_RELAY_HOSTS`); Intelligence Console UI, plain-language MITRE, on-prem forecasting/what's-changed, activity heatmaps |
| Granular email-notification preferences | Per-severity/category/vendor/min-risk email filters, cooldown, and extra recipients (`app_settings` `email_notify_*` keys, enforced in `collector/emailer.js`'s `shouldSendEmail()`) |
| Per-user app access | NetVault SSO's `apps` claim is carried into LogVault's own session (`auth.ts`) and enforced by `proxy.ts`'s `appAllowed()` for both page routes and API calls; a denied user is redirected to the hub launcher (pages) or gets a JSON 403 (API) (v2.19.0-2.19.2) |
| Reporting engine — Phase 1 | `api/reports.js` + `frontend/src/components/ReportsTab.tsx`: 3 report types (Security Summary, Site/Device Activity, MITRE ATT&CK Coverage), each previewable in-app or exportable as CSV/PDF. See "Reporting Engine" section below (v2.20.0) |

## Pending / Planned

| Feature | Priority |
|---|---|
| Top talkers showing device names from NetVault | Next up |
| Compliance reports (PCI-DSS, ISO 27001) | Medium — Phase 2 of the reporting engine below; not yet built |
| Scheduled report email delivery | Low — Phase 1 shipped on-demand export only; `report_schedules`/`report_email_log` tables deliberately deferred |
| Dashboard customization | Low |

---

## Reporting Engine (Phase 1, added v2.20.0)

`api/reports.js` ported DDIVault's proven report-engine pattern: a `REPORTS`
registry `{ key: { title, gather(db, query, rbac) } }`, one generic router
(`GET /api/reports/:type?hours=<int>&format=json|csv|pdf`, mounted at
`app.use('/api/reports', ...)` after both `rbacMiddleware` and
`enforceLicense`), shared pdfkit rendering (cover page, summary tiles, vector
charts, zebra-striped table — all portrait). `api/pdfCharts.js` and
`api/csv.js` were ported alongside it (both fully portable, no
DDIVault-specific coupling). The 3 report types (`security-summary`,
`site-activity`, `mitre-coverage`) reuse the exact query logic already in the
`/api/stats/*` dashboard endpoints — no new analysis, just packaged for
export. `saved_reports` / `report_run_history` tables log every generation
(best-effort, wrapped so a logging failure never breaks the export).

**RBAC CONTRACT DIFFERS FROM DDIVAULT — do not "fix" it to match.** DDIVault's
router passes a plain `allowedSiteIds` array into `gather()`. LogVault's
`rbacMiddleware` instead attaches the WHOLE `req.rbac` object; every
`gather(db, query, rbac)` here takes that full object and calls
`getSiteFilter`/`getStatsSiteFilter`/`getAlertSiteFilter` itself per-query —
exactly like the `/api/stats/*` endpoints these reports reuse. Passing a bare
array instead would silently drop the site-scoping shape those helpers
expect.

**Chart rendering uses a generic `drawChart` ChartSpec primitive
(`{type:'line'|'bar', title, x, series, yFormat}`), not `pdfCharts.js`'s
`renderTrendChart`.** `renderTrendChart` is a single-series, 0-100%,
time-axis primitive (DDIVault only uses it for DHCP scope-utilization
blocks). LogVault's Phase 1 charts are multi-series/bar/categorical
(severity distribution, category/vendor breakdown, top techniques), so
`drawChart` — the same generic primitive DDIVault's own trend reports use
for this exact shape — is co-located in `reports.js` instead. `renderTrendChart`
stays ported and available for a future single-series per-device/per-site
trend block, but isn't wired into any Phase 1 report.

**No site/scope picker in the frontend** — every report is scoped
server-side to the viewing user's assigned sites automatically, identical to
every other LogVault page. Only a time-range control (`hours`, reusing the
existing `TimeRangePicker`) is exposed. Exports use the same plain
`window.open('/api/reports/:type?...', '_blank')` pattern as the existing
`/api/logs/export` (`LogExplorer.tsx`) — identity rides the session cookie
through `proxy.ts`, so no fetch→blob indirection is needed (unlike DDIVault's
old client-injected-header model).

---

## Versioning Policy

This app follows semantic versioning. Baseline: 1.2.0 (Jun 2026)

Every commit must include a version bump:
- Bug fix, UI tweak, copy change, config fix → PATCH (x.x.+1)
  Run: npm version patch --no-git-tag-version
- New feature, new page, new API, new chart → MINOR (x.+1.0)
  Run: npm version minor --no-git-tag-version
- Breaking change, DB migration, architecture overhaul → MAJOR (+1.0.0)
  Run: npm version major --no-git-tag-version

Examples of what counts as each type:
- Login page overhaul → Minor
- New dashboard with charts → Minor
- Health score tracking → Minor
- Bug fix (hardcoded IP, broken link, wrong email) → Patch
- New EOL intelligence integration → Minor
- Schema breaking change → Major

Rules:
- ALWAYS bump version as part of the same commit as the changes
- NEVER skip the version bump
- **Exception: pure documentation changes do NOT require a version bump.**
  `CLAUDE.md`-only edits, and source-comment-only fixes with zero logic
  change (e.g. a stale comment corrected in `api/rbac.js`), have no
  runtime/user-facing effect — bumping would misleadingly imply a functional
  change occurred. Anything that touches actual runtime behavior, however
  small (a copy string, a default value, a log line), still needs the bump.
- Run npm version BEFORE npm run build
- The app reads version from package.json via /api/health
- NocVault suite itself has no version number — only the 4 apps
- When bumping version, also update the releaseNotes object in the update status API with 3-5 bullets describing what changed. No CHANGELOG.md — release notes live in the update status API only.

## Database Access (Read-Only Diagnostics)

A read-only PostgreSQL user exists for Claude Code to query the live production
database directly during development. No psql installation needed — use the
Node.js `pg` module directly.

Connection details:

```
Host:      192.168.6.111
Port:      5432
User:      claude_readonly
Password:  [stored in Claude project memory — ask Amrin]
Databases: logvault, netvault, ddivault, spanvault
```

Usage in Claude Code:

```js
const { Client } = require('pg');
const client = new Client({
  host: '192.168.6.111',
  port: 5432,
  user: 'claude_readonly',
  password: process.env.DB_READONLY_PASS,
  database: 'logvault',  // change per app
  ssl: false
});
await client.connect();
const { rows } = await client.query('SELECT ...');
await client.end();
```

Permissions: SELECT only — cannot INSERT, UPDATE, DELETE, or modify schema.

Use it to:
- Check actual DB schema before writing queries
- Verify data exists before writing display code
- Diagnose query performance issues
- Confirm migrations worked correctly
- Inspect app_settings, known_hosts, alert_rules, etc.

The password is **never** stored in this repo — it lives in Claude Code's project
memory and is provided at the start of each session. Never log it or commit it to
any repo.

## Live Server Verification (Diagnostics)

The suite runs on the production server **192.168.6.111**. Verify the *running*
deployment directly from the dev host over HTTP — no SSH needed — using `curl`
(Bash tool) or `Invoke-WebRequest` (PowerShell). Pair this with the read-only DB
access above: **curl answers "is it up / what version / what HTTP status", the DB
answers "is the data correct".**

**Health / deployed version** (unauthenticated — safe to hit anytime; use it to
confirm a deploy actually landed):

```bash
curl http://192.168.6.111:3004/api/health        # -> { status, version, logs_last_hour }
```
```powershell
Invoke-WebRequest -Uri "http://192.168.6.111:3004/api/health" -UseBasicParsing | Select-Object -ExpandProperty Content
```

Use each app's **frontend** port (it also serves `/api/*`). LogVault's API port
3005 is also directly reachable, but the other apps' API ports (3007/3009) are
internal/proxied — so verify via the frontend port for consistency:

| App | Health URL |
|---|---|
| netvault  | http://192.168.6.111:3000/api/health |
| logvault  | http://192.168.6.111:3004/api/health |
| ddivault  | http://192.168.6.111:3006/api/health |
| spanvault | http://192.168.6.111:3008/api/health |

**This app: logvault → frontend port 3004 (API also on 3005).**

**Verifying behaviour & data:**
- Most endpoints require an authenticated session + RBAC (`getSiteFilter`), so an
  unauthenticated `curl` of them returns empty / 401 — that does **not** prove the
  endpoint is broken. To check the DATA an endpoint should return, query the
  read-only DB (above) or use the logged-in browser UI.
- Public/no-auth endpoints you CAN curl directly: `/api/health` (version +
  logs_last_hour) and `/api/stats` (logs_today / log_sources / active_alerts).
- Also use `curl` for HTTP-status sanity (200 vs 500, e.g. after a query change:
  `curl -s -o /dev/null -w "%{http_code}" http://192.168.6.111:3004/api/logs`).
- Deploys are **manual** — Amrin runs `Update-LogVault.ps1`; Claude never deploys.
  Always verify **after** the deploy: confirm `/api/health` shows the new version,
  then confirm data via the read-only DB, then eyeball the UI. (Backend-only
  changes can fast-path via restarting the LogVault-API service.)
