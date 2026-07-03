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
    netvaultSync.js                  ← NetVault asset sync for API
  collector\
    collector.js                     ← Syslog collector (514/1514)
    correlationEngine.js             ← Alert correlation rules
    netvaultSync.js                  ← NetVault asset sync for collector
    dnsLookup.js                     ← Reverse DNS lookup utility
    emailer.js                       ← SMTP email alerting
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
  collector\
    taxonomy.js                      ← Universal event category assignment
    riskScorer.js                    ← 0-100 risk score per log entry
  frontend\
    src\
      app\
        page.tsx                     ← Main app (sidebar + tab routing)
        layout.tsx                   ← Root layout with AuthProvider
        globals.css                  ← CSS variables + design tokens
        sso\page.tsx                 ← SSO landing page
        api\auth\[...nextauth]\route.ts
      components\
        Header.tsx                   ← Top bar with avatar dropdown
        ThemeContext.tsx             ← Dark mode context
        Toast.tsx                    ← Toast notifications
        LogExplorer.tsx             ← Log search with smart filters
        LogDetailPanel.tsx          ← Slide-over detail panel
        DashboardWidgets.tsx        ← All dashboard chart widgets
        StorageWidget.tsx           ← Storage & capacity widget
        KnownHosts.tsx              ← Known hosts with NetVault sync
        Settings.tsx                ← Settings page (branding, DNS, SMTP)
        AlertsPanel.tsx             ← Alert events panel
        SeverityChart.tsx           ← Severity distribution chart
        TopTalkers.tsx              ← Top talkers widget
        VendorBreakdown.tsx         ← Vendor breakdown chart
      auth.ts                       ← NextAuth config
      proxy.ts                      ← Auth middleware (replaces middleware.ts)
      types\next-auth.d.ts
    package.json                    ← Frontend dependencies
    next.config.js                  ← Rewrites /api/* → port 3005
    .next\                          ← Built output (next start)
  scripts\
    schema.sql                      ← SINGLE SOURCE OF TRUTH for DB schema
    cleanup.js                      ← Data retention cleanup
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

**Hub URL:** Always use `process.env.NEXT_PUBLIC_NOCVAULT_HUB_URL` (client) or `process.env.NOCVAULT_HUB_URL` (server) — never hardcode `192.168.6.111:3000`

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

### How identity reaches the API — header proxy (NOT cookie decode)

`next-auth` v4 with `session.strategy: 'jwt'` stores the session cookie as an
**encrypted JWE** (A256GCM, key derived from `NEXTAUTH_SECRET`). A plain
`jsonwebtoken.decode()` **cannot** read it — it returns `null`. So the Express
API does **not** parse the cookie, and `cookie-parser` / `jsonwebtoken` are
**not** added to the backend.

Instead, identity flows through a server-side proxy:

```
Browser → /api/*  →  frontend/src/app/api/[...path]/route.ts
                       (reads session via getServerSession — decrypts the JWE)
                       attaches X-User-Id + X-User-Role headers
                     → Express API (localhost:3005)
                       rbacMiddleware reads those headers → req.rbac
```

- The old `/api/*` rewrite in `next.config.js` was **removed** — a rewrite
  cannot attach per-request session headers. `/api/auth/*` is still served by
  the more-specific next-auth route.
- The API is internal-only (port 3005, never firewalled open), so the proxy is
  the sole trusted caller of those headers.

> **No `next.config.js` rewrite for `/api/*`.** The authenticated proxy route
> at `frontend/src/app/api/[...path]/route.ts` is the *only* path browser API
> calls take to Express — it reads the session server-side, forwards
> `X-User-Id` + `X-User-Role` to `http://localhost:3005`, and relays the
> upstream status (so e.g. a `402` license response passes through). New API
> endpoints work automatically; do **not** re-add an `/api/*` rewrite.

### `api/rbac.js`

- `rbacMiddleware` — sets `req.rbac = { userId, role, isSuperAdmin, isAdmin, allowedSiteIds }`.
  `allowedSiteIds` is `null` for admins (no filter), `[]` for a user with no
  sites (sees nothing), or an array of site IDs. User→site lookups are cached 5 min.
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
- Applied to: `/api/logs`, `/api/logs/export`, `/api/stats/summary`,
  `/api/stats/timeline`, `/api/stats/top-talkers`, `/api/stats/top-blocked`,
  `/api/stats/top-failures`, `/api/stats/top-security-events`,
  `/api/alerts/events` (filtered by `ae.source_ip`).

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

## next.config.js — API Proxy

The frontend proxies all `/api/*` requests to the Express API on port 3005. This is why port 3005 does not need to be open in the firewall.

```javascript
async rewrites() {
  return [
    { source: '/api/:path*', destination: 'http://localhost:3005/api/:path*' }
  ];
}
```

If this rewrite is missing, all API calls return 404.

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
| TypeScript in `.js` files | Never use type annotations in server/collector JS files |
| `${hours}` in SQL | Use `make_interval(hours => $1)` |
| Same `$1` twice in query | Use JOIN not nested subquery |
| Wide-open CORS | Restrict to `localhost:3004` |
| Stack traces to client | Always return generic `Internal server error` |
| `any` types unchecked | Define proper interfaces in TypeScript |
| `.env.local` not at runtime | Set vars in NSSM `AppEnvironmentExtra` |
| Next.js API 404 | Add rewrites in `next.config.js` |
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

## Pending / Planned

| Feature | Priority |
|---|---|
| Top talkers showing device names from NetVault | Next up |
| Compliance reports (PCI-DSS, ISO 27001) | Medium |
| Dashboard customization | Low |

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
