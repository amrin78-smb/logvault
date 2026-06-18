# LogVault — Claude Development Guide

## What is LogVault

LogVault is a syslog analyzer and log management platform, part of the **NocVault Network Intelligence Suite**. It collects syslog from network devices (Fortinet, Cisco, Palo Alto, Aruba, Sangfor, Forcepoint, Check Point, Juniper, Windows, SonicWall), parses and stores them in PostgreSQL, and provides a real-time dashboard, log explorer, alerting, universal event taxonomy, risk scoring, and asset enrichment via NetVault integration.

**Live deployment:** `http://192.168.6.111:3004`  
**GitHub repo:** `https://github.com/amrin78-smb/logvault`  
**Primary customer:** Thai Union Group — ~2,500 network devices across APAC, EMEA, NAM

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
1. Make ALL changes in GitHub Codespaces
2. Upload files to temp/ folder in Codespaces if coming from Claude chat
3. Copy files to correct paths: cp temp/file.tsx frontend/src/components/file.tsx
4. Run: cd frontend && npm run build  (verify no build errors)
5. If build passes: cd .. && git add -A
6. git commit -m "descriptive message"
7. git push origin main
8. On Windows Server: & "C:\Apps\logvault\installer\Update-LogVault.ps1" -InstallDir "C:\Apps\logvault"
```

**NEVER edit files directly on the Windows Server.**  
**NEVER commit broken code.**  
**ALWAYS fix build errors before committing.**

### temp/ folder
- Used to stage files uploaded from Claude chat to Codespaces
- Listed in `.gitignore` — never committed
- Copy pattern: `cp temp/filename destination/path`

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

### Connection details
```
Host:     localhost
Port:     5432
Database: logvault
User:     logvault_user
Password: NVAdmin@2026
```

### NetVault DB (read-only, for SSO + asset sync)
```
Database: netvault
User:     netvault
Password: PgAdmin@2026!
```

### Run psql commands
```powershell
$env:PGPASSWORD = "PgAdmin@2026!"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -d logvault -c "YOUR SQL HERE"
```

### Schema rules — CRITICAL
- `scripts/schema.sql` is the **single source of truth**
- Every `ALTER TABLE`, `CREATE TABLE`, `CREATE INDEX` run manually on the server **MUST** also be added to `schema.sql`
- Use `IF NOT EXISTS` everywhere — schema must be idempotent (safe to run multiple times)
- New `app_settings` keys must use: `INSERT INTO app_settings (key, value) VALUES ('key', 'default') ON CONFLICT (key) DO NOTHING;`
- After any manual schema change on server, immediately update `schema.sql` in Codespaces and commit

### Tables
```sql
syslog_entries    -- All log entries (main table, grows large)
                  --   includes category TEXT + risk_score SMALLINT columns
alert_rules       -- Alert rule definitions
alert_events      -- Fired alert instances
known_hosts       -- IP → hostname/vendor/site mapping
app_settings      -- Key/value app configuration
```

`syslog_entries.category` holds the universal taxonomy value (authentication, vpn,
firewall, interface, routing, configuration, security, wireless, system, dns, web,
email, dlp, network). `syslog_entries.risk_score` is a 0-100 score from
`collector/riskScorer.js`. Both are written by the collector and indexed.

### Permissions — fresh install requirement
```sql
GRANT ALL ON ALL TABLES IN SCHEMA public TO logvault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO logvault_user;
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
LV_DB_PASS=NVAdmin@2026
NETVAULT_DB_HOST=localhost
NETVAULT_DB_PORT=5432
NETVAULT_DB_NAME=netvault
NETVAULT_DB_USER=netvault
NETVAULT_DB_PASS=PgAdmin@2026!
```

**LogVault-API:**
```
NODE_ENV=production
DB_HOST=localhost
DB_PORT=5432
LV_DB_NAME=logvault
LV_DB_USER=logvault_user
LV_DB_PASS=NVAdmin@2026
LV_APP_URL=http://192.168.6.111:3004
NOCVAULT_HUB_URL=http://192.168.6.111:3000
NETVAULT_DB_HOST=localhost
NETVAULT_DB_PORT=5432
NETVAULT_DB_NAME=netvault
NETVAULT_DB_USER=netvault
NETVAULT_DB_PASS=PgAdmin@2026!
```

> `NOCVAULT_HUB_URL` lets the API reach the NocVault hub for license enforcement
> (`api/licenseCheck.js` → `GET {hub}/api/license`). If unset, it falls back to
> `http://localhost:3000`, which only works when the hub is on the same server.

**LogVault-App:**
```
NODE_ENV=production
NEXTAUTH_URL=http://192.168.6.111:3004
NEXTAUTH_SECRET=bue3VdWszntJ24GMhfKg1QkPIEaZYC95
NOCVAULT_HUB_URL=http://192.168.6.111:3000
NEXT_PUBLIC_NOCVAULT_HUB_URL=http://192.168.6.111:3000
NETVAULT_DB_HOST=localhost
NETVAULT_DB_PORT=5432
NETVAULT_DB_NAME=netvault
NETVAULT_DB_USER=netvault
NETVAULT_DB_PASS=PgAdmin@2026!
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

**Shared secret:** `bue3VdWszntJ24GMhfKg1QkPIEaZYC95`

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
- **Exception:** the severity (`SEV_COLORS`) and vendor (`VENDOR_COLORS`) palettes in
  `LogExplorer.tsx` / `LogDetailPanel.tsx` (and chart series color arrays / status-badge
  color pairs) are intentional semantic palettes with no matching token — leave them.
- This is the **NocVault SUITE-WIDE standard**: the same scale and `--font-mono` token are
  used in **spanvault, ddivault, and netvault**. Keep them in sync.

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
Rules match on: severity array, vendor array, host pattern (ILIKE), message regex pattern, threshold count + window

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
$env:PGPASSWORD = "NVAdmin@2026"
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

## Pending / Planned

| Feature | Priority |
|---|---|
| MITRE ATT&CK mapping on alerts | Medium |
| Compliance reports (PCI-DSS, ISO 27001) | Medium |
| Top talkers showing device names from NetVault | Next up |
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
