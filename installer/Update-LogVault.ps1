# ============================================================
# LogVault Update Script
# NocVault Product Family
# Usage: .\Update-LogVault.ps1 [-InstallDir "C:\Apps\logvault"]
# Must be run as Administrator
# ============================================================

param(
  [string]$InstallDir = "C:\Apps\logvault",
  [string]$ServerIp   = ""
)

# The scheduled task runs as SYSTEM, which has a minimal PATH that does not
# include git/node/npm. Without this, "git fetch/reset" silently exits 0 with
# no binary found and the update "succeeds" with old code (and npm install/build
# no-op). Prepend the standard install locations so the toolchain resolves under
# SYSTEM. (Services are controlled via sc.exe, which is PATH-independent.)
$env:PATH = @(
    "C:\Program Files\Git\cmd",
    "C:\Program Files\Git\bin",
    "C:\Program Files\nodejs",
    "C:\Program Files\npm",
    $env:PATH
) -join ";"

# Windows Task Scheduler's default task priority (level 7) maps to the BelowNormal
# process priority class, unlike a manually-run script (Normal). This starves the
# CPU-bound npm install/build under contention from the rest of the suite, making
# an in-app-triggered update (Settings -> Updates, which schedules this as a SYSTEM
# task - see api/server.js's POST /api/system/update) look "stuck" compared to the
# same update run manually from an interactive PowerShell window. Reset to Normal
# regardless of how this script was invoked - a no-op when already Normal (the
# manual-run case). Child processes inherit the parent's priority class by default,
# so this also covers the npm/node/next child processes it spawns.
# (Same fix as NetVault's Update-NetVault.ps1 1.23.26 / DDIVault's Update-DDIVault.ps1.)
try {
    $proc = Get-Process -Id $PID
    $originalPriority = $proc.PriorityClass
    if ($originalPriority -ne 'Normal') {
        $proc.PriorityClass = 'Normal'
        Write-Host "Adjusted process priority to Normal (was $originalPriority)"
    }
} catch { Write-Warning "Could not adjust process priority: $($_.Exception.Message)" }

# Self-locate the app root. This script lives at <appRoot>\installer\Update-LogVault.ps1,
# so the real app root is the PARENT of the script's own folder. This is correct on BOTH
# the suite install (C:\Apps\LogVault\app) and a standalone install (C:\Apps\logvault),
# regardless of what -InstallDir is (or isn't) passed. The -InstallDir param is kept for
# backward-compat but NO LONGER drives any path - self-location always wins, so the updater
# can never Set-Location to a non-repo parent dir and leave services down.
# Resolve a path to its TRUE on-disk casing (walking each parent for the real component
# name). Get-Item().FullName only echoes the TYPED casing, which is not enough here.
function Get-TrueCasePath([string]$p) {
    try {
        $di = New-Object System.IO.DirectoryInfo([System.IO.Path]::GetFullPath($p))
        $parts = @()
        while ($null -ne $di.Parent) {
            $m = $di.Parent.GetFileSystemInfos($di.Name)
            if ($m.Count -eq 0) { return [System.IO.Path]::GetFullPath($p) }
            $parts = ,($m[0].Name) + $parts; $di = $di.Parent
        }
        $root = $di.Name; if (-not $root.EndsWith('\')) { $root += '\' }
        return $root + ($parts -join '\')
    } catch { return $p }
}
$AppDir      = Split-Path -Parent $PSScriptRoot
# Normalize the build directory to its true on-disk casing. `next build` caches absolute
# module paths in .next; if a later run's cwd casing differs (e.g. C:\Apps\LogVault vs
# ...\logvault, depending on how the invocation path was typed), webpack treats the two
# casings as different modules and loads React twice -> the build crashes with "Cannot read
# properties of null (reading 'useContext')". Pinning to on-disk casing makes it stable.
$AppDir      = Get-TrueCasePath $AppDir
$FrontendDir = "$AppDir\frontend"
$LogDir      = "$AppDir\logs"
$Services    = @("LogVault-Collector", "LogVault-API", "LogVault-App")

# The in-app updater (Settings -> Updates) is fire-and-forget: api/server.js schedules
# this script as a SYSTEM scheduled task (schtasks /create ... /ru SYSTEM, then
# schtasks /run) and immediately returns { started: true } to the browser, with no
# live output stream. Without a transcript, a run triggered that way leaves NO
# durable record of what happened - update.log below only captures a handful of
# milestone lines (start/fail/complete), not the full Write-Step/Write-OK/Write-Err
# narrative. Start it as early as possible (before the Admin pre-flight check) so
# even an early failure is captured. Best-effort: a transcript that fails to start
# (e.g. one is already open in this session) must never block the actual update.
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}
$transcriptPath = "$LogDir\update-transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch { Write-Warning "Could not start transcript: $($_.Exception.Message)" }

# Helper functions
function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "    [XX] $msg" -ForegroundColor Red }

function Get-ServiceStatus($name) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { return "NOT_FOUND" }
    return $svc.Status.ToString().ToUpper()
}

# psql is often not on PATH on Windows. Resolve it from PATH, then fall back to the
# standard PostgreSQL install locations (newest version first). Returns $null if not
# found - the schema step treats psql as optional (warn + skip, never fail).
function Resolve-Psql {
    $cmd = Get-Command psql -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $roots = @('C:\Program Files\PostgreSQL', 'C:\Program Files (x86)\PostgreSQL')
    $found = Get-ChildItem -Path $roots -Filter 'psql.exe' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

# --- Resilience: rollback + structured status reporting -------------------
# LogVault has no `output: 'standalone'` build - LogVault-App runs `next start`
# directly against a plain `frontend\.next`, sharing the app's normal node_modules
# (root for the API/Collector, `frontend\node_modules` for the Next.js app). A
# rollback here has to protect THREE things: the git source, root node_modules
# (the API/Collector are plain JS with no build step - a broken npm install can
# break them directly), and both `frontend\.next` and `frontend\node_modules` (the
# Next.js build output + its deps). Renaming is a metadata-only operation on the
# same NTFS volume regardless of directory size, so snapshotting all three this way
# is cheap. (Same shape as DDIVault's Update-DDIVault.ps1 - the closest structural
# match in the suite, since LogVault is also a non-standalone Next.js build.)
$StatusPath           = "$LogDir\last-update-status.json"
$prevCommit           = $null
$attemptedCommit      = $null
$currentStage         = 'init'
$envBackupForRollback = $null  # set once the .env.local backup step below has run

$StageCodes = @{
    'init'                 = 5
    'pre-flight'           = 10
    'git-pull'             = 20
    'schema-apply'         = 25
    'npm-install-root'     = 30
    'npm-install-frontend' = 35
    'npm-build'            = 40
    'service-start'        = 50
    'health-check'         = 60
    'rollback-failed'      = 70
}

function Write-StatusJson {
    param(
        [bool]$Success,
        [string]$Stage,
        [int]$ErrorCode = 0,
        [string]$ErrorMessage = $null,
        [bool]$RolledBack = $false,
        [bool]$HealthCheckPassed = $false
    )
    $status = [ordered]@{
        timestamp         = (Get-Date).ToString('o')
        success           = $Success
        stage             = $Stage
        errorCode         = $ErrorCode
        errorMessage      = $ErrorMessage
        previousCommit    = $prevCommit
        attemptedCommit   = $attemptedCommit
        finalCommit       = if ($RolledBack) { $prevCommit } else { $attemptedCommit }
        rolledBack        = $RolledBack
        healthCheckPassed = $HealthCheckPassed
    }
    try {
        $json = $status | ConvertTo-Json
        # Write via .NET directly with a BOM-less UTF8Encoding, not Out-File
        # -Encoding UTF8 (which writes a UTF-8 BOM in Windows PowerShell 5.1) -
        # Node's fs.readFileSync(path, 'utf8') doesn't strip a BOM, which would
        # break JSON.parse on every single write. (Same bug found and fixed in
        # NetVault's Update-NetVault.ps1 1.23.27 / DDIVault's Update-DDIVault.ps1 -
        # fixed here from the start.)
        # Write to a PID-suffixed temp file in the SAME directory, then
        # Move-Item -Force onto the real path. Writing directly to $StatusPath
        # meant a crash/kill mid-write (or two overlapping runs racing each
        # other) could leave a truncated/corrupt JSON file behind - the API's
        # /api/system/last-update-status route would then either 500 or show a
        # stale/garbled result instead of a clean prior-or-current status. The
        # rename is a same-volume metadata-only operation, so this adds no
        # meaningful cost.
        $tempStatusPath = "$StatusPath.$PID.tmp"
        [System.IO.File]::WriteAllText($tempStatusPath, $json, (New-Object System.Text.UTF8Encoding $false))
        Move-Item -Path $tempStatusPath -Destination $StatusPath -Force
    } catch {
        Write-Warn "Could not write status file $StatusPath - $($_.Exception.Message)"
    }
}

# Poll the API's /api/health until it reports ok, or $TimeoutSec elapses. LogVault's
# /api/health returns {status:'ok', version, logs_last_hour} - there is no separate
# 'db' field to check (unlike DDIVault), since the query itself would throw and 500
# if the DB were unreachable.
function Wait-Healthy([int]$TimeoutSec = 60) {
    Write-Host "    Waiting for LogVault API to respond on :3005 " -ForegroundColor Gray -NoNewline
    $healthy = $false
    for ($i = 0; $i -lt $TimeoutSec; $i++) {
        try {
            # 127.0.0.1 (not localhost): on Windows localhost resolves to IPv6 ::1
            # first, which the server may not answer, making the poll time out
            # while the app is actually up.
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:3005/api/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            $body = $resp.Content | ConvertFrom-Json
            if ($resp.StatusCode -eq 200 -and $body.status -eq 'ok') { $healthy = $true; break }
        } catch {}
        Write-Host "." -ForegroundColor DarkGray -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host ""
    return $healthy
}

# Revert to the pre-update commit + restore the node_modules/.next snapshots,
# restart all 3 services (Collector -> API -> App, the documented startup order),
# and confirm the OLD version is actually healthy before declaring the rollback
# itself successful.
#
# Note on database migrations: this rolls back CODE, not schema. The schema-apply
# step below still refuses to deploy new code against a database it failed to
# migrate (schema.sql is not applied inside a single transaction, so a code-level
# rollback cannot undo a partially-applied schema) - but a schema failure now
# triggers this same rollback instead of leaving the app down entirely, since the
# old code is far more likely to tolerate a few extra/partial columns than LogVault
# is to tolerate being completely offline. (Same reasoning as DDIVault's schema-apply
# step - see its own comment.)
function Invoke-Rollback([string]$Reason) {
    Write-Host ""
    Write-Step "ROLLING BACK - reason: $Reason"
    $ok = $true
    try {
        # Stop services BEFORE touching node_modules/.next below. Step 7 already
        # started all 3 services by the time a failure can trigger this function,
        # so without this, the restore's Remove-Item/Rename-Item would be mutating
        # a directory tree while LogVault-API/-Collector are still live and
        # actively require()-ing from it - a real race that produced exactly this
        # symptom in production: the restore reported success, but the resulting
        # node_modules ended up with only a handful of packages (Collector then
        # crash-looped on "Cannot find module 'nodemailer'"). Mirrors the safe
        # order the main update flow already uses (Step 1 stops services before
        # Step 5/6 ever touch node_modules/.next).
        Write-Step "Stopping services before restoring last known-good version"
        # Always issue the stop, regardless of sampled status - a service that
        # isn't currently "RUNNING" isn't necessarily fully stopped (crash-loop,
        # START_PENDING/STOP_PENDING, or NSSM's own PAUSED throttle state after
        # repeated rapid restarts all leave its auto-restart armed and can be
        # sampled in any of these transient states). The main flow's Step 1
        # already stops unconditionally; this rollback copy previously only
        # stopped a service sampled as exactly "RUNNING", which could skip a
        # crash-looping service and leave it eligible for NSSM auto-restart
        # exactly while the restore below mutates files underneath it. Same
        # fix already applied in DDIVault's Update-DDIVault.ps1 (its own
        # Invoke-Rollback's Step 1-equivalent).
        foreach ($svc in @("LogVault-App", "LogVault-API", "LogVault-Collector")) {
            if ((Get-ServiceStatus $svc) -ne "NOT_FOUND") { sc.exe stop $svc | Out-Null }
        }
        Start-Sleep -Seconds 5
        # sc.exe stop is asynchronous - it can return before the process has
        # actually exited, which is exactly the class of race this whole
        # function exists to close. Mirrors Step 1's own port-based force-kill
        # fallback (this function previously only did the flat sleep, weaker
        # than Step 1's own stop sequence for the identical hazard).
        # Includes 514/1514 (LogVault-Collector, TCP+UDP) alongside 3004/3005
        # (App/API) - this is the EXACT mechanism of the original production
        # incident: the Collector kept running against a node_modules
        # directory being renamed/restored underneath it (below) because only
        # the App/API ports were ever checked here. See Step 1's identical
        # comment for why `netstat -ano`'s combined TCP+UDP listing needs no
        # extra parsing to cover the Collector's UDP sockets too.
        foreach ($port in @(3004, 3005, 514, 1514)) {
            $lines = netstat -ano 2>$null | Select-String ":$port\s"
            foreach ($line in $lines) {
                $parts = ($line -split '\s+') | Where-Object { $_ -ne '' }
                $pid2 = $parts[-1]
                if ($pid2 -match '^\d+$') {
                    $proc = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
                    if ($proc -and $proc.Name -eq 'node') {
                        Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
                        Write-Warn "Killed lingering node PID $pid2 on port $port before restore"
                    }
                }
            }
        }

        Set-Location $AppDir
        $sourceReverted = $false
        if ($prevCommit) {
            Write-Host "    Reverting source to $prevCommit" -ForegroundColor Gray
            $null = git reset --hard $prevCommit 2>&1
            if ($LASTEXITCODE -eq 0) { Write-OK "Source reverted"; $sourceReverted = $true }
            else { Write-Warn "git reset during rollback failed (exit $LASTEXITCODE)"; $ok = $false }
        } else {
            Write-Warn "No pre-update commit recorded - skipping source revert"
            $ok = $false
        }

        # Do NOT proceed to restore node_modules/.next or restart services if the
        # source itself could not be reverted (prevCommit was never captured, or
        # `git reset --hard` failed). Continuing past this point would restore the
        # OLD node_modules/.next on top of whatever source is currently checked
        # out - which, if the git reset failed partway or never ran, could still
        # be the NEW (broken) code - then start services against that hybrid.
        # That reproduces the exact "new code, old deps" crash shape this whole
        # rollback exists to prevent, just triggered from inside the rollback
        # itself. Short-circuit here instead and report the clearest possible
        # failure state - this is a genuine can't-safely-continue condition, not
        # a soft warning like a missing node_modules/.next snapshot below.
        if (-not $sourceReverted) {
            Write-Err "Source could not be reverted - the update's broken code and OLD dependencies would otherwise both be in place; skipped starting services against that combination - MANUAL INTERVENTION REQUIRED."
            return $false
        }

        $rootModulesBackup     = "$AppDir\node_modules.lastgood"
        $frontendNextBackup    = "$FrontendDir\.next.lastgood"
        $frontendModulesBackup = "$FrontendDir\node_modules.lastgood"

        if (Test-Path $rootModulesBackup) {
            if (Test-Path "$AppDir\node_modules") { Remove-Item "$AppDir\node_modules" -Recurse -Force -ErrorAction SilentlyContinue }
            Rename-Item -Path $rootModulesBackup -NewName 'node_modules' -ErrorAction Stop
            Write-OK "Restored root node_modules"
        } else {
            Write-Warn "No root node_modules snapshot found to restore"
            $ok = $false
        }
        if (Test-Path $frontendNextBackup) {
            if (Test-Path "$FrontendDir\.next") { Remove-Item "$FrontendDir\.next" -Recurse -Force -ErrorAction SilentlyContinue }
            Rename-Item -Path $frontendNextBackup -NewName '.next' -ErrorAction Stop
            Write-OK "Restored frontend .next build output"
        } else {
            Write-Warn "No frontend .next snapshot found to restore"
            $ok = $false
        }
        if (Test-Path $frontendModulesBackup) {
            if (Test-Path "$FrontendDir\node_modules") { Remove-Item "$FrontendDir\node_modules" -Recurse -Force -ErrorAction SilentlyContinue }
            Rename-Item -Path $frontendModulesBackup -NewName 'node_modules' -ErrorAction Stop
            Write-OK "Restored frontend node_modules"
        } else {
            Write-Warn "No frontend node_modules snapshot found to restore"
            $ok = $false
        }

        if ($envBackupForRollback) {
            # Deliberate choice (not an accidental gap): if a .env.local did NOT
            # exist pre-update (no backup was captured), but one exists now -
            # created or modified by the failed update attempt - remove it so
            # rollback fully restores the pre-update state rather than leaving
            # a new file behind that the running (reverted) code never expected.
            if ($null -ne $envBackupForRollback.Root) {
                Set-Content -Path "$AppDir\.env.local" -Value $envBackupForRollback.Root -NoNewline
            } elseif (Test-Path "$AppDir\.env.local") {
                Remove-Item "$AppDir\.env.local" -Force -ErrorAction SilentlyContinue
                Write-Warn "Removed root .env.local created during the failed update (none existed before it)"
            }
            if ($null -ne $envBackupForRollback.Frontend) {
                Set-Content -Path "$FrontendDir\.env.local" -Value $envBackupForRollback.Frontend -NoNewline
            } elseif (Test-Path "$FrontendDir\.env.local") {
                Remove-Item "$FrontendDir\.env.local" -Force -ErrorAction SilentlyContinue
                Write-Warn "Removed frontend .env.local created during the failed update (none existed before it)"
            }
        }

        Write-Step "Restarting services on last known-good version"
        sc.exe start LogVault-Collector | Out-Null
        Start-Sleep -Seconds 3
        sc.exe start LogVault-API | Out-Null
        Start-Sleep -Seconds 3
        sc.exe start LogVault-App | Out-Null
        Start-Sleep -Seconds 5

        # Informational only - same reasoning as the main flow's health-check gate
        # above: SCM's STARTPENDING -> RUNNING transition can lag several seconds
        # behind the process actually serving traffic, and letting that alone fail
        # the rollback (even when Wait-Healthy passes right after) produced the
        # exact "Rollback verified... healthy" immediately followed by "ROLLBACK
        # ALSO FAILED" contradiction seen in production. Poll briefly for a clean
        # status line, but only $healthy below decides the return value.
        foreach ($svc in $Services) {
            $status = 'UNKNOWN'
            for ($i = 0; $i -lt 30; $i++) {
                $status = Get-ServiceStatus $svc
                if ($status -eq "RUNNING") { break }
                Start-Sleep -Seconds 1
            }
            if ($status -ne "RUNNING") { Write-Warn "$svc - $status (SCM status can lag - health check below is authoritative)" }
        }

        # Same 60s budget as the main flow's own health check below, not a
        # shorter one - rollback does NOT skip npm install/build (it restores
        # pre-built node_modules/.next from the snapshot instead of rebuilding),
        # but the actual bottleneck Wait-Healthy is timing is service cold-start
        # (Collector DB connection, Next.js `next start` boot), which is just as
        # slow-but-fine here as on a fresh build. A shorter budget here risked
        # misreporting a genuinely healthy-but-slow rollback as "rollback also
        # failed" purely from a tighter timeout, not an actual problem.
        $healthy = Wait-Healthy -TimeoutSec 60
        if ($healthy) { Write-OK "Rollback verified - last known-good version is up and healthy" }
        else { Write-Warn "Rollback restart did not pass the health check"; $ok = $false }
        return ($ok -and $healthy)
    } catch {
        Write-Warn "Rollback itself failed: $($_.Exception.Message)"
        return $false
    }
}

# Every failure path in this script funnels through here instead of a bare
# `exit 1`, so a failure always attempts recovery and always leaves a structured
# record behind - see the resilience block above.
function Fail-Update {
    param([string]$Stage, [string]$Message)
    $code = if ($StageCodes.ContainsKey($Stage)) { $StageCodes[$Stage] } else { 99 }
    Write-Host ""
    Write-Err "Update failed at stage '$Stage': $Message"
    $rollbackOk = Invoke-Rollback -Reason $Message
    if (-not $rollbackOk) {
        Write-Err "!!! ROLLBACK ALSO FAILED - LogVault may be DOWN. Manual intervention required. !!!"
        $code = $StageCodes['rollback-failed']
    }
    Write-StatusJson -Success $false -Stage $Stage -ErrorCode $code -ErrorMessage $Message -RolledBack $rollbackOk -HealthCheckPassed $rollbackOk
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "$LogDir\update.log" -Value "[$ts] FAILED at stage '$Stage': $Message (rolledBack=$rollbackOk)"
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}

# Header
Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkGray
Write-Host "  LogVault Update Script" -ForegroundColor White
Write-Host "  NocVault Product Family" -ForegroundColor DarkGray
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  ================================================" -ForegroundColor DarkGray
Write-Host ""

# Check Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator"
    exit 1
}

# --- Concurrency guard ------------------------------------------------------
# Refuse to run if another update is already in flight - a manual on-server run
# (interactive PowerShell) can race an in-app-triggered SYSTEM scheduled task
# (api/server.js's POST /api/system/update) hitting the exact same git working
# tree / node_modules / .next files at the same time; each assumes it has
# exclusive ownership of the working tree, so two overlapping runs corrupt
# each other's snapshot/restore state. Guarded with a PID-stamped lock file; a
# lock whose recorded PID is no longer a running process is stale (a previous
# run crashed or was killed without cleaning up) and is safely reclaimed
# rather than wedging every future update forever.
$LockPath = "$LogDir\update.lock"
if (Test-Path $LockPath) {
    $rawLockPid = $null
    try { $rawLockPid = (Get-Content -Path $LockPath -Raw -ErrorAction Stop).Trim().TrimStart([char]0xFEFF) } catch {}
    $lockedPid    = 0
    $stillRunning = $false
    if ($rawLockPid -match '^\d+$') {
        $lockedPid = [int]$rawLockPid
        if (Get-Process -Id $lockedPid -ErrorAction SilentlyContinue) { $stillRunning = $true }
    }
    if ($stillRunning) {
        Write-Err "Another update is already running (PID $lockedPid) - exiting. Wait for it to finish, or check $LogDir\update.log."
        Add-Content -Path "$LogDir\update.log" -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Refused to start - another update is already running (PID $lockedPid)"
        try { Stop-Transcript | Out-Null } catch {}
        exit 1
    } else {
        Write-Warn "Found a stale lock file (recorded PID $rawLockPid is not running) - reclaiming it"
    }
}
# Best-effort: if the lock file can't be written (e.g. a permissions issue),
# continue WITHOUT the guard rather than blocking a legitimate update - same
# "never let a resilience mechanism itself block the real update" spirit as
# the transcript/priority-adjustment steps above.
$lockAcquired = $false
try {
    [System.IO.File]::WriteAllText($LockPath, "$PID", (New-Object System.Text.UTF8Encoding $false))
    $lockAcquired = $true
} catch {
    Write-Warn "Could not write lock file $LockPath - continuing without a concurrency guard: $($_.Exception.Message)"
}

# Everything from here on runs with the lock held (if acquired above) - wrapped
# in try/finally so the lock is released even when a stage fails and Fail-Update
# calls `exit 1` (PowerShell unwinds through enclosing finally blocks on exit,
# same as a normal return).
try {

# Brief delay so the API can return its response before services are stopped
Write-Host "=== Update starting in 5 seconds ===" -ForegroundColor Cyan
Start-Sleep -Seconds 5

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update started"

# Step 1: Stop services
Write-Step "Stopping LogVault services"

sc.exe stop LogVault-App       | Out-Null
sc.exe stop LogVault-API       | Out-Null
sc.exe stop LogVault-Collector | Out-Null

Write-Host "    Waiting for services to stop..." -ForegroundColor DarkGray
Start-Sleep -Seconds 5

# Kill any remaining node processes on our ports. Includes 514/1514
# (LogVault-Collector, TCP+UDP) as well as 3004/3005 (App/API) - `sc.exe stop`
# is asynchronous and can return before the process has actually exited (see
# Invoke-Rollback's own copy of this loop, above, for the production incident
# this closes: the Collector kept running against a node_modules directory
# being renamed/restored underneath it because only 3004/3005 were ever
# checked here).
# `netstat -ano` with no `-p` filter lists BOTH TCP and UDP sockets in one
# call - a UDP line just has no "State" column, so `($line -split '\s+')`
# still yields the PID as the LAST token either way (e.g. TCP:
# "TCP 0.0.0.0:1514 0.0.0.0:0 LISTENING 4521", UDP: "UDP 0.0.0.0:1514 *:* 4521"
# - both end in the PID), so this loop needs no extra protocol-specific parsing
# to cover the Collector's UDP listeners too.
$ports = @(3004, 3005, 514, 1514)
foreach ($port in $ports) {
    $lines = netstat -ano 2>$null | Select-String ":$port\s"
    foreach ($line in $lines) {
        $parts = ($line -split '\s+') | Where-Object { $_ -ne '' }
        $pid2 = $parts[-1]
        if ($pid2 -match '^\d+$') {
            $proc = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
            if ($proc -and $proc.Name -eq 'node') {
                Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
                Write-Warn "Killed node PID $pid2 on port $port"
            }
        }
    }
}

Write-OK "Services stopped"

# Step 2: Backup .env.local
Write-Step "Backing up .env.local files"

$envRoot     = $null
$envFrontend = $null

$rootEnvPath     = "$AppDir\.env.local"
$frontendEnvPath = "$FrontendDir\.env.local"

if (Test-Path $rootEnvPath) {
    $envRoot = Get-Content -Path $rootEnvPath -Raw
    Write-OK "Backed up $rootEnvPath"
} else {
    Write-Warn "No .env.local at $rootEnvPath"
}

if (Test-Path $frontendEnvPath) {
    $envFrontend = Get-Content -Path $frontendEnvPath -Raw
    Write-OK "Backed up $frontendEnvPath"
} else {
    Write-Warn "No .env.local at $frontendEnvPath"
}
$envBackupForRollback = @{ Root = $envRoot; Frontend = $envFrontend }

# Ensure git safe.directory is set for SYSTEM account. Derive it from the self-located
# $AppDir (git wants forward slashes) so it matches the REAL repo on any layout - a
# hardcoded C:/Apps/logvault would not cover the suite install at C:\Apps\LogVault\app.
$gitSafeDir = $AppDir -replace '\\', '/'
try {
    $null = git config --global --add safe.directory $gitSafeDir 2>&1
} catch {}

# Step 2.5: Snapshot current version for rollback
# Must happen BEFORE git touches anything and BEFORE npm install/build overwrites
# node_modules/.next, so a failure anywhere from here on can be undone by putting
# these exact folders back rather than needing to rebuild (which could itself fail
# for the same reason the original update did).
Write-Step "Snapshotting current version for rollback"
$currentStage = 'pre-flight'
Set-Location $AppDir
$rp = git rev-parse HEAD 2>&1
if ($rp -match '^[0-9a-f]{40}$') { $prevCommit = $rp }
if ($prevCommit) { Write-OK "Current commit: $prevCommit" }
else { Write-Warn "Could not determine current commit - rollback will not be able to revert source" }

$rootModulesBackup     = "$AppDir\node_modules.lastgood"
$frontendNextBackup    = "$FrontendDir\.next.lastgood"
$frontendModulesBackup = "$FrontendDir\node_modules.lastgood"
# Clear any stale backups left by a prior interrupted run before snapshotting the
# CURRENTLY-serving version, not an older leftover one.
foreach ($stale in @($rootModulesBackup, $frontendNextBackup, $frontendModulesBackup)) {
    if (Test-Path $stale) { Remove-Item $stale -Recurse -Force -ErrorAction SilentlyContinue }
}
# Each rename is verified by checking the destination actually exists
# afterward, and a genuine failure is routed through Fail-Update (same
# failure-handling every other stage uses) instead of the previous
# `-ErrorAction SilentlyContinue` + unconditional "Snapshotted ..." message,
# which made a failed rename (a locked file, a permissions issue) completely
# invisible - the script believed it snapshotted successfully when it hadn't,
# poisoning any LATER rollback attempt (nothing to actually restore from).
# Mirrors DDIVault's Update-DDIVault.ps1 (try/-ErrorAction Stop routed through
# Fail-Update); the post-rename Test-Path re-check additionally guards the
# pathological case where Rename-Item reports success but the destination
# still doesn't exist, mirroring SpanVault's Update-SpanVault.ps1 verification.
try {
    if (Test-Path "$AppDir\node_modules") {
        Rename-Item -Path "$AppDir\node_modules" -NewName 'node_modules.lastgood' -ErrorAction Stop
        if (-not (Test-Path $rootModulesBackup)) { throw "root node_modules rename reported success but $rootModulesBackup does not exist" }
        Write-OK "Snapshotted root node_modules"
    }
    if (Test-Path "$FrontendDir\.next") {
        Rename-Item -Path "$FrontendDir\.next" -NewName '.next.lastgood' -ErrorAction Stop
        if (-not (Test-Path $frontendNextBackup)) { throw "frontend .next rename reported success but $frontendNextBackup does not exist" }
        Write-OK "Snapshotted frontend .next build output"
    }
    if (Test-Path "$FrontendDir\node_modules") {
        Rename-Item -Path "$FrontendDir\node_modules" -NewName 'node_modules.lastgood' -ErrorAction Stop
        if (-not (Test-Path $frontendModulesBackup)) { throw "frontend node_modules rename reported success but $frontendModulesBackup does not exist" }
        Write-OK "Snapshotted frontend node_modules"
    }
} catch {
    Fail-Update -Stage 'pre-flight' -Message "Snapshotting current version failed: $($_.Exception.Message)"
}

# Step 3: Pull latest from GitHub
Write-Step "Pulling latest code from GitHub"
$currentStage = 'git-pull'

Set-Location $AppDir

$fetchResult = git fetch origin 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail-Update -Stage 'git-pull' -Message "git fetch failed (exit $LASTEXITCODE): $fetchResult"
}

$resetResult = git reset --hard origin/main 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail-Update -Stage 'git-pull' -Message "git reset failed (exit $LASTEXITCODE): $resetResult"
}

git clean -fd --exclude=".env.local" --exclude="node_modules" --exclude="*.lastgood" 2>&1 | Out-Null

$commitHash = git rev-parse --short HEAD 2>&1
$rp = git rev-parse HEAD 2>&1
if ($rp -match '^[0-9a-f]{40}$') { $attemptedCommit = $rp }
Write-OK "Updated to commit: $commitHash"

# Step 4: Restore .env.local
Write-Step "Restoring .env.local files"

if ($null -ne $envRoot) {
    Set-Content -Path $rootEnvPath -Value $envRoot -NoNewline
    Write-OK "Restored $rootEnvPath"
}

if ($null -ne $envFrontend) {
    Set-Content -Path $frontendEnvPath -Value $envFrontend -NoNewline
    Write-OK "Restored $frontendEnvPath"
} elseif ($null -ne $envRoot) {
    Set-Content -Path $frontendEnvPath -Value $envRoot -NoNewline
    Write-OK "Synced root .env.local to frontend"
}

# Persist SERVER_IP (passed by the in-app updater) if not already present
if ($ServerIp -and (Test-Path $rootEnvPath) -and -not (Get-Content $rootEnvPath -Raw).Contains('SERVER_IP=')) {
    Add-Content -Path $rootEnvPath "`nSERVER_IP=$ServerIp"
    Add-Content -Path $frontendEnvPath "`nSERVER_IP=$ServerIp"
    Write-OK "Wrote SERVER_IP=$ServerIp to .env.local"
}

# Step 4.5: Apply database schema (idempotent) - mirrors the SpanVault pattern
Write-Step "Applying database schema"
$currentStage = 'schema-apply'

$psql   = Resolve-Psql
$schema = "$AppDir\scripts\schema.sql"
if ($psql -and (Test-Path $schema)) {
    # Connect as the 'postgres' superuser using POSTGRES_PASSWORD from .env.local.
    # Unlike spanvault/ddivault, LogVault's schema.sql CANNOT be applied as the app
    # user: it defines SECURITY DEFINER partition functions that must be OWNED BY
    # postgres, plus self-REVOKEs UPDATE/DELETE from logvault_user (the append-only
    # tamper-evidence model). Applying as logvault_user would break that ownership.
    # This applies scripts/schema.sql ONLY (idempotent). The Phase 3 partitioning
    # migration (scripts/migration-phase3-partitioning.sql) is destructive and must
    # still be run MANUALLY, in a maintenance window, with a pg_dump backup first.
    $envContent = if (Test-Path $rootEnvPath) { Get-Content $rootEnvPath -Raw } else { '' }
    $dbName = [regex]::Match($envContent, 'LV_DB_NAME=(.+)').Groups[1].Value.Trim()
    $pgPass = [regex]::Match($envContent, 'POSTGRES_PASSWORD=(.+)').Groups[1].Value.Trim()
    if (-not $dbName) { $dbName = 'logvault' }
    if ($pgPass) {
        $env:PGPASSWORD = $pgPass
        # --quiet suppresses NOTICE/INFO chatter psql writes to stderr (which would
        # otherwise raise NativeCommandError over WinRM); consume both streams and
        # gate success on $LASTEXITCODE.
        # -v ON_ERROR_STOP=1 (added 2026-07-23): without it, psql prints a genuine
        # SQL error (e.g. a typo'd column in a REVOKE/GRANT block) to stderr and
        # keeps going, then still exits 0 - so this step would report "[OK] Schema
        # applied" even though a statement failed and the DB was left half-migrated.
        # This is the exact failure mode that bit a sibling NocVault app's own
        # equivalent schema fix the same day this was added. schema.sql's own
        # idempotent statements (IF NOT EXISTS/IF EXISTS/OR REPLACE/ON CONFLICT) are
        # not errors on a re-apply, so this does not affect them - only a genuine SQL
        # error now surfaces as a real failure.
        try { $null = & $psql --quiet -U postgres -d $dbName -v ON_ERROR_STOP=1 -f $schema 2>&1 } catch {}
        $psqlExit = $LASTEXITCODE
        $env:PGPASSWORD = ''
        # psql over WinRM commonly returns -1 on a successful run, so treat -1 as 0.
        if ($psqlExit -eq 0 -or $psqlExit -eq -1) {
            Write-OK "Schema applied (as postgres to $dbName)"
        } else {
            # A real SQL error halted schema.sql partway through (ON_ERROR_STOP=1) -
            # refuse to deploy new code against a database it failed to migrate. This
            # rolls back CODE only; the database itself is left in whatever partial
            # state the failed statement produced (schema.sql is not applied inside a
            # single transaction, so a code-level rollback cannot undo that part).
            # Same reasoning DDIVault's Update-DDIVault.ps1 uses for its own
            # schema-apply failure path.
            Fail-Update -Stage 'schema-apply' -Message "psql exited with code $psqlExit applying scripts\schema.sql as postgres to $dbName - re-run manually and fix the reported statement before assuming the schema is current"
        }
    } else {
        Write-Warn "POSTGRES_PASSWORD not set in .env.local - skipping schema apply."
        Write-Warn "Add POSTGRES_PASSWORD to .env.local, or apply scripts\schema.sql manually as postgres."
    }
} else {
    Write-Warn "psql not found or schema.sql missing - skipping schema apply (run manually if needed)."
}

# Step 5: Install root dependencies
Write-Step "Installing root dependencies"
$currentStage = 'npm-install-root'

Set-Location $AppDir
npm install 2>&1 | Out-File -FilePath "$LogDir\npm-install-root.log" -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    # Root deps failing to install is exactly the class of failure the rollback
    # exists for - previously this was a bare exit 1 leaving services stopped on a
    # broken root node_modules with no recovery attempt.
    Fail-Update -Stage 'npm-install-root' -Message "npm install (root) failed (exit $LASTEXITCODE) - see $LogDir\npm-install-root.log"
}
Write-OK "Root dependencies installed"

# Step 6: Install frontend dependencies and build
Write-Step "Installing frontend dependencies"
$currentStage = 'npm-install-frontend'

Set-Location $FrontendDir
npm install 2>&1 | Out-File -FilePath "$LogDir\npm-install-frontend.log" -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Fail-Update -Stage 'npm-install-frontend' -Message "npm install (frontend) failed (exit $LASTEXITCODE) - see $LogDir\npm-install-frontend.log"
}
Write-OK "Frontend dependencies installed"

Write-Step "Building Next.js frontend"
$currentStage = 'npm-build'

$buildResult = npm run build 2>&1
$buildResult | Out-File -FilePath "$LogDir\npm-build.log" -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "Build FAILED"
    Write-Err "See: $LogDir\npm-build.log"
    Write-Host ""
    $buildResult | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    # Previously this warned "Services NOT restarted - previous build still
    # running" and stopped here - which was misleading on two counts: services
    # were stopped in Step 1 (nothing was "still running"), and there was no
    # recovery path at all. Fail-Update now actually restores the last-known-good
    # build output and restarts services on it.
    Fail-Update -Stage 'npm-build' -Message "npm run build failed (exit $LASTEXITCODE) - see $LogDir\npm-build.log"
}
Write-OK "Frontend built successfully"

# Step 7: Start services
Write-Step "Starting LogVault services"
$currentStage = 'service-start'

Set-Location $AppDir

sc.exe start LogVault-Collector | Out-Null
Write-Host "    Starting LogVault-Collector..." -ForegroundColor DarkGray
Start-Sleep -Seconds 3

sc.exe start LogVault-API | Out-Null
Write-Host "    Starting LogVault-API..." -ForegroundColor DarkGray
Start-Sleep -Seconds 3

sc.exe start LogVault-App | Out-Null
Write-Host "    Starting LogVault-App..." -ForegroundColor DarkGray
Start-Sleep -Seconds 5

Write-OK "Services started"

# Step 8: Verify (now a mandatory gate, not advisory)
Write-Step "Verifying service status"
$currentStage = 'health-check'

# Informational only - do NOT gate on this. SCM's STARTPENDING -> RUNNING
# transition can legitimately lag several seconds behind the underlying process
# actually being up and serving traffic (confirmed live: /api/health answered
# successfully while every service still showed STARTPENDING here). Poll for up
# to 30s so a normal-speed start still reports RUNNING instead of a stale
# snapshot, but never fail the update on this alone - Wait-Healthy below is the
# real, authoritative signal (same reasoning NetVault's single-service gate
# already used - this brings LogVault in line with it).
foreach ($svc in $Services) {
    $status = 'UNKNOWN'
    for ($i = 0; $i -lt 30; $i++) {
        $status = Get-ServiceStatus $svc
        if ($status -eq "RUNNING") { break }
        Start-Sleep -Seconds 1
    }
    if ($status -eq "RUNNING") {
        Write-OK "$svc - $status"
    } else {
        Write-Warn "$svc - $status (SCM status can lag behind the actual process - the health check below is authoritative)"
    }
}

Write-Host ""
# Mandatory final health check (matches NetVault/DDIVault's resilience upgrade): a
# service reporting RUNNING per SCM is not proof the app is actually serving
# traffic - poll /api/health with retries instead of a single best-effort attempt,
# and treat a failure here the same as any other stage failure (triggers a
# rollback) rather than just printing a warning and reporting success anyway.
$healthy = Wait-Healthy -TimeoutSec 60
if ($healthy) {
    Write-OK "API health check passed"
} else {
    Write-Err "API health check failed"
    Fail-Update -Stage 'health-check' -Message "API did not answer /api/health within 60s of starting - service may be crash-looping or stuck"
}

# Update succeeded and is confirmed healthy - the pre-update snapshots are no
# longer needed. Remove them so they don't accumulate across updates or get
# mistaken for a stale rollback target on the next run.
foreach ($snap in @("$AppDir\node_modules.lastgood", "$FrontendDir\.next.lastgood", "$FrontendDir\node_modules.lastgood")) {
    if (Test-Path $snap) { Remove-Item $snap -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-StatusJson -Success $true -Stage $null -ErrorCode 0 -RolledBack $false -HealthCheckPassed $true

# Done
Write-Host ""
Write-Host "  ================================================" -ForegroundColor Green
Write-Host "  Update complete - LogVault is running" -ForegroundColor Green
Write-Host "  http://localhost:3004" -ForegroundColor Green
Write-Host "  Commit: $commitHash" -ForegroundColor DarkGray
Write-Host "  ================================================" -ForegroundColor Green
Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update completed successfully - $commitHash"
Write-Host ""

# Best-effort - if Start-Transcript never succeeded (see top of script), this
# throws harmlessly; never let it mask the update's own success/failure.
try { Stop-Transcript | Out-Null } catch {}

} finally {
    # Release the concurrency-guard lock (see the guard near the top of the
    # script) regardless of how the try block above exits - normal completion,
    # a Fail-Update `exit 1` from any stage, or an unexpected thrown error.
    # Only remove it if THIS run actually wrote it (never delete a lock file
    # written by a different, still-running instance).
    if ($lockAcquired) {
        try { Remove-Item -Path $LockPath -Force -ErrorAction SilentlyContinue } catch {}
    }
}
