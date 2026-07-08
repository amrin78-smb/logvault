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

# Helper functions
function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "    [XX] $msg" -ForegroundColor Red }

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

# Kill any remaining node processes on our ports
$ports = @(3004, 3005)
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

# Ensure git safe.directory is set for SYSTEM account. Derive it from the self-located
# $AppDir (git wants forward slashes) so it matches the REAL repo on any layout - a
# hardcoded C:/Apps/logvault would not cover the suite install at C:\Apps\LogVault\app.
$gitSafeDir = $AppDir -replace '\\', '/'
try {
    $null = git config --global --add safe.directory $gitSafeDir 2>&1
} catch {}

# Step 3: Pull latest from GitHub
Write-Step "Pulling latest code from GitHub"

Set-Location $AppDir

$fetchResult = git fetch origin 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "git fetch failed: $fetchResult"
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at git fetch"
    exit 1
}

$resetResult = git reset --hard origin/main 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "git reset failed: $resetResult"
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at git reset"
    exit 1
}

git clean -fd --exclude=".env.local" --exclude="node_modules" 2>&1 | Out-Null

$commitHash = git rev-parse --short HEAD 2>&1
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
        try { $null = & $psql --quiet -U postgres -d $dbName -f $schema 2>&1 } catch {}
        $psqlExit = $LASTEXITCODE
        $env:PGPASSWORD = ''
        # psql over WinRM commonly returns -1 on a successful run, so treat -1 as 0.
        if ($psqlExit -eq 0 -or $psqlExit -eq -1) {
            Write-OK "Schema applied (as postgres to $dbName)"
        } else {
            Write-Warn "psql exited with code $psqlExit - apply scripts\schema.sql manually as postgres."
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

Set-Location $AppDir
npm install 2>&1 | Out-File -FilePath "$LogDir\npm-install-root.log" -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "npm install (root) failed - see $LogDir\npm-install-root.log"
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at root npm install"
    exit 1
}
Write-OK "Root dependencies installed"

# Step 6: Install frontend dependencies and build
Write-Step "Installing frontend dependencies"

Set-Location $FrontendDir
npm install 2>&1 | Out-File -FilePath "$LogDir\npm-install-frontend.log" -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "npm install (frontend) failed - see $LogDir\npm-install-frontend.log"
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at frontend npm install"
    exit 1
}
Write-OK "Frontend dependencies installed"

Write-Step "Building Next.js frontend"

$buildResult = npm run build 2>&1
$buildResult | Out-File -FilePath "$LogDir\npm-build.log" -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "Build FAILED - old version still running"
    Write-Err "See: $LogDir\npm-build.log"
    Write-Host ""
    $buildResult | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at npm run build"
    Write-Warn "Services NOT restarted - previous build still running"
    exit 1
}
Write-OK "Frontend built successfully"

# Step 7: Start services
Write-Step "Starting LogVault services"

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

# Step 8: Verify
Write-Step "Verifying service status"

$services = @("LogVault-Collector", "LogVault-API", "LogVault-App")
$allOK    = $true

foreach ($svc in $services) {
    $status = (sc.exe query $svc 2>&1 | Out-String)
    if ($status -match "RUNNING") {
        Write-OK "$svc - SERVICE_RUNNING"
    } elseif ($status -match "PAUSED") {
        Write-Warn "$svc - SERVICE_PAUSED (may still be starting)"
    } else {
        Write-Warn "$svc - status unclear (check manually)"
    }
}

# Quick health check
Start-Sleep -Seconds 2
try {
    $health = Invoke-WebRequest -Uri "http://localhost:3005/api/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($health.StatusCode -eq 200) {
        Write-OK "API health check passed - $($health.Content)"
    }
} catch {
    Write-Warn "API health check skipped (service may still be starting)"
}

# Done
Write-Host ""
if ($allOK) {
    Write-Host "  ================================================" -ForegroundColor Green
    Write-Host "  Update complete - LogVault is running" -ForegroundColor Green
    Write-Host "  http://localhost:3004" -ForegroundColor Green
    Write-Host "  Commit: $commitHash" -ForegroundColor DarkGray
    Write-Host "  ================================================" -ForegroundColor Green
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update completed successfully - $commitHash"
} else {
    Write-Host "  ================================================" -ForegroundColor Yellow
    Write-Host "  Update finished with warnings - check status above" -ForegroundColor Yellow
    Write-Host "  ================================================" -ForegroundColor Yellow
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update completed with warnings - $commitHash"
}
Write-Host ""
