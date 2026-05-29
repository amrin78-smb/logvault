# ============================================================
# LogVault Update Script
# NocVault Product Family
# Usage: .\Update-LogVault.ps1 [-InstallDir "C:\Apps\LogVault"]
# Must be run as Administrator
# ============================================================

param(
  [string]$InstallDir = "C:\Apps\LogVault"
)

$AppDir      = "$InstallDir\app"
$FrontendDir = "$AppDir\frontend"
$NssmExe     = "C:\Apps\NetVault\nssm\nssm-2.24\win64\nssm.exe"
$LogDir      = "$InstallDir\logs"

# ── Helper functions ──────────────────────────────────────────
function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "    [XX] $msg" -ForegroundColor Red }

# ── Header ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkGray
Write-Host "  LogVault Update Script" -ForegroundColor White
Write-Host "  NocVault Product Family" -ForegroundColor DarkGray
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  ================================================" -ForegroundColor DarkGray
Write-Host ""

# ── Check Admin ───────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator"
    exit 1
}

# ── Ensure log directory exists ───────────────────────────────
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update started"

# ── Step 1: Stop services ─────────────────────────────────────
Write-Step "Stopping LogVault services"

sc.exe stop LogVault-App       | Out-Null
sc.exe stop LogVault-API       | Out-Null
sc.exe stop LogVault-Collector | Out-Null

Write-Host "    Waiting for services to stop..." -ForegroundColor DarkGray
Start-Sleep -Seconds 5

# Kill any remaining node processes holding our ports
$ports = @(3004, 3005)
foreach ($port in $ports) {
    $pids = netstat -ano 2>$null | Select-String ":$port\s" | ForEach-Object {
        ($_ -split '\s+')[-1]
    } | Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique
    foreach ($pid in $pids) {
        try {
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($proc -and $proc.Name -eq 'node') {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Write-Warn "Killed node process PID $pid holding port $port"
            }
        } catch {}
    }
}

Write-OK "Services stopped"

# ── Step 2: Backup .env.local ─────────────────────────────────
Write-Step "Backing up .env.local files"

$envRoot     = $null
$envFrontend = $null

$rootEnvPath     = "$AppDir\.env.local"
$frontendEnvPath = "$FrontendDir\.env.local"

if (Test-Path $rootEnvPath) {
    $envRoot = Get-Content -Path $rootEnvPath -Raw
    Write-OK "Backed up $rootEnvPath"
} else {
    Write-Warn "No .env.local found at $rootEnvPath — will not restore"
}

if (Test-Path $frontendEnvPath) {
    $envFrontend = Get-Content -Path $frontendEnvPath -Raw
    Write-OK "Backed up $frontendEnvPath"
} else {
    Write-Warn "No .env.local found at $frontendEnvPath — will not restore"
}

# ── Step 3: Pull latest from GitHub ──────────────────────────
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

# Clean untracked files but preserve .env.local and node_modules
git clean -fd --exclude=".env.local" --exclude="node_modules" 2>&1 | Out-Null

$commitHash = git rev-parse --short HEAD 2>&1
Write-OK "Code updated to commit: $commitHash"

# ── Step 4: Restore .env.local ────────────────────────────────
Write-Step "Restoring .env.local files"

if ($null -ne $envRoot) {
    Set-Content -Path $rootEnvPath -Value $envRoot -NoNewline
    Write-OK "Restored $rootEnvPath"
}

if ($null -ne $envFrontend) {
    Set-Content -Path $frontendEnvPath -Value $envFrontend -NoNewline
    Write-OK "Restored $frontendEnvPath"
} elseif ($null -ne $envRoot) {
    # Sync root .env.local to frontend if frontend copy didn't exist
    Set-Content -Path $frontendEnvPath -Value $envRoot -NoNewline
    Write-OK "Synced root .env.local to frontend"
}

# ── Step 5: Install root dependencies ────────────────────────
Write-Step "Installing root dependencies"

Set-Location $AppDir
$npmRootLog = "$LogDir\npm-install-root.log"

$npmRootResult = npm install 2>&1
$npmRootResult | Out-File -FilePath $npmRootLog -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "npm install (root) failed — see $npmRootLog"
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at root npm install"
    exit 1
}
Write-OK "Root dependencies installed"

# ── Step 6: Install frontend dependencies and build ───────────
Write-Step "Installing frontend dependencies"

Set-Location $FrontendDir
$npmFrontLog = "$LogDir\npm-install-frontend.log"

$npmFrontResult = npm install 2>&1
$npmFrontResult | Out-File -FilePath $npmFrontLog -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "npm install (frontend) failed — see $npmFrontLog"
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at frontend npm install"
    exit 1
}
Write-OK "Frontend dependencies installed"

Write-Step "Building Next.js frontend"
$npmBuildLog = "$LogDir\npm-build.log"

$buildResult = npm run build 2>&1
$buildResult | Out-File -FilePath $npmBuildLog -Encoding utf8

if ($LASTEXITCODE -ne 0) {
    Write-Err "Build FAILED — old version still running"
    Write-Err "See build log: $npmBuildLog"
    Write-Host ""
    Write-Host "  Last 20 lines of build output:" -ForegroundColor Yellow
    $buildResult | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] FAILED at npm run build"
    Write-Host ""
    Write-Warn "Services NOT restarted — previous build is still running"
    exit 1
}
Write-OK "Frontend built successfully"

# ── Step 7: Start services ────────────────────────────────────
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

# ── Step 8: Verify ────────────────────────────────────────────
Write-Step "Verifying service status"

$services  = @("LogVault-Collector", "LogVault-API", "LogVault-App")
$allOK     = $true

foreach ($svc in $services) {
    $status = sc.exe query $svc 2>&1 | Select-String "STATE" | ForEach-Object {
        if ($_ -match "RUNNING")  { "SERVICE_RUNNING" }
        elseif ($_ -match "PAUSED") { "SERVICE_PAUSED" }
        elseif ($_ -match "STOPPED") { "SERVICE_STOPPED" }
        else { "UNKNOWN" }
    }
    if (-not $status) { $status = "UNKNOWN" }

    if ($status -eq "SERVICE_RUNNING") {
        Write-OK "$svc — $status"
    } elseif ($status -eq "SERVICE_PAUSED") {
        # PAUSED can mean starting — check if port is listening
        Write-Warn "$svc — $status (may still be starting)"
        $allOK = $false
    } else {
        Write-Err "$svc — $status"
        $allOK = $false
    }
}

# Quick API health check
Start-Sleep -Seconds 2
try {
    $health = Invoke-WebRequest -Uri "http://localhost:3005/api/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($health.StatusCode -eq 200) {
        Write-OK "API health check passed — $($health.Content)"
    }
} catch {
    Write-Warn "API health check skipped (service may still be starting)"
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
if ($allOK) {
    Write-Host "  ================================================" -ForegroundColor Green
    Write-Host "  Update complete — LogVault is running" -ForegroundColor Green
    Write-Host "  http://localhost:3004" -ForegroundColor Green
    Write-Host "  Commit: $commitHash" -ForegroundColor DarkGray
    Write-Host "  ================================================" -ForegroundColor Green
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update completed successfully — $commitHash"
} else {
    Write-Host "  ================================================" -ForegroundColor Yellow
    Write-Host "  Update finished with warnings" -ForegroundColor Yellow
    Write-Host "  Check service status above — some may still be starting" -ForegroundColor Yellow
    Write-Host "  ================================================" -ForegroundColor Yellow
    Add-Content -Path "$LogDir\update.log" -Value "[$timestamp] Update completed with warnings — $commitHash"
}
Write-Host ""
