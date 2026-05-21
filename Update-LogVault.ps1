# ============================================================
# LogVault Update Script
# Run this after pulling changes from GitHub via Codespaces
# Usage: .\Update-LogVault.ps1
# ============================================================

$InstallDir = "C:\Apps\logvault"
$LogFile    = "$InstallDir\logs\update.log"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "==> $msg"
}

function OK($msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
    Add-Content -Path $LogFile -Value "    [OK] $msg"
}

function ERR($msg) {
    Write-Host "    [!!] $msg" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "    [!!] $msg"
}

# ── Header ───────────────────────────────────────────────────
Write-Host ""
Write-Host "  LogVault Update Script" -ForegroundColor White
Write-Host "  NexVault Product Family" -ForegroundColor DarkGray
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host ""

Log "Update started"

# ── Step 1: Pull from GitHub ──────────────────────────────────
Step "Pulling latest changes from GitHub"
Set-Location $InstallDir

$gitOutput = git pull 2>&1
if ($LASTEXITCODE -ne 0) {
    ERR "git pull failed: $gitOutput"
    Log "Update FAILED at git pull"
    exit 1
}
OK "Git pull complete"
Write-Host "    $gitOutput" -ForegroundColor DarkGray

# ── Sync .env.local to frontend ──────────────────────────────
Copy-Item "$InstallDir\.env.local" "$InstallDir\frontend\.env.local" -Force

# ── Step 2: Install root dependencies ────────────────────────
Step "Installing root dependencies (collector + API)"
$npmRoot = npm install 2>&1
if ($LASTEXITCODE -ne 0) {
    ERR "npm install failed at root"
    Log "Update FAILED at root npm install"
    exit 1
}
OK "Root dependencies installed"

# ── Step 3: Install frontend dependencies ────────────────────
Step "Installing frontend dependencies"
Set-Location "$InstallDir\frontend"
$npmFront = npm install 2>&1
if ($LASTEXITCODE -ne 0) {
    ERR "npm install failed at frontend"
    Log "Update FAILED at frontend npm install"
    exit 1
}
OK "Frontend dependencies installed"

# ── Step 4: Build frontend ────────────────────────────────────
Step "Building Next.js frontend"
$buildOutput = npm run build 2>&1
if ($LASTEXITCODE -ne 0) {
    ERR "Build failed - check output below"
    Write-Host $buildOutput -ForegroundColor Red
    Log "Update FAILED at npm run build"
    Set-Location $InstallDir
    exit 1
}
OK "Build complete"

# ── Step 5: Stop services ─────────────────────────────────────
Set-Location $InstallDir
Step "Stopping LogVault services"

nssm stop LogVault-App       | Out-Null
nssm stop LogVault-API       | Out-Null
nssm stop LogVault-Collector | Out-Null
Start-Sleep -Seconds 3
OK "Services stopped"

# ── Step 6: Start services ────────────────────────────────────
Step "Starting LogVault services"

nssm start LogVault-Collector | Out-Null
Start-Sleep -Seconds 2
nssm start LogVault-API       | Out-Null
Start-Sleep -Seconds 2
nssm start LogVault-App       | Out-Null
Start-Sleep -Seconds 3
OK "Services started"

# ── Step 7: Verify ───────────────────────────────────────────
Step "Verifying service status"

$services = @("LogVault-Collector", "LogVault-API", "LogVault-App")
$allOK = $true

foreach ($svc in $services) {
    $status = nssm status $svc 2>&1
    if ($status -eq "SERVICE_RUNNING") {
        OK "$svc — $status"
    } else {
        ERR "$svc — $status"
        $allOK = $false
    }
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
if ($allOK) {
    Write-Host "  Update complete. LogVault is running at: http://localhost:3004" -ForegroundColor Green
    Log "Update completed successfully"
} else {
    Write-Host "  Update finished with warnings. Check service status above." -ForegroundColor Yellow
    Log "Update completed with warnings"
}
Write-Host ""
