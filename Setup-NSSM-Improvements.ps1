# LogVault NSSM Improvements
# Run this script once to apply NSSM log rotation and PostgreSQL dependency

Write-Host "Applying NSSM improvements to LogVault services..." -ForegroundColor Cyan

$services = @("LogVault-Collector", "LogVault-API", "LogVault-App")

foreach ($svc in $services) {
    Write-Host "`nConfiguring $svc..." -ForegroundColor Yellow

    # Set PostgreSQL as a dependency (ensures PG starts first)
    nssm set $svc DependOnService postgresql-x64-16
    Write-Host "  [+] PostgreSQL dependency set"

    # Enable NSSM log rotation — rotate when file exceeds 10MB
    nssm set $svc AppRotateFiles 1
    nssm set $svc AppRotateBytes 10485760
    nssm set $svc AppRotateOnline 1
    Write-Host "  [+] Log rotation enabled (10MB)"

    # Set restart delay — wait 3 seconds before restarting on crash
    nssm set $svc AppRestartDelay 3000
    Write-Host "  [+] Restart delay set to 3 seconds"

    # Throttle restarts — if service restarts more than 3 times in 60s, wait longer
    nssm set $svc AppThrottle 60000
    Write-Host "  [+] Restart throttle configured"
}

Write-Host "`nRestarting services to apply changes..." -ForegroundColor Yellow
foreach ($svc in $services) {
    nssm restart $svc
    Start-Sleep -Seconds 2
    $status = nssm status $svc
    Write-Host "  $svc : $status"
}

Write-Host "`nDone! NSSM improvements applied." -ForegroundColor Green
Write-Host "Log files will now rotate at 10MB automatically." -ForegroundColor Green
Write-Host "Services will wait for PostgreSQL before starting." -ForegroundColor Green
