# 05-dos-stress.ps1
# Simulation: Send many concurrent registration and PDU session requests to test
# for lack of rate limiting / DoS resilience.
#
# Usage: $ALB_DNS = "your-alb"; .\05-dos-stress.ps1 [-Count 20]

param(
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = $env:ALB_DNS,
    [int]$Count = 20
)

if (-not $BaseUrl) { Write-Error "Set `$ALB_DNS or pass -BaseUrl"; exit 1 }
$base = "http://$BaseUrl"

Write-Host "=== Attack 5: DoS / stress (no rate limiting) ===" -ForegroundColor Yellow
Write-Host "Sending $Count concurrent PDU session requests...`n"

$jobs = 1..$Count | ForEach-Object {
    $i = $_
    Start-Job -ScriptBlock {
        param($b, $idx)
        try {
            $r = Invoke-WebRequest -UseBasicParsing -Method POST `
                -Uri "$b/namf-comm/v1/pdu-sessions/imsi-001010000000001" `
                -Headers @{"Content-Type"="application/json"; "x-trace-id"="dos-$idx"} `
                -Body '{}' -TimeoutSec 15
            [PSCustomObject]@{ Index = $idx; Status = $r.StatusCode; Ok = $true }
        } catch {
            [PSCustomObject]@{ Index = $idx; Status = 0; Ok = $false; Error = $_.Exception.Message }
        }
    } -ArgumentList $base, $i
}

$results = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job -Force
$ok = ($results | Where-Object { $_.Ok }).Count
Write-Host "Completed: $ok / $Count requests succeeded."
if ($ok -eq $Count) {
    Write-Host "RESULT: No rate limiting observed; all requests accepted (DoS risk)." -ForegroundColor Red
} else {
    Write-Host "Some requests failed (timeout or 5xx); check for rate limiting or capacity."
}
$results | Format-Table -AutoSize
