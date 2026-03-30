# Run verification tests (Test 1, 2, 3) and attack simulations (01, 02 combined).
# If the optional WAF stack is deployed, attacks are expected to be blocked; otherwise vulnerable.
# Usage: .\scripts\run-tests.ps1 [-Region us-east-2] [-BaseStackName netsec-base] [-WafStackName waf-5gc]

param(
    [string]$Region = "us-east-2",
    [string]$BaseStackName = "netsec-base",
    [string]$WafStackName = "waf-5gc"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

# Get ALB DNS from base stack (same as lab guide and threat model)
$env:ALB_DNS = aws cloudformation describe-stacks --stack-name $BaseStackName --region $Region --query "Stacks[0].Outputs[?OutputKey=='AlbDNS'].OutputValue" --output text
if (-not $env:ALB_DNS) { Write-Error "Could not get AlbDNS from stack $BaseStackName"; exit 1 }
$base = "http://$env:ALB_DNS"

# Detect optional WAF: if WAF stack exists, attacks are expected to be blocked
$script:WafActive = $false
aws cloudformation describe-stacks --stack-name $WafStackName --region $Region --query "Stacks[0].StackStatus" --output text 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $script:WafActive = $true }

Write-Host "ALB: $env:ALB_DNS" -ForegroundColor Cyan
Write-Host "WAF: $(if ($script:WafActive) { 'ACTIVE (attacks expected blocked)' } else { 'inactive (attacks expected to succeed)' })" -ForegroundColor $(if ($script:WafActive) { 'Green' } else { 'Gray' })
Write-Host ""

$failed = 0
$script:WebSession = $null
$script:SESSION_ID = $null

# --- Verification Test 1: UE Authentication (preserve cookie for WAF) ---
Write-Host "=== Test 1: UE Authentication (5G-AKA) ===" -ForegroundColor Yellow
try {
    $r1 = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/namf-comm/v1/ue-contexts/imsi-001010000000001" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="test-auth-1"} `
        -Body '{"supi":"imsi-001010000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}' -TimeoutSec 30 -SessionVariable WebSession
    $script:WebSession = $WebSession
    $j1 = $r1.Content | ConvertFrom-Json
    $authOk = $j1.registration_steps | Where-Object { $_.step -eq "authentication" -and $_.status -eq "success" }
    $smfOk = $j1.registration_steps | Where-Object { $_.step -eq "smf_discovery" -and $_.status -eq "success" }
    if ($authOk -and $smfOk -and $j1.event -eq "ue_initial_registration") {
        Write-Host "  PASS: auth success, smf_discovery success (cookie preserved)" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: unexpected response" -ForegroundColor Red; $failed++
    }
} catch {
    Write-Host "  FAIL: $_" -ForegroundColor Red; $failed++
}

# --- Verification Test 2: PDU Session (send cookie if WAF is active) ---
Write-Host "`n=== Test 2: PDU Session Establishment ===" -ForegroundColor Yellow
try {
    $r2 = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/namf-comm/v1/pdu-sessions/imsi-001010000000001" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="test-pdu-1"} -Body '{}' -TimeoutSec 30 -WebSession $script:WebSession
    $j2 = $r2.Content | ConvertFrom-Json
    $sessionId = if ($j2.session) { $j2.session.sessionId } else { $null }
    if ($j2.event -eq "pdu_session_created" -and $sessionId -and $j2.session.sessionStatus -eq "ACTIVE") {
        Write-Host "  PASS: session created, sessionId = $sessionId" -ForegroundColor Green
        $script:SESSION_ID = $sessionId
    } else {
        Write-Host "  FAIL: unexpected response" -ForegroundColor Red; $failed++
    }
} catch {
    Write-Host "  FAIL: $_" -ForegroundColor Red; $failed++
}

# --- Verification Test 3: Data forwarding (UPF N6 to internet) ---
Write-Host "`n=== Test 3: Data Forwarding (UPF N6) ===" -ForegroundColor Yellow
if (-not $script:SESSION_ID) { Write-Host "  SKIP: no sessionId from Test 2" -ForegroundColor Gray } else {
    try {
        $test3Url = "https://httpbin.org/get"
        $body3 = @{ sessionId = $script:SESSION_ID; url = $test3Url } | ConvertTo-Json
        $h3 = @{"Content-Type"="application/json"; "x-trace-id"="test-data-1"}
        $r3 = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/nupf-dp/v1/forward" -Headers $h3 -Body $body3 -TimeoutSec 30
        $j3 = $r3.Content | ConvertFrom-Json
        if ($j3.sessionId -and $j3.response.statusCode -eq 200 -and $j3.counters.packetCount -ge 1) {
            Write-Host "  PASS: forward OK, statusCode=$($j3.response.statusCode), N6 to internet (HTTPS)" -ForegroundColor Green
        } else {
            Write-Host "  FAIL: unexpected response" -ForegroundColor Red; $failed++
        }
    } catch {
        Write-Host "  FAIL: $_" -ForegroundColor Red; $failed++
    }
}

# --- Attack 01: PDU without auth ---
Write-Host "`n=== Attack 01: PDU without auth ===" -ForegroundColor Yellow
try {
    $a1 = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/namf-comm/v1/pdu-sessions/imsi-001010000000001" `
        -Headers @{"Content-Type"="application/json"; "x-trace-id"="attack-01"} -Body '{}' -TimeoutSec 15
    $sid = if ($a1.Content) { (($a1.Content | ConvertFrom-Json).session).sessionId } else { $null }
    if ($script:WafActive) {
        Write-Host "  UNEXPECTED (WAF on): Session created without cookie" -ForegroundColor Red; $failed++
    } else {
        if ($sid) { Write-Host "  EXPECTED (vulnerable): Session created without prior auth, sessionId = $sid" -ForegroundColor Red }
        else { Write-Host "  UNEXPECTED: No session returned" -ForegroundColor Gray; $failed++ }
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($script:WafActive -and $code -eq 403) { Write-Host "  EXPECTED (defended): WAF blocked PDU session without auth cookie (403)" -ForegroundColor Green }
    elseif (-not $script:WafActive) { Write-Host "  UNEXPECTED: Request failed with $code" -ForegroundColor Red; $failed++ }
    else { Write-Host "  Blocked with status: $code" -ForegroundColor Green }
}

# --- Attack 02: UPF SSRF to metadata endpoint (WAF should block link-local targets) ---
Write-Host "`n=== Attack 02: UPF SSRF (metadata endpoint via forward) ===" -ForegroundColor Yellow
$attack02Session = $script:SESSION_ID
if (-not $attack02Session) { Write-Host "  SKIP: no sessionId from Test 2" -ForegroundColor Gray } else {
    $ssrfBlocked = $false
    $ssrfSucceeded = $false
    try {
        $target = "http://169.254.169.254/latest/meta-data/"
        $bodyS = @{ sessionId = $attack02Session; url = $target } | ConvertTo-Json
        $r = Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/nupf-dp/v1/forward" -Headers @{"Content-Type"="application/json"} -Body $bodyS -TimeoutSec 30
        $ssrfSucceeded = $true
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -eq 403) { $ssrfBlocked = $true }
    }
    if ($script:WafActive) {
        if ($ssrfBlocked) {
            Write-Host "  EXPECTED (defended): WAF blocked metadata SSRF target in forward request (403)" -ForegroundColor Green
        } else {
            Write-Host "  UNEXPECTED (WAF on): metadata SSRF target was not blocked" -ForegroundColor Red; $failed++
        }
    } else {
        if ($ssrfBlocked) { Write-Host "  UNEXPECTED: blocked without WAF (is WAF active?)" -ForegroundColor Gray; $failed++ }
        elseif ($ssrfSucceeded) { Write-Host "  EXPECTED (vulnerable): UPF fetched link-local metadata via forward (SSRF)" -ForegroundColor Red }
        else { Write-Host "  NOTE: metadata SSRF attempt did not return 403 but also did not succeed (environment-dependent)." -ForegroundColor Yellow }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($failed -eq 0) {
    Write-Host "All checks completed. Verification tests and attack simulations behaved as expected." -ForegroundColor Green
} else {
    Write-Host "$failed check(s) failed." -ForegroundColor Red
}
exit $failed
