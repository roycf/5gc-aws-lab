# Activate or deactivate the optional edge WAF for the 5GC lab.
# Enable = deploy/update the WAF stack (attach Web ACL to ALB).
# Disable = delete the WAF stack (WAF no longer attached).
# Usage: .\waf-toggle.ps1 -Enable [-Region us-east-2] [-BaseStackName netsec-base] [-WafStackName waf-5gc]
#        .\waf-toggle.ps1 -Disable [-Region us-east-2] [-WafStackName waf-5gc]
#        .\waf-toggle.ps1 -Status  [-Region us-east-2] [-WafStackName waf-5gc]

param(
    [switch]$Enable,
    [switch]$Disable,
    [switch]$Status,
    [string]$Region = "us-east-2",
    [string]$BaseStackName = "netsec-base",
    [string]$WafStackName = "waf-5gc"
)

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$TemplatePath = "$ProjectRoot\infra\waf-5gc-edge.yaml"

function Get-WafStackStatus {
    try {
        $st = aws cloudformation describe-stacks --stack-name $WafStackName --region $Region --query "Stacks[0].StackStatus" --output text 2>$null
        return $st
    } catch {
        return $null
    }
}

if ($Status) {
    $st = Get-WafStackStatus
    if ($st) {
        Write-Host "WAF stack '$WafStackName': $st (WAF is ACTIVE)" -ForegroundColor Green
    } else {
        Write-Host "WAF stack '$WafStackName' does not exist (WAF is INACTIVE)" -ForegroundColor Gray
    }
    exit 0
}

if ($Disable) {
    $st = Get-WafStackStatus
    if (-not $st) {
        Write-Host "WAF stack '$WafStackName' does not exist. Nothing to disable." -ForegroundColor Gray
        exit 0
    }
    Write-Host "Deleting WAF stack '$WafStackName' (WAF will be deactivated)..." -ForegroundColor Yellow
    aws cloudformation delete-stack --stack-name $WafStackName --region $Region
    if ($LASTEXITCODE -ne 0) { Write-Error "Delete failed"; exit 1 }
    aws cloudformation wait stack-delete-complete --stack-name $WafStackName --region $Region
    Write-Host "WAF stack deleted. Edge WAF is now INACTIVE." -ForegroundColor Green
    exit 0
}

if (-not $Enable) {
    Write-Host "Specify -Enable, -Disable, or -Status." -ForegroundColor Red
    Write-Host "  -Enable   Deploy/update the WAF stack (attach WAF to ALB)" -ForegroundColor Gray
    Write-Host "  -Disable  Delete the WAF stack (detach WAF)" -ForegroundColor Gray
    Write-Host "  -Status   Show whether WAF stack exists (active/inactive)" -ForegroundColor Gray
    exit 1
}

# Enable: get ALB ARN from base stack and create/update WAF stack
$AlbArn = aws cloudformation describe-stacks --stack-name $BaseStackName --region $Region --query "Stacks[0].Outputs[?OutputKey=='AlbArn'].OutputValue" --output text 2>$null
if (-not $AlbArn) {
    Write-Error "Could not get AlbArn from stack '$BaseStackName'. Deploy the base stack first."
    exit 1
}

if (-not (Test-Path $TemplatePath)) {
    Write-Error "Template not found: $TemplatePath"
    exit 1
}

$TemplateBody = Get-Content -Raw -Path $TemplatePath -Encoding UTF8
$stackExists = $false
aws cloudformation describe-stacks --stack-name $WafStackName --region $Region 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $stackExists = $true }

if ($stackExists) {
    Write-Host "Updating WAF stack '$WafStackName'..." -ForegroundColor Yellow
    $out = aws cloudformation update-stack --stack-name $WafStackName --region $Region --template-body $TemplateBody --parameters "ParameterKey=AlbArn,ParameterValue=$AlbArn" 2>&1
    if ($LASTEXITCODE -eq 0) {
        aws cloudformation wait stack-update-complete --stack-name $WafStackName --region $Region
        Write-Host "WAF stack updated. Edge WAF is ACTIVE." -ForegroundColor Green
    } elseif ($out -match "No updates are to be performed") {
        Write-Host "WAF stack already up to date. Edge WAF is ACTIVE." -ForegroundColor Green
    } else {
        Write-Host "Update failed: $out" -ForegroundColor Red; exit 1
    }
} else {
    Write-Host "Creating WAF stack '$WafStackName'..." -ForegroundColor Yellow
    aws cloudformation create-stack --stack-name $WafStackName --region $Region --template-body $TemplateBody --parameters "ParameterKey=AlbArn,ParameterValue=$AlbArn"
    if ($LASTEXITCODE -ne 0) { Write-Error "Create failed"; exit 1 }
    aws cloudformation wait stack-create-complete --stack-name $WafStackName --region $Region
    Write-Host "WAF stack created. Edge WAF is ACTIVE." -ForegroundColor Green
}

Write-Host "Run .\waf-toggle.ps1 -Status to check; run .\waf-toggle.ps1 -Disable to turn WAF off." -ForegroundColor Cyan
