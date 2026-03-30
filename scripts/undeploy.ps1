# Undeploy 5GC lab: delete CloudFormation stacks to stop charges.
# Deletes core-services first, then netsec-base (base has VPC, ALB, ECS, EC2).
# Usage: .\scripts\undeploy.ps1 [-Region us-east-2] [-BaseStackName netsec-base] [-ServicesStackName core-services]

param(
    [string]$Region = "us-east-2",
    [string]$BaseStackName = "netsec-base",
    [string]$ServicesStackName = "core-services"
)

$ErrorActionPreference = "Stop"

Write-Host "=== 5GC Lab Undeploy (stop charges) ===" -ForegroundColor Cyan
Write-Host "Region: $Region. Deleting: $ServicesStackName, then $BaseStackName"

# 1) Delete core-services stack first (depends on base)
Write-Host "`n[1] Deleting $ServicesStackName..." -ForegroundColor Yellow
$exists = $false
try {
    aws cloudformation describe-stacks --stack-name $ServicesStackName --region $Region 2>$null | Out-Null
    $exists = $true
} catch {}
if ($exists) {
    aws cloudformation delete-stack --stack-name $ServicesStackName --region $Region
    aws cloudformation wait stack-delete-complete --stack-name $ServicesStackName --region $Region
    Write-Host "  $ServicesStackName deleted." -ForegroundColor Green
} else {
    Write-Host "  $ServicesStackName does not exist, skipping." -ForegroundColor Gray
}

# 2) Delete base stack (VPC, ALB, ECS cluster, ASG/EC2)
Write-Host "`n[2] Deleting $BaseStackName..." -ForegroundColor Yellow
$exists = $false
try {
    aws cloudformation describe-stacks --stack-name $BaseStackName --region $Region 2>$null | Out-Null
    $exists = $true
} catch {}
if ($exists) {
    aws cloudformation delete-stack --stack-name $BaseStackName --region $Region
    aws cloudformation wait stack-delete-complete --stack-name $BaseStackName --region $Region
    Write-Host "  $BaseStackName deleted." -ForegroundColor Green
} else {
    Write-Host "  $BaseStackName does not exist, skipping." -ForegroundColor Gray
}

Write-Host "`nDone. Stacks removed; you should no longer be charged for this lab." -ForegroundColor Green
Write-Host "Note: ECR images in repo 5gc-lab (if you created it) still incur small storage cost until you delete the repo or images." -ForegroundColor Cyan
