# Deploy 5GC lab: build images, push to ECR, deploy core-services stack.
# Prerequisites: Docker running, AWS CLI configured, base stack (netsec-base) exists.
# Usage: .\scripts\deploy.ps1 [-Region us-east-2] [-StackName netsec-base]

param(
    [string]$Region = "us-east-2",
    [string]$BaseStackName = "netsec-base",
    [string]$ServicesStackName = "core-services",
    [string]$EcrRepo = "5gc-lab"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
if (-not (Test-Path "$ProjectRoot\infra\netsec-base.yaml")) { $ProjectRoot = (Get-Location).Path }

$AccountId = (aws sts get-caller-identity --query Account --output text)
$EcrUri = "$AccountId.dkr.ecr.$Region.amazonaws.com/$EcrRepo"

Write-Host "=== 5GC Lab Deploy ===" -ForegroundColor Cyan
Write-Host "Region: $Region, Base stack: $BaseStackName, ECR: $EcrUri"

# 1) Docker login to ECR
Write-Host "`n[1] ECR login..." -ForegroundColor Yellow
aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin "$AccountId.dkr.ecr.$Region.amazonaws.com"

# 2) Build and push each NF image (requires Docker daemon running)
$Services = @("nrf", "amf", "ausf", "udm", "smf", "upf")
foreach ($svc in $Services) {
    Write-Host "`n[2] Build & push $svc..." -ForegroundColor Yellow
    Push-Location "$ProjectRoot\services\$svc"
    docker build -t "${EcrUri}:${svc}" .
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Docker build failed for $svc. Ensure Docker Desktop is running." }
    docker push "${EcrUri}:${svc}"
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Docker push failed for $svc." }
    Pop-Location
}

# 3) Get base stack outputs
Write-Host "`n[3] Get base stack outputs..." -ForegroundColor Yellow
$Outputs = aws cloudformation describe-stacks --stack-name $BaseStackName --region $Region --query "Stacks[0].Outputs" --output json | ConvertFrom-Json
$get = { param($key) ($Outputs | Where-Object { $_.OutputKey -eq $key }).OutputValue }
$VpcId = & $get "VpcId"
$Subnet1 = & $get "PublicSubnet1"
$Subnet2 = & $get "PublicSubnet2"
$UpfSubnet1 = & $get "PrivateSubnet1"
$UpfSubnet2 = & $get "PrivateSubnet2"
$AlbListenerArn = & $get "AlbListenerArn"
$AlbSG = & $get "AlbSG"
$ECSInstanceSG = & $get "ECSInstanceSG"
$ClusterName = & $get "EcsClusterName"

# 4) Create or update core-services stack
Write-Host "`n[4] Deploy core-services stack..." -ForegroundColor Yellow
$Params = @(
    "ParameterKey=ClusterName,ParameterValue=$ClusterName",
    "ParameterKey=VpcId,ParameterValue=$VpcId",
    "ParameterKey=Subnet1,ParameterValue=$Subnet1",
    "ParameterKey=Subnet2,ParameterValue=$Subnet2",
    "ParameterKey=UpfSubnet1,ParameterValue=$UpfSubnet1",
    "ParameterKey=UpfSubnet2,ParameterValue=$UpfSubnet2",
    "ParameterKey=AlbListenerArn,ParameterValue=$AlbListenerArn",
    "ParameterKey=AlbSG,ParameterValue=$AlbSG",
    "ParameterKey=ECSInstanceSG,ParameterValue=$ECSInstanceSG",
    "ParameterKey=NrfImage,ParameterValue=${EcrUri}:nrf",
    "ParameterKey=AmfImage,ParameterValue=${EcrUri}:amf",
    "ParameterKey=AusfImage,ParameterValue=${EcrUri}:ausf",
    "ParameterKey=UdmImage,ParameterValue=${EcrUri}:udm",
    "ParameterKey=SmfImage,ParameterValue=${EcrUri}:smf",
    "ParameterKey=UpfImage,ParameterValue=${EcrUri}:upf"
)
$TemplateBody = Get-Content -Raw -Path "$ProjectRoot\infra\core-services.yaml" -Encoding UTF8
$stackExists = $false
try { aws cloudformation describe-stacks --stack-name $ServicesStackName --region $Region 2>$null; $stackExists = $true } catch {}
if ($stackExists) {
    $updateOut = aws cloudformation update-stack --stack-name $ServicesStackName --region $Region --template-body $TemplateBody --parameters $Params --capabilities CAPABILITY_NAMED_IAM 2>&1
    if ($LASTEXITCODE -eq 0) {
        aws cloudformation wait stack-update-complete --stack-name $ServicesStackName --region $Region
    } elseif ($updateOut -notmatch "No updates are to be performed") {
        Write-Host "Stack update failed: $updateOut" -ForegroundColor Red; exit 1
    }
} else {
    aws cloudformation create-stack --stack-name $ServicesStackName --region $Region --template-body $TemplateBody --parameters $Params --capabilities CAPABILITY_NAMED_IAM
    aws cloudformation wait stack-create-complete --stack-name $ServicesStackName --region $Region
}
Write-Host "Core-services stack ready." -ForegroundColor Green
# Force ECS services to pull the images we just pushed
$svcNames = (aws ecs list-services --cluster $ClusterName --region $Region --query "serviceArns[]" --output text) -split "\s+"
foreach ($arn in $svcNames) {
    if ($arn) {
        $svcName = $arn.Split("/")[-1]
        aws ecs update-service --cluster $ClusterName --service $svcName --region $Region --force-new-deployment --no-cli-pager 2>$null
    }
}
Write-Host "Forced new deployment on ECS services so they pull the new images. Wait 2-3 min then run .\scripts\run-tests.ps1" -ForegroundColor Cyan
Write-Host "ALB DNS: $((aws cloudformation describe-stacks --stack-name $BaseStackName --region $Region --query ""Stacks[0].Outputs[?OutputKey=='AlbDNS'].OutputValue"" --output text))"
