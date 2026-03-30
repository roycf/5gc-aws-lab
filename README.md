# 5GC AWS Lab

Minimal 5G Core lab on AWS using six Python/FastAPI network functions (**NRF, AMF, AUSF, UDM, SMF, UPF**) deployed on **ECS (EC2 launch type)** behind an internet-facing **ALB**.

> Educational environment for architecture learning, security testing, and threat-model exercises.  
> Not intended for production use.

## Highlights

- 5G SBA-inspired microservice topology with clear control-plane/user-plane separation.
- Infrastructure-as-code with CloudFormation for base networking and service stack.
- Scripted deployment, teardown, WAF toggle, and automated test runs.
- Security-focused scenarios including auth-bypass and SSRF simulation paths.

## Architecture at a glance

- **Control plane:** AMF orchestrates registration/authentication and PDU session setup through AUSF/UDM/SMF.
- **User plane (lab model):** UPF stores sessions and exposes a test forward endpoint representing N6 behavior.
- **Service exposure:** ALB routes only AMF/UPF paths for verification and red-team style testing.
- **Service discovery:** NRF provides registry/discovery behavior for NF interactions.

## Repository structure

| Path | Description |
|------|-------------|
| `docs/5gc-handbook.md` | Complete technical handbook (theory, internals, threat model, operations) |
| `infra/netsec-base.yaml` | VPC, subnets, NAT, ALB, ECS cluster, flow logs |
| `infra/core-services.yaml` | ECS services/task defs, service wiring, ALB rules, SG controls |
| `infra/waf-5gc-edge.yaml` | Optional WAF protection stack for ALB |
| `services/` | Source for each NF (`nrf`, `amf`, `ausf`, `udm`, `smf`, `upf`) |
| `scripts/` | Deploy/test/teardown helpers and attack simulation scripts |

## Prerequisites

- AWS account with permissions for CloudFormation, ECS, ECR, EC2/VPC, IAM.
- AWS CLI configured for your target account/region.
- Docker Desktop running (for image build and push).
- PowerShell (project scripts are `.ps1`).

## Quick start

1. Deploy base infrastructure (`infra/netsec-base.yaml`) with `CAPABILITY_NAMED_IAM`.
2. Build/push NF images and deploy services:
   ```powershell
   cd path\to\5gc-aws-lab
   .\scripts\deploy.ps1
   ```
3. Wait for ECS services to become healthy (typically 2-3 minutes).
4. Run full validation (functional tests + attack simulations):
   ```powershell
   .\scripts\run-tests.ps1
   ```

## WAF modes

- **Vulnerable mode:** WAF disabled, attack scripts are expected to succeed.
- **Defended mode:** WAF enabled, attack scripts are expected to be blocked.

```powershell
.\scripts\waf-toggle.ps1 -Enable
.\scripts\waf-toggle.ps1 -Status
.\scripts\waf-toggle.ps1 -Disable
```

## Documentation

- Primary guide: [`docs/5gc-handbook.md`](docs/5gc-handbook.md)
- Scripts and operational notes: [`scripts/README.md`](scripts/README.md)

## Security notice

This repository intentionally includes insecure-by-design behaviors for training and assessment. Do not reuse as-is for production 5G core or internet-exposed telecom workloads.
