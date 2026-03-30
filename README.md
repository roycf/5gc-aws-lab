# 5GC AWS Lab

A **minimal, educational 5G Core** on AWS: six HTTP/JSON microservices (**NRF, AMF, AUSF, UDM, SMF, UPF**) in **Service-Based Architecture** style, running on **ECS (EC2)** behind an **internet-facing Application Load Balancer** on **HTTP port 80**.

**Full detail:** [docs/5gc-handbook.md](docs/5gc-handbook.md) — architecture, 5G theory, threats, tests, operations.

## What this repo is for

- Learn **control-plane + user-plane flow**: authenticate a UE → establish a PDU session → traffic via UPF (**N6** modeled as a lab HTTP forward API).
- Run **verification tests** and **attack simulations** (e.g. auth bypass, UPF SSRF); optionally enable an **edge WAF** and compare results.

## What it is not

- Not a standards-complete commercial core (no full NAS, GTP-U, PFCP, etc.).
- Not production security; some behaviors are **intentionally** simplified or exposed for teaching.

## Key layout

| Path | Purpose |
|------|--------|
| `docs/5gc-handbook.md` | Primary reference: theory, AWS design, tests, threat modeling |
| `infra/netsec-base.yaml` | VPC, subnets, NAT, ALB, ECS cluster, Flow Logs |
| `infra/core-services.yaml` | Six NFs on ECS, discovery, SGs, ALB rules |
| `infra/waf-5gc-edge.yaml` | Optional WAF → ALB |
| `services/*` | One Python/FastAPI app per NF (port **8080** in task) |
| `scripts/` | Deploy, tests, WAF toggle, attack scripts |

## Prerequisites

- **AWS account**, AWS CLI configured, permissions for CloudFormation, ECS, ECR, VPC, IAM as used in the templates.
- **Docker Desktop** (for building and pushing images).
- **PowerShell** (scripts are `.ps1`).

## Quick start (deploy order)

1. **Base stack** — VPC, ALB, ECS cluster, etc.  
   Example: create stack `netsec-base` from `infra/netsec-base.yaml` with **`CAPABILITY_NAMED_IAM`** (see [scripts/README.md](scripts/README.md)).

2. **Core services** — build images, push to ECR, deploy NF stack:
   ```powershell
   cd path\to\5gc-aws-lab
   .\scripts\deploy.ps1
   ```
   Wait **2–3 minutes** for ECS tasks to become healthy.

3. **Optional WAF** — separate stack; enable only when you want edge protection:
   ```powershell
   .\scripts\waf-toggle.ps1 -Enable
   ```

4. **Tests** — verification + attack expectations (behavior depends on WAF on/off):
   ```powershell
   .\scripts\run-tests.ps1
   ```

More options, teardown, and manual test commands: **[scripts/README.md](scripts/README.md)**.

## Security note

Only **AMF** and **UPF** paths are exposed via the ALB in this lab design—useful for exercises, **not** a recommended production pattern. Treat credentials, cookies, and forward URLs as **lab-only**; rotate any real secrets and lock down exposure if you extend the project.
