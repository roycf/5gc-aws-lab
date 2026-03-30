# 5GC Lab – Attack Simulations

These scripts are **attack simulations** — they demonstrate the lab’s **two priority threats** by deliberately abusing the same APIs the core exposes: (1) **auth bypass** (PDU session without 5G-AKA), and (2) **UPF SSRF into metadata endpoints** via the exposed forward API. They are **not** the verification tests: the verification tests (Test 1, 2, 3 in `docs/5gc-handbook.md`) confirm the 5G Core works correctly (authentication, PDU session, data forwarding). Run the verification tests first to ensure the core is healthy; then run these scripts to illustrate the threats. **Use only in a lab environment you control.**

## Prerequisites

- Lab deployed (both CloudFormation stacks).
- ALB DNS name. In PowerShell:

```powershell
$env:ALB_DNS = (aws cloudformation describe-stacks --stack-name netsec-base --region us-east-2 --query "Stacks[0].Outputs[?OutputKey=='AlbDNS'].OutputValue" --output text)
```

## Scripts

| Script | Threat | What it does |
|--------|--------|---------------|
| `01-pdu-without-auth.ps1` | Auth bypass | Requests PDU session without prior UE registration/5G-AKA. |
| `02-upf-ssrf.ps1` | UPF SSRF / exfil | Creates a session (or uses `-SessionId`), then forwards to a link-local metadata endpoint (e.g. `169.254.169.254`) via the forward API. With WAF enabled, expected blocked (403). |
| `04-supi-enumeration.ps1` | SUPI enumeration | Registers and creates sessions for several SUPIs (known and unknown). |
| `05-dos-stress.ps1` | DoS / no rate limit | Sends many concurrent PDU session requests. |
| `06-rogue-nrf.ps1` | Rogue NF registration | Tries to register a fake NF via ALB (expect 404; NRF not exposed). |

## Running

From `scripts/attack-simulations/`:

```powershell
cd scripts/attack-simulations
$env:ALB_DNS = "your-alb-1234567890.us-east-2.elb.amazonaws.com"
.\01-pdu-without-auth.ps1
.\02-upf-ssrf.ps1
.\04-supi-enumeration.ps1
.\05-dos-stress.ps1 -Count 10
.\06-rogue-nrf.ps1
```

Or pass `-BaseUrl`:

```powershell
.\01-pdu-without-auth.ps1 -BaseUrl "your-alb-1234567890.us-east-2.elb.amazonaws.com"
```

## Threat model

See **`docs/5gc-handbook.md`** for the full threat model, concepts, and mitigations.
