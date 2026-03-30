# 5GC Lab Scripts

## Deployment order

Deploy in this order (each step assumes the previous is done):

| Step | What | Command / action |
|------|------|-------------------|
| 1 | **Base stack** (VPC, ALB, ECS cluster, NAT, flow logs) | `aws cloudformation create-stack --stack-name netsec-base --template-body file://infra/netsec-base.yaml --capabilities CAPABILITY_NAMED_IAM` (or use console). |
| 2 | **Core services** (NF images + ECS services) | `.\scripts\deploy.ps1` (needs Docker; reads base stack outputs). |
| 3 | **Wait** for ECS tasks healthy | 2–3 minutes. |
| 4 | **Optional WAF** (only if you want edge protection) | `.\scripts\waf-toggle.ps1 -Enable` — do **not** run this if you want to test without WAF first. |

The WAF is **optional** and separate. You can test **without** WAF (step 4 omitted) and **with** WAF (run step 4, then test again).

## Deploy (requires Docker)

1. **Start Docker Desktop** so the Docker daemon is running.
2. Deploy the base stack (if not already done). If you create or update the base stack (e.g. to enable VPC Flow Logs for interactive Attack 3 verification), use `--capabilities CAPABILITY_NAMED_IAM` with `create-stack` or `update-stack`.
3. Build/push NF images and deploy or update the core-services stack:

```powershell
cd c:\Users\Roy\Project\5gc-aws-lab
.\scripts\deploy.ps1
```

This will:

- Log in to ECR and build/push all six NF images (`nrf`, `amf`, `ausf`, `udm`, `smf`, `upf`).
- Create or update the `core-services` CloudFormation stack with the correct parameters (including private subnets for the UPF).
- Force a new deployment on ECS services so they pull the new images.

4. Wait **2–3 minutes** for ECS tasks to become healthy behind the ALB.

## Testing without WAF vs with WAF

**Test without WAF (vulnerable mode — attacks expected to succeed):**

1. Do **not** run `waf-toggle.ps1 -Enable`. Ensure the WAF stack does not exist: `.\scripts\waf-toggle.ps1 -Status` → should say *INACTIVE*.
2. Run the full test suite:
   ```powershell
   .\scripts\run-tests.ps1
   ```
3. You should see: `WAF: inactive (attacks expected to succeed)`. Verification tests (Test 1–3) pass; Attack 01 and 02 are expected to **succeed** (session without auth, SSRF to external URL).

**Test with WAF (defended mode — attacks expected blocked):**

1. Activate the WAF: `.\scripts\waf-toggle.ps1 -Enable`
2. Run the full test suite again:
   ```powershell
   .\scripts\run-tests.ps1
   ```
3. You should see: `WAF: ACTIVE (attacks expected blocked)`. Verification tests (Test 1–3) still pass; Attack 01 and 02 are expected to be **blocked** (403).

**Switch back to vulnerable mode:** `.\scripts\waf-toggle.ps1 -Disable` then run `.\scripts\run-tests.ps1` again.

## Run verification tests and attack simulations

`run-tests.ps1` runs **both** verification tests and attack simulations in one go. They are different:

| Type | Purpose | In this script |
|------|---------|----------------|
| **Verification tests** | Confirm the 5G Core works (auth, PDU session, N6 forwarding). | Test 1, Test 2, Test 3 |
| **Attack simulations** | Demonstrate the two priority threats: auth bypass; and UPF SSRF into metadata endpoints via forward (credential/environment disclosure). | Attack 01, Attack 02 |

After the stack is deployed and tasks are running:

```powershell
.\scripts\run-tests.ps1
```

**Verification tests (confirm the core works):** The script preserves the `5gc-auth` cookie (Test 1) and reuses the sessionId from Test 2 for the forward request (Test 3). If the **optional WAF** is active, Test 3 uses an internal URL; if not, it uses `https://httpbin.org/get` for N6 to internet.

- **Test 1:** UE authentication (5G-AKA); cookie preserved.
- **Test 2:** PDU session establishment; sessionId captured from response.
- **Test 3:** Data forwarding through the UPF.

**Attack simulations:** Pass/fail depends on whether the **optional WAF** is active (see below). When WAF is active, attacks are expected to be blocked (403); when inactive, they are expected to succeed (vulnerable).

- **Attack 01:** PDU session without auth cookie.
- **Attack 02:** UPF SSRF into metadata endpoints (e.g. IMDS/task metadata link-local IPs).

The script reads the ALB DNS from the `netsec-base` stack outputs. Exit code 0 means all checks behaved as expected. For **Attack 02 (SSRF step)**, you can verify in the AWS Console (CloudWatch → `/5gc/upf`, search for `N6_EXTERNAL_REQUEST`); see the lab guide section *Interactive verification: Attack 3*.

## Optional WAF (activate/deactivate on demand)

The edge WAF is a **separate stack** so you can turn it on or off without changing the base or core-services stacks:

```powershell
.\scripts\waf-toggle.ps1 -Enable    # Deploy WAF stack → WAF active
.\scripts\waf-toggle.ps1 -Status   # Check if WAF stack exists
.\scripts\waf-toggle.ps1 -Disable  # Delete WAF stack → WAF inactive
```

Template: `infra/waf-5gc-edge.yaml`. Default stack name: `waf-5gc` (matches `waf-toggle.ps1` / `run-tests.ps1`).

## Manual runs

- **Verification tests only:** see **`docs/5gc-handbook.md`** for the full Test 1, 2, 3 commands.
- **Attack simulations only:** see **`scripts/attack-simulations/`** for individual scripts and **`docs/5gc-handbook.md`** for the threat model.
