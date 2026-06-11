# Acme Health Patient Intake API — CGE-P Capstone

**Primary Framework:** CMMC Level 2 (NIST SP 800-171 Rev. 3)

A GRC baseline layered on top of the `cgep-app-starter` Patient Intake API. The starter's eight intentional compliance gaps are closed via Terraform overrides, enforced by OPA/Conftest policies in CI, and described in an OSCAL component definition.

---

## What this is

A minimal AWS workload (VPC, Lambda, API Gateway, DynamoDB, S3) that ingests patient intake submissions — inherited as-is and made audit-defensible without rewriting the application. See `GAPS.md` for the eight named flaws and `WRITEUP.md` for the design rationale.

---

## Repository Structure

```
terraform/
  main.tf               Starter workload (unchanged)
  main_override.tf      Gap-closing overrides (GAP-02, 05, 06, 07, 08)
  hardening.tf          New GRC resources (GAP-01, 03, 04, 05, 06, 08)
  kms.tf                Customer-managed KMS key
  evidence.tf           Evidence vault (S3 Object Lock) + CloudTrail
  backend.tf            Remote state configuration
  variables.tf / outputs.tf

policies/
  s3_kms_encryption.rego + _test.rego         GAP-01 — SC.L2-3.13.11
  dynamodb_kms_encryption.rego + _test.rego   GAP-02 — SC.L2-3.13.11
  s3_tls_required.rego + _test.rego           GAP-03 — SC.L2-3.13.8
  s3_versioning.rego + _test.rego             GAP-04 — MP.L2-3.8.9
  lambda_vpc.rego + _test.rego                GAP-05 — SC.L2-3.13.1
  iam_least_privilege.rego + _test.rego       GAP-07 — AC.L2-3.1.5
  api_gateway_logging.rego + _test.rego       GAP-08 — AU.L2-3.3.1

.github/workflows/grc-gate.yml   Plan → Policy check → Apply → Sign → Upload
oscal/components/component-definition.json   CMMC L2 control implementations
oscal/profiles/cmmc-l2-profile.json          Selected controls profile
scripts/                                      Local helpers for evidence + verification
WRITEUP.md                                    Design decisions, trade-offs, future work
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Terraform | >= 1.6 | https://developer.hashicorp.com/terraform/install |
| AWS CLI | >= 2.x | https://aws.amazon.com/cli/ |
| OPA | >= 0.63 | https://www.openpolicyagent.org/docs/latest/#1-download-opa |
| Conftest | >= 0.50 | https://www.conftest.dev/install/ |
| Cosign | >= 2.2 | https://docs.sigstore.dev/cosign/system_config/installation/ |

---

## Deploy

```bash
# 1. Verify credentials
make creds AWS_PROFILE=<your-sandbox>

# 2. Deploy starter + GRC baseline
make deploy AWS_PROFILE=<your-sandbox>

# 3. Smoke test — must return {"submission_id": "...", "status": "received"}
make test AWS_PROFILE=<your-sandbox>
```

**Remote state bootstrap (one-time before CI runs):** see `terraform/backend.tf`.

---

## Grader Verification

### 1. OPA unit tests

```bash
opa test ./policies --verbose
# All tests: PASS
```

### 2. Policy gate — compliant plan passes

```bash
make plan AWS_PROFILE=<sandbox>
terraform -chdir=terraform show -json terraform/tfplan.binary > terraform/tfplan.json
conftest test terraform/tfplan.json --policy policies/ --all-namespaces
# Expected: PASS (no deny messages)
```

### 3. Policy gate — non-compliant plan is blocked

To reproduce the **red PR**: temporarily change `sse_algorithm = "aws:kms"` to `"AES256"` in
`terraform/hardening.tf`, re-plan, and re-run conftest. Expected output:

```
FAIL - terraform/tfplan.json - main - [CMMC SC.L2-3.13.11 | GAP-01] S3 bucket SSE must use 'aws:kms' ...
```

Revert the change to restore the green state.

### 4. Evidence bundle integrity

```bash
EVIDENCE_BUCKET=$(terraform -chdir=terraform output -raw evidence_bucket)
PREFIX=<run-prefix>   # from GitHub Actions summary or S3 console

aws s3 cp s3://${EVIDENCE_BUCKET}/${PREFIX}/evidence-bundle.tar.gz .
aws s3 cp s3://${EVIDENCE_BUCKET}/${PREFIX}/evidence-bundle.tar.gz.sha256 .

sha256sum evidence-bundle.tar.gz
cat evidence-bundle.tar.gz.sha256
# Both lines must show the same hash.
```

### 5. Cosign signature verification

```bash
aws s3 cp s3://${EVIDENCE_BUCKET}/${PREFIX}/evidence-bundle.tar.gz.cosign.bundle .

cosign verify-blob \
  --bundle evidence-bundle.tar.gz.cosign.bundle \
  --certificate-identity-regexp "https://github.com/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  evidence-bundle.tar.gz
# Expected: Verified OK
```

### 6. Object Lock retention

```bash
aws s3api head-object \
  --bucket ${EVIDENCE_BUCKET} \
  --key ${PREFIX}/evidence-bundle.tar.gz \
  --query '{Mode:ObjectLockMode,RetainUntil:ObjectLockRetainUntilDate}'
# Expected: {"Mode": "GOVERNANCE", "RetainUntil": "<365 days from upload>"}
```

Or use the verification script:
```bash
EVIDENCE_BUCKET=<bucket> scripts/verify-evidence.sh ${PREFIX}
```

### 7. OSCAL validation

```bash
pip install compliance-trestle
trestle validate -f oscal/components/component-definition.json
```

---

## CI/CD Secrets Required

| Secret | Description |
|--------|-------------|
| `AWS_ROLE_ARN` | IAM role ARN for GitHub OIDC federation |
| `TF_STATE_BUCKET` | S3 bucket for Terraform remote state |
| `TF_LOCK_TABLE` | DynamoDB table for state locking |
| `AWS_REGION` (variable) | AWS region (default: `us-east-1`) |

---

## Tear Down

```bash
make destroy AWS_PROFILE=<your-sandbox>
```

> The evidence vault has `force_destroy = false` + Object Lock. To destroy it, set `force_destroy = true` in `terraform/evidence.tf` and re-apply first, or manually delete all object versions.

---

## License

MIT. Fork freely. See original starter: [GRCEngClub/cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter)
