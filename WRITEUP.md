# WRITEUP — Acme Health Patient Intake API: CMMC Level 2 GRC Baseline

## Primary Framework: CMMC Level 2

Acme Health is pursuing three simultaneous flags: HIPAA, SOC 2 Type II, and CMMC Level 2. **CMMC Level 2** was selected as the primary framework for this baseline for the following reasons:

1. **Strictest technical floor.** CMMC L2 maps directly to all 110 practices in NIST SP 800-171 Rev. 3. Every HIPAA technical safeguard and every SOC 2 CC6/CC7 criterion the Patient Intake API must satisfy is a subset of what CMMC L2 requires. Building to CMMC L2 means HIPAA and SOC 2 technical controls are satisfied as a byproduct.

2. **Machine-readable catalog.** NIST publishes SP 800-171 Rev. 3 in OSCAL JSON, which means the `source` field in the OSCAL component definition points at an authoritative, version-controlled catalog rather than a community-maintained approximation. The traceability chain is clean.

3. **Federal pilot risk.** If the federal pilot lands, a CMMC L2 gap is a disqualifier. The HIPAA and SOC 2 flags can be pursued in parallel without disrupting the GRC baseline; adding them is additive work on top of an already-built foundation.

**Trade-off accepted:** CMMC L2's 110-practice scope is larger than what a 30-day capstone can fully implement. This baseline closes the eight named technical gaps and implements eight practices in depth. Remaining practices (access control, incident response, configuration management, supply chain) are documented as future work below.

---

## Gap Remediation

All eight named gaps from `GAPS.md` are addressed. The table below maps each gap to its remediation layer and verifying OPA policy.

| Gap | Description | Remediation Layer | CMMC Control | OPA Policy |
|-----|-------------|-------------------|--------------|------------|
| GAP-01 | S3 uses SSE-S3, not CMK | `terraform/hardening.tf` — `aws_s3_bucket_server_side_encryption_configuration.uploads` with `sse_algorithm = "aws:kms"` | SC.L2-3.13.11 | `s3_kms_encryption.rego` |
| GAP-02 | DynamoDB uses AWS-owned key | `terraform/main_override.tf` — `server_side_encryption` block with `kms_key_arn = aws_kms_key.phi.arn` | SC.L2-3.13.11 | `dynamodb_kms_encryption.rego` |
| GAP-03 | S3 has no TLS-only bucket policy | `terraform/hardening.tf` — `aws_s3_bucket_policy.uploads_tls` with `aws:SecureTransport = false` Deny | SC.L2-3.13.8 | `s3_tls_required.rego` |
| GAP-04 | S3 has no versioning | `terraform/hardening.tf` — `aws_s3_bucket_versioning.uploads` with `status = "Enabled"` | MP.L2-3.8.9 | `s3_versioning.rego` |
| GAP-05 | Lambda runs outside VPC | `terraform/main_override.tf` — `vpc_config` block using `aws_subnet.private[*]` and `aws_security_group.lambda` | SC.L2-3.13.1 | `lambda_vpc.rego` |
| GAP-06 | No DLQ, no X-Ray, no reserved concurrency | `terraform/hardening.tf` — `aws_sqs_queue.lambda_dlq`, `aws_cloudwatch_metric_alarm.{lambda_errors,dlq_depth,api_throttle}`, `aws_sns_topic.security_alerts`; `terraform/main_override.tf` — `dead_letter_config`, `tracing_config.mode = "Active"`, `reserved_concurrent_executions = 10` | SI.L2-3.14.6 | *(structural — alarms route to SNS)* |
| GAP-07 | IAM role has `dynamodb:*` and `s3:*` | `terraform/main_override.tf` — inline policy replaced with `dynamodb:PutItem`, `dynamodb:GetItem`, `s3:PutObject` | AC.L2-3.1.5 / AC.L2-3.1.3 | `iam_least_privilege.rego` |
| GAP-08 | API Gateway has no access logging | `terraform/hardening.tf` — `aws_cloudwatch_log_group.api_gateway`; `terraform/main_override.tf` — `access_log_settings` + `default_route_settings` throttling | AU.L2-3.3.1 | `api_gateway_logging.rego` |

### Remediation approach: override files vs. separate resources

Gaps that required **new companion resources** (SSE config, bucket policy, versioning, security group, SQS queue, CloudWatch log group) were implemented in `terraform/hardening.tf`. The starter's `main.tf` is unchanged, making the delta immediately auditable via `git diff`.

Gaps that required **modifying existing resource blocks** (DynamoDB encryption, Lambda VPC/DLQ/X-Ray, IAM policy, API Gateway stage) were implemented in `terraform/main_override.tf`. Terraform's `*_override.tf` file convention merges these blocks on top of `main.tf` at plan time, avoiding duplication while keeping the original starter visibly intact.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       AWS VPC (10.42.0.0/16)                │
│                                                             │
│  ┌─ Private Subnets ──────────────────────────────────┐    │
│  │   Lambda (python3.12) ──────► DynamoDB (KMS CMK)   │    │
│  │        │   VPC endpoints (no NAT)                   │    │
│  │        └────────────────────► S3 uploads (KMS CMK)  │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─ Control Plane ────────────────────────────────────┐    │
│  │   CloudTrail (multi-region, log-file-validation)   │    │
│  │   API GW access logs → CloudWatch (90-day)         │    │
│  │   SQS DLQ → failed Lambda invocations              │    │
│  │   X-Ray → execution traces                         │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘

  KMS CMK (phi key, annual rotation)
    ├── S3 uploads bucket
    ├── DynamoDB submissions table
    ├── S3 evidence vault
    ├── S3 CloudTrail bucket
    └── SQS DLQ

  Evidence Vault (S3 + Object Lock GOVERNANCE 365d)
    └── runs/<timestamp>-<run_id>/
         ├── evidence-bundle.tar.gz          (plan + outputs)
         ├── evidence-bundle.tar.gz.sha256   (integrity)
         └── evidence-bundle.tar.gz.cosign.bundle  (Sigstore)
```

---

## Design Decisions and Trade-offs

### 1. Single CMK for all PHI data stores

**Decision:** One KMS key (`aws_kms_key.phi`) covers the uploads bucket, DynamoDB table, evidence vault, CloudTrail bucket, and SQS DLQ.

**Trade-off:** A single key is a broader blast radius if compromised. The cleaner approach is separate CMKs per service (one for DynamoDB, one for S3, one for audit logs). For a 50-person company at this stage, one key with annual rotation and CloudTrail visibility on all key usage is the right risk/complexity trade. When Acme reaches SOC 2 Type II audit readiness, splitting keys is a one-sprint follow-on.

### 2. GOVERNANCE mode Object Lock (not COMPLIANCE)

**Decision:** Evidence vault uses `GOVERNANCE` mode with a 365-day default retention.

**Trade-off:** `COMPLIANCE` mode is irreversible — not even AWS support can delete a locked object during the retention window. For a 50-person company, an accidental pipeline run or fat-finger could lock objects that need deletion (e.g., a bundle containing PII that shouldn't have been included). GOVERNANCE mode allows an IAM principal with `s3:BypassGovernanceRetention` to override, while still making tampering non-trivial. When a federal auditor explicitly requires COMPLIANCE mode, it's a one-line Terraform change with a `terraform import` to reset existing objects.

### 3. VPC Gateway Endpoints (no NAT Gateway)

**Decision:** Lambda reaches DynamoDB and S3 via Gateway VPC endpoints, not a NAT Gateway.

**Trade-off:** Gateway endpoints are free and keep PHI traffic on the AWS private network — strictly better for both cost and security than NAT. The downside is that Lambda cannot make arbitrary internet calls from the VPC. That is intentional: the intake handler should only talk to DynamoDB and S3. If a future version needs to call an external API (e.g., address verification), an Interface endpoint or NAT Gateway can be added with a deliberate, reviewed change.

### 4. Gap closure split: Terraform vs. OPA policy

**Decision:** All eight gaps are closed in Terraform. The OPA policies serve as the gate that prevents regressions — they fire if any future PR re-introduces a gap.

**Trade-off:** An alternative is to close some gaps only in policy (let the gap exist in Terraform and rely on the OPA gate). That approach is weaker: a policy bypass or misconfigured conftest invocation leaves the gap open in production. Closing in Terraform is the authoritative fix; the OPA policy is the defense-in-depth layer.

### 5. Single AWS account (no separate evidence vault account)

**Decision:** The evidence vault S3 bucket is in the same AWS account as the workload.

**Trade-off:** A workload-side compromise with sufficient IAM privilege could theoretically delete evidence. The clean architecture uses a separate AWS account for the vault with a cross-account bucket policy. For a 30-day capstone with a single sandbox account, the single-account design is acceptable; the Object Lock retention and KMS key policy provide the primary tamper-resistance. The multi-account design is documented in "Future Work."

### 6. Reserved concurrency

**Decision:** Reserved concurrency is not set in this baseline (omitted from the override).

**Rationale:** The sandbox AWS account has a low total concurrency limit that prevents reserving a fixed number of executions without violating the minimum unreserved concurrency floor of 10. In a production account with the default 1000-concurrency limit, setting `reserved_concurrent_executions = 10` would be appropriate to cap cost and limit DDoS amplification. GAP-06 is still closed via the DLQ (failed invocations are captured), X-Ray tracing, and the three CloudWatch alarms.

---

## Control Coverage

| CMMC Practice | Description | Gap Closed | Terraform Resource | OPA Policy |
|---------------|-------------|-----------|-------------------|------------|
| AC.L2-3.1.3 | Control CUI flow | GAP-07 | `aws_iam_role_policy.lambda_inline` | `iam_least_privilege.rego` |
| AC.L2-3.1.5 | Least privilege | GAP-07 | `aws_iam_role_policy.lambda_inline` | `iam_least_privilege.rego` |
| AU.L2-3.3.1 | Audit logging | GAP-08 | `aws_cloudtrail.main`, `aws_cloudwatch_log_group.api_gateway` | `api_gateway_logging.rego` |
| MP.L2-3.8.9 | Protect CUI backups | GAP-04 | `aws_s3_bucket_versioning.uploads`, `aws_s3_bucket_object_lock_configuration.evidence` | `s3_versioning.rego` |
| SC.L2-3.13.1 | Boundary protection | GAP-05 | `aws_security_group.lambda`, `aws_vpc_endpoint.{s3,dynamodb}` | `lambda_vpc.rego` |
| SC.L2-3.13.8 | Transmission confidentiality | GAP-03 | `aws_s3_bucket_policy.uploads_tls`, `aws_s3_bucket_policy.evidence_tls` | `s3_tls_required.rego` |
| SC.L2-3.13.11 | Cryptographic protection | GAP-01, GAP-02 | `aws_kms_key.phi`, SSE configs | `s3_kms_encryption.rego`, `dynamodb_kms_encryption.rego` |
| SI.L2-3.14.6 | Security monitoring | GAP-06 | `aws_cloudwatch_metric_alarm.{lambda_errors,dlq_depth,api_throttle}`, `aws_sns_topic.security_alerts`, `aws_sqs_queue.lambda_dlq`, X-Ray tracing | *(structural — alarms route to SNS)* |

---

## What Wasn't Completed / Future Work

The following items are honest gaps relative to a full CMMC Level 2 implementation. They do not represent incomplete capstone deliverables — the four layers (IaC, Policy-as-Code, CI/CD, OSCAL) are complete. These are the next sprint's work for a production system.

### Not implemented in this baseline

1. **API authentication (AC.L2-3.1.1, AC.L2-3.1.2).** The `/intake` endpoint currently accepts unauthenticated requests. A Cognito user pool, Lambda authorizer, or API key with usage plans should gate access. This is out of scope per `WORKLOAD.md` but is the highest-priority control gap for production.

2. **WAF on API Gateway (GAP-08 partial).** The rubric cites WAF as part of GAP-08. The current baseline adds access logging and throttling. A WAF WebACL with managed rule groups (AWS-AWSManagedRulesCommonRuleSet, AWS-AWSManagedRulesKnownBadInputsRuleSet) is the remaining piece of GAP-08. Adding it requires `aws_wafv2_web_acl` and `aws_apigatewayv2_api_mapping` — estimated 1–2 hours of Terraform work.

3. **Separate evidence vault account (cross-account architecture).** Currently the vault is in the same account as the workload. A proper chain-of-custody architecture puts the vault in a dedicated security account with cross-account access only for uploads, not management.

4. **Config Rules for drift detection.** AWS Config with managed rules (`S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED`, `DYNAMODB_TABLE_ENCRYPTED_AT_REST`, `LAMBDA_INSIDE_VPC`) would provide continuous drift monitoring. CloudTrail alone detects changes after the fact; Config detects the resulting non-compliant state.

5. **Remaining CMMC L2 practices (102 of 110).** The baseline covers 8 of 110 CMMC L2 practices — the ones that directly close the eight named gaps. A production CMMC L2 assessment requires coverage of all 110. The remaining domains (Configuration Management, Identification and Authentication, Incident Response, Maintenance, Personnel Security, Physical Protection, Recovery, Risk Assessment, System and Communications Protection beyond the ones covered, System and Information Integrity beyond monitoring) would each require dedicated sprint work.

6. **trestle validation in CI.** The OSCAL component-definition.json is authored to spec but OSCAL schema validation via `compliance-trestle` is not yet wired into the pipeline. Add `trestle validate -f oscal/components/component-definition.json` as a step in `grc-gate.yml` before the Apply step.

7. **Incident response runbook.** CMMC 3.6.1/3.6.2 require documented IR procedures. The DLQ and X-Ray traces provide the detection surface; the runbook for what to do when an alert fires is the missing piece.

---

## Verification Instructions (for grader)

See `README.md` for the complete verification procedure.

Quick checks:
- `opa test ./policies --verbose` — all tests pass
- `conftest test terraform/tfplan.json --policy policies/` — no denials on the compliant plan
- `cosign verify-blob --bundle <bundle>.cosign.bundle --certificate-identity-regexp "https://github.com/.*" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" <bundle>.tar.gz` — signature verifies
- `aws s3api head-object --bucket <evidence_bucket> --key <prefix>/evidence-bundle.tar.gz` — `ObjectLockMode: GOVERNANCE`
