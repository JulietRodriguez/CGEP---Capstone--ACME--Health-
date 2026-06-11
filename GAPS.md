# The Gaps

This starter ships eight named, intentional compliance gaps. Your capstone's policy suite, baseline overrides, and OSCAL component must address them.

You don't have to fix all eight to pass. You **do** have to write **at least five** Rego policies that detect the most material ones, and your OSCAL must explain how your controlled system closes them.

| ID | Gap | Where | Frameworks the gap implicates |
|---|---|---|---|
| GAP-01 | S3 uploads bucket relies on AWS-managed SSE-S3 (the 2023 default) instead of SSE-KMS with a customer CMK. PHI keys are not under customer custody. | `aws_s3_bucket.uploads` | HIPAA 164.312(a)(2)(iv); SOC 2 CC6.1; CMMC SC.L2-3.13.11 |
| GAP-02 | DynamoDB submissions table uses the AWS-owned default encryption key, not a CMK you control. | `aws_dynamodb_table.intake` | HIPAA 164.312(a)(2)(iv); SOC 2 CC6.1; CMMC SC.L2-3.13.11 |
| GAP-03 | S3 uploads bucket has no policy denying non-TLS requests (no `aws:SecureTransport` deny). | `aws_s3_bucket.uploads` | HIPAA 164.312(e)(1); SOC 2 CC6.7; CMMC SC.L2-3.13.8 |
| GAP-04 | S3 uploads bucket has no versioning. PHI overwrites are unrecoverable. | `aws_s3_bucket.uploads` | HIPAA 164.308(a)(7); SOC 2 A1.2; CMMC MP.L2-3.8.9 |
| GAP-05 | Lambda runs in the default Lambda environment, not in the VPC the starter provisions. | `aws_lambda_function.intake` | HIPAA 164.312(e)(1); SOC 2 CC6.6; CMMC SC.L2-3.13.1 |
| GAP-06 | No reserved concurrency, no DLQ, no X-Ray. | `aws_lambda_function.intake` | SOC 2 CC7.2; CMMC SI.L2-3.14.6 |
| GAP-07 | Lambda IAM role has `dynamodb:*` and `s3:*` on the workload resources. Wildly over-broad. | `aws_iam_role_policy.lambda_inline` | HIPAA 164.312(a)(1); SOC 2 CC6.3; CMMC AC.L2-3.1.5 |
| GAP-08 | API Gateway has no access logging, no throttling, no WAF. | `aws_apigatewayv2_stage.default` | HIPAA 164.312(b); SOC 2 CC7.2; CMMC AU.L2-3.3.1 |

> **A note on AWS-default safety**: AWS has improved S3 defaults over time. New buckets ship with SSE-S3 enabled and the public-access-block fully on. Those defaults sit between you and a worse outcome, but they are not customer-controlled. For PHI under HIPAA, your CMK custody matters; for SOC 2 trust criteria, your TLS-enforcing bucket policy matters. The gaps above reflect what's still missing once the defaults do their job.

## What "addressing a gap" looks like

You can address a gap in any of three layers. Your write-up explains which layer you used and why.

1. **Override in your Terraform baseline.** Add the missing resource (e.g., `aws_s3_bucket_server_side_encryption_configuration` for GAP-01). Wire it to the starter's resource by reference.
2. **Block in your policy suite.** A Rego policy that fails the plan if the gap is present. Useful when you want CI to refuse merges that re-introduce the gap.
3. **Document in OSCAL.** When a control is satisfied by an organizational process you can't enforce in code (e.g., an annual access review), the OSCAL component is the right place. Don't use this as a cop-out for technical gaps.

The strongest capstone submissions use all three layers.

## What the grader will check

We will run your Terraform plan. For every gap your write-up claims to address technically, we will look for the corresponding remediation in the plan. For every gap your policies claim to detect, we will run your policy suite against a copy of the starter with the gap re-introduced and confirm it fails closed.

Closing all eight gaps is impressive. Closing five gaps with depth and clear OSCAL traceability is what passes.
