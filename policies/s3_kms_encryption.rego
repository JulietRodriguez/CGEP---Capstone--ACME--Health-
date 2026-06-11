# METADATA
# title: S3 KMS Customer-Managed Encryption
# description: >
#   S3 buckets storing PHI must use SSE-KMS with a customer-managed key.
#   AWS-managed SSE-S3 (AES256) does not give the organization key custody
#   or audit trail of key usage. Closes GAP-01.
# custom:
#   framework: cmmc-l2
#   controls:
#     - SC.L2-3.13.11
#   nist_ref: "NIST SP 800-171 Rev. 3 — 3.13.11"
#   severity: HIGH
#   gap: GAP-01
#   remediation: >
#     Add aws_s3_bucket_server_side_encryption_configuration with
#     sse_algorithm = "aws:kms" referencing your CMK ARN.

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] in {"create", "update"}
    rule := resource.change.after.rule[_]
    config := rule.apply_server_side_encryption_by_default[_]
    config.sse_algorithm != "aws:kms"
    msg := sprintf(
        "[CMMC SC.L2-3.13.11 | GAP-01] S3 bucket SSE must use 'aws:kms', found '%v'. Resource: %v",
        [config.sse_algorithm, resource.address],
    )
}
