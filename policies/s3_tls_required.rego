package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_policy"
    resource.change.actions[_] in {"create", "update"}
    policy := json.unmarshal(resource.change.after.policy)
    not has_tls_deny(policy)
    msg := sprintf(
        "[CMMC SC.L2-3.13.8 | GAP-03] S3 bucket policy '%v' does not deny non-TLS requests. Add Deny with aws:SecureTransport = false.",
        [resource.address],
    )
}

has_tls_deny(policy) if {
    stmt := policy.Statement[_]
    stmt.Effect == "Deny"
    stmt.Condition.Bool["aws:SecureTransport"] == "false"
}
