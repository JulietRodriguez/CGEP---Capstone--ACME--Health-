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
