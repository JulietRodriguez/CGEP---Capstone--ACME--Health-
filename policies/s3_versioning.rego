package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    resource.change.actions[_] in {"create", "update"}
    config := resource.change.after.versioning_configuration[_]
    config.status != "Enabled"
    msg := sprintf(
        "[CMMC MP.L2-3.8.9 | GAP-04] S3 bucket versioning '%v' must have status 'Enabled', found '%v'.",
        [resource.address, config.status],
    )
}
