# METADATA
# title: S3 Bucket Versioning Enabled
# description: >
#   S3 buckets storing PHI must have versioning enabled so that
#   accidental overwrites or deletes can be recovered. Without versioning,
#   PHI loss is unrecoverable. Closes GAP-04.
# custom:
#   framework: cmmc-l2
#   controls:
#     - MP.L2-3.8.9
#   nist_ref: "NIST SP 800-171 Rev. 3 — 3.8.9"
#   severity: MEDIUM
#   gap: GAP-04
#   remediation: >
#     Add aws_s3_bucket_versioning with versioning_configuration.status
#     = "Enabled" for every PHI-bearing S3 bucket.

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
