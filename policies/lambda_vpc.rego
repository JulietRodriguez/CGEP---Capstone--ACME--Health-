# METADATA
# title: Lambda Function Must Run in VPC
# description: >
#   Lambda functions that process PHI must run inside the VPC to enforce
#   network boundary protection. A Lambda running in the default
#   environment has no network-level isolation. Closes GAP-05.
# custom:
#   framework: cmmc-l2
#   controls:
#     - SC.L2-3.13.1
#   nist_ref: "NIST SP 800-171 Rev. 3 — 3.13.1"
#   severity: HIGH
#   gap: GAP-05
#   remediation: >
#     Add a vpc_config block to aws_lambda_function with non-empty
#     subnet_ids and security_group_ids.

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] in {"create", "update"}
    after := resource.change.after
    not lambda_in_vpc(after)
    msg := sprintf(
        "[CMMC SC.L2-3.13.1 | GAP-05] Lambda function '%v' is not deployed in a VPC. Add vpc_config with subnet_ids and security_group_ids.",
        [resource.address],
    )
}

lambda_in_vpc(after) if {
    vpc := after.vpc_config[_]
    count(vpc.subnet_ids) > 0
    count(vpc.security_group_ids) > 0
}
