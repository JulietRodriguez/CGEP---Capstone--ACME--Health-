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
