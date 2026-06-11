package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_apigatewayv2_stage"
    resource.change.actions[_] in {"create", "update"}
    after := resource.change.after
    not access_logging_configured(after)
    msg := sprintf(
        "[CMMC AU.L2-3.3.1 | GAP-08] API Gateway stage '%v' has no access_log_settings. Configure a CloudWatch log group destination.",
        [resource.address],
    )
}

access_logging_configured(after) if {
    # Block presence is sufficient at plan time — destination_arn is unknown
    # (null) when the log group is created in the same plan. The ARN resolves
    # at apply time; what matters here is that the block is configured at all.
    count(after.access_log_settings) > 0
}
