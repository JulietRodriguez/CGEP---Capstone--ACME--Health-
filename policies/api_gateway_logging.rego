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
    settings := after.access_log_settings[_]
    settings.destination_arn != null
    settings.destination_arn != ""
}
