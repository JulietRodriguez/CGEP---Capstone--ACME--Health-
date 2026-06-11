# METADATA
# title: API Gateway Access Logging Required
# description: >
#   API Gateway stages must have access_log_settings configured so that
#   every inbound request is captured for audit and incident response.
#   Without access logs, there is no audit trail of who submitted what
#   to the intake endpoint. Closes GAP-08.
# custom:
#   framework: cmmc-l2
#   controls:
#     - AU.L2-3.3.1
#   nist_ref: "NIST SP 800-171 Rev. 3 — 3.3.1"
#   severity: HIGH
#   gap: GAP-08
#   remediation: >
#     Add access_log_settings { destination_arn = <cloudwatch_log_group_arn> }
#     inside aws_apigatewayv2_stage.

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
