package main

import future.keywords.if

# ── Failing: stage with no access_log_settings ───────────────────────

test_apigw_no_logging_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_apigatewayv2_stage.default",
            "type": "aws_apigatewayv2_stage",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "$default",
                    "auto_deploy": true,
                    "access_log_settings": []
                }
            }
        }]
    }
}

# ── Failing: stage with empty destination_arn ────────────────────────

test_apigw_empty_log_destination_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_apigatewayv2_stage.default",
            "type": "aws_apigatewayv2_stage",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "$default",
                    "access_log_settings": [{"destination_arn": ""}]
                }
            }
        }]
    }
}

# ── Passing: stage with CloudWatch log group destination ──────────────

test_apigw_logging_configured_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_apigatewayv2_stage.default",
            "type": "aws_apigatewayv2_stage",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "$default",
                    "access_log_settings": [{
                        "destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/test"
                    }]
                }
            }
        }]
    }
}
