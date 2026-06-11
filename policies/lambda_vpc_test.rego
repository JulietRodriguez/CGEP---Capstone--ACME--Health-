package main

import future.keywords.if

# ── Failing: Lambda with no vpc_config ───────────────────────────────

test_lambda_no_vpc_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_lambda_function.intake",
            "type": "aws_lambda_function",
            "change": {
                "actions": ["create"],
                "after": {
                    "function_name": "test-handler",
                    "runtime": "python3.12",
                    "vpc_config": []
                }
            }
        }]
    }
}

# ── Passing: vpc_config block present, null IDs (plan-time, resolves at apply) ──

test_lambda_null_subnet_ids_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_lambda_function.intake",
            "type": "aws_lambda_function",
            "change": {
                "actions": ["create"],
                "after": {
                    "function_name": "test-handler",
                    "vpc_config": [{
                        "subnet_ids": null,
                        "security_group_ids": null
                    }]
                }
            }
        }]
    }
}

# ── Passing: Lambda with VPC config ──────────────────────────────────

test_lambda_in_vpc_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_lambda_function.intake",
            "type": "aws_lambda_function",
            "change": {
                "actions": ["create"],
                "after": {
                    "function_name": "test-handler",
                    "vpc_config": [{
                        "subnet_ids": ["subnet-abc123", "subnet-def456"],
                        "security_group_ids": ["sg-11111111"]
                    }]
                }
            }
        }]
    }
}
