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

# ── Failing: Lambda with empty subnet list ────────────────────────────

test_lambda_empty_subnets_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_lambda_function.intake",
            "type": "aws_lambda_function",
            "change": {
                "actions": ["create"],
                "after": {
                    "function_name": "test-handler",
                    "vpc_config": [{
                        "subnet_ids": [],
                        "security_group_ids": ["sg-12345"]
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
