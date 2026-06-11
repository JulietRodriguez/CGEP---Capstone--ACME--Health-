package main

import future.keywords.if

# ── Failing: dynamodb:* as string ────────────────────────────────────

test_iam_dynamodb_wildcard_string_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_iam_role_policy.lambda_inline",
            "type": "aws_iam_role_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-policy",
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"arn:aws:dynamodb:us-east-1:123456789012:table/test\"}]}"
                }
            }
        }]
    }
}

# ── Failing: s3:* in an action array ─────────────────────────────────

test_iam_s3_wildcard_array_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_iam_role_policy.lambda_inline",
            "type": "aws_iam_role_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-policy",
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\",\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::test-bucket/*\"}]}"
                }
            }
        }]
    }
}

# ── Passing: specific actions only ───────────────────────────────────

test_iam_specific_actions_pass if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_iam_role_policy.lambda_inline",
            "type": "aws_iam_role_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-policy",
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"],\"Resource\":\"*\"}]}"
                }
            }
        }]
    }
}

# ── Passing: Deny statements with wildcards are allowed ───────────────

test_iam_deny_wildcard_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_iam_role_policy.lambda_inline",
            "type": "aws_iam_role_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-policy",
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
                }
            }
        }]
    }
}
