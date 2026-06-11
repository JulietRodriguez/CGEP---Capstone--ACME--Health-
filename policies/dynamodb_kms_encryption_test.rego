package main

import future.keywords.if

# ── Failing: no server_side_encryption block ─────────────────────────

test_dynamodb_no_sse_denied if {
    # Real Terraform plan JSON serializes absent blocks as [] not as absent key.
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_dynamodb_table.intake",
            "type": "aws_dynamodb_table",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-table",
                    "billing_mode": "PAY_PER_REQUEST",
                    "hash_key": "submission_id",
                    "server_side_encryption": []
                }
            }
        }]
    }
}

# ── Failing: SSE enabled but no CMK ──────────────────────────────────

test_dynamodb_sse_no_cmk_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_dynamodb_table.intake",
            "type": "aws_dynamodb_table",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-table",
                    "server_side_encryption": [{
                        "enabled": true,
                        "kms_key_arn": null
                    }]
                }
            }
        }]
    }
}

# ── Passing: SSE enabled with CMK ────────────────────────────────────

test_dynamodb_cmk_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_dynamodb_table.intake",
            "type": "aws_dynamodb_table",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-table",
                    "server_side_encryption": [{
                        "enabled": true,
                        "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
                    }]
                }
            }
        }]
    }
}
