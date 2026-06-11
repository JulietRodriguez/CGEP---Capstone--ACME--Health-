package main

import future.keywords.if

# ── Failing fixture: SSE-S3 (AES256) should be denied ────────────────

test_s3_sse_s3_is_denied if {
    count(deny) == 1 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "change": {
                "actions": ["create"],
                "after": {
                    "bucket": "test-uploads-bucket",
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": "AES256",
                            "kms_master_key_id": null
                        }],
                        "bucket_key_enabled": false
                    }]
                }
            }
        }]
    }
}

# ── Passing fixture: SSE-KMS with CMK should pass ────────────────────

test_s3_kms_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "change": {
                "actions": ["create"],
                "after": {
                    "bucket": "test-uploads-bucket",
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": "aws:kms",
                            "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
                        }],
                        "bucket_key_enabled": true
                    }]
                }
            }
        }]
    }
}

# ── Delete actions are not evaluated ─────────────────────────────────

test_s3_delete_not_evaluated if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "change": {
                "actions": ["delete"],
                "after": null
            }
        }]
    }
}
