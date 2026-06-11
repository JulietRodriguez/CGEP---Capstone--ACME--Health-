package main

import future.keywords.if

# ── Failing: versioning suspended ────────────────────────────────────

test_s3_versioning_suspended_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_versioning.uploads",
            "type": "aws_s3_bucket_versioning",
            "change": {
                "actions": ["create"],
                "after": {
                    "bucket": "test-bucket",
                    "versioning_configuration": [{"status": "Suspended"}]
                }
            }
        }]
    }
}

# ── Passing: versioning enabled ───────────────────────────────────────

test_s3_versioning_enabled_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_versioning.uploads",
            "type": "aws_s3_bucket_versioning",
            "change": {
                "actions": ["create"],
                "after": {
                    "bucket": "test-bucket",
                    "versioning_configuration": [{"status": "Enabled"}]
                }
            }
        }]
    }
}
