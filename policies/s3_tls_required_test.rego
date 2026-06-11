package main

import future.keywords.if

# ── Failing: bucket policy with no TLS deny ───────────────────────────

test_s3_no_tls_deny_denied if {
    count(deny) > 0 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_policy.uploads_tls",
            "type": "aws_s3_bucket_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "bucket": "test-bucket",
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowAll\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::test-bucket/*\"}]}"
                }
            }
        }]
    }
}

# ── Passing: bucket policy with TLS deny ─────────────────────────────

test_s3_tls_deny_passes if {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_policy.uploads_tls",
            "type": "aws_s3_bucket_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "bucket": "test-bucket",
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyNonTLS\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::test-bucket\",\"arn:aws:s3:::test-bucket/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
                }
            }
        }]
    }
}
