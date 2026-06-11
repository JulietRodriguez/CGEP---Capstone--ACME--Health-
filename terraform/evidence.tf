######################################################################
# Evidence Vault — S3 bucket with Object Lock (GOVERNANCE mode)
# All pipeline runs upload signed evidence bundles here.
# CMMC MP.L2-3.8.9, AU.L2-3.3.1
#
# GOVERNANCE mode chosen over COMPLIANCE: allows an IAM admin to
# override retention for lifecycle / error recovery without requiring
# AWS support involvement. For a 50-person company this is the right
# trade-off; upgrade to COMPLIANCE mode if a federal customer requires it.
######################################################################

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true
  force_destroy       = false

  tags = {
    Name    = "${local.name_prefix}-evidence"
    Purpose = "compliance-evidence-vault"
    Control = "CMMC-MP.L2-3.8.9"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "evidence_tls" {
  bucket     = aws_s3_bucket.evidence.id
  depends_on = [aws_s3_bucket_public_access_block.evidence]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

######################################################################
# CloudTrail — multi-region trail, log-file-validation on
# CMMC AU.L2-3.3.1
######################################################################

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${local.name_prefix}-cloudtrail-${local.suffix}"

  # checkov:skip=CKV_AWS_21:Versioning is set in aws_s3_bucket_versioning below
  # checkov:skip=CKV2_AWS_62:Event notifications not required for audit log bucket
  # force_destroy omitted intentionally — CloudTrail logs must not be
  # accidentally deleted. Set to true only in a destroy runbook.

  tags = {
    Name    = "${local.name_prefix}-cloudtrail"
    Purpose = "audit-trail-storage"
    Control = "CMMC-AU.L2-3.3.1"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket     = aws_s3_bucket.cloudtrail.id
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail-${local.suffix}"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-trail-${local.suffix}"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail-${local.suffix}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.phi.arn

  tags = {
    Name    = "${local.name_prefix}-trail"
    Control = "CMMC-AU.L2-3.3.1"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
