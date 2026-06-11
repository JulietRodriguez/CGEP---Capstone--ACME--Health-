######################################################################
# Terraform Override — merges on top of main.tf after normal processing.
# Only gap-closing changes are listed; all other attributes are inherited
# from main.tf unchanged.
# File suffix _override.tf activates Terraform's override merge behavior.
######################################################################

# ── GAP-02: DynamoDB CMK encryption + PITR ───────────────────────────
# CMMC SC.L2-3.13.11

resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ── GAP-05 + GAP-06: Lambda VPC, DLQ, X-Ray, reserved concurrency ────
# CMMC SC.L2-3.13.1, SI.L2-3.14.6

resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  reserved_concurrent_executions = 10
}

# ── GAP-07: IAM least-privilege — replaces dynamodb:* + s3:* ─────────
# CMMC AC.L2-3.1.5

resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBMinimal"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid      = "S3UploadsWrite"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.uploads.arn}/uploads/*"
      },
      {
        Sid      = "KMSDataKeys"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.phi.arn
      },
      {
        Sid      = "DLQSend"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

# ── GAP-08: API Gateway access logging + throttling ───────────────────
# CMMC AU.L2-3.3.1

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
  }

  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
}
