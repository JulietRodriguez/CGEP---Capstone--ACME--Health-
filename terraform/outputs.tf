output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "S3 evidence vault bucket name (used by pipeline for signed bundle uploads)."
}

output "kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "ARN of the PHI customer-managed KMS key."
}

output "kms_key_id" {
  value       = aws_kms_key.phi.key_id
  description = "Key ID of the PHI CMK (for alias and policy references)."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.main.name
  description = "CloudTrail trail name."
}

output "lambda_dlq_arn" {
  value       = aws_sqs_queue.lambda_dlq.arn
  description = "ARN of the Lambda dead-letter queue."
}

output "security_alerts_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "SNS topic ARN for security alarm notifications. Subscribe your SOC email here."
}
