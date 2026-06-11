variable "aws_region" {
  type        = string
  description = "AWS region for all resources."
  default     = "us-east-1"
}

variable "evidence_retention_days" {
  type        = number
  description = "Object Lock default retention period for evidence vault (days)."
  default     = 365
}
