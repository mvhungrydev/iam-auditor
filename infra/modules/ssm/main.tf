resource "aws_ssm_parameter" "sns_topic_arn" {
  name        = "/iam-auditor/sns-topic-arn"
  type        = "String"
  tier        = "Standard"
  value       = var.sns_topic_arn
  description = "SNS topic ARN used by the Lambda auditor to publish alerts"
}

resource "aws_ssm_parameter" "dynamodb_table_name" {
  name        = "/iam-auditor/dynamodb-table-name"
  type        = "String"
  tier        = "Standard"
  value       = var.dynamodb_table_name
  description = "DynamoDB table name used by the Lambda auditor to persist findings"
}

resource "aws_ssm_parameter" "unused_days_threshold" {
  name        = "/iam-auditor/unused-days-threshold"
  type        = "String"
  tier        = "Standard"
  value       = tostring(var.unused_days_threshold)
  description = "Days of inactivity before a credential is flagged as unused (default 90)"
}
