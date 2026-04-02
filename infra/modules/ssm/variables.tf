variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN — passed from the SNS module output"
}

variable "dynamodb_table_name" {
  type        = string
  description = "DynamoDB table name — passed from the DynamoDB module output"
}

variable "unused_days_threshold" {
  type        = number
  default     = 90
  description = "Number of days of inactivity before a credential is flagged as unused"
}
