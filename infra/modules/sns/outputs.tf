output "topic_arn" {
  value       = aws_sns_topic.this.arn
  description = "SNS topic ARN — passed to the SSM module as a parameter value"
}
