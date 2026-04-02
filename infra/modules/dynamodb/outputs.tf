output "table_name" {
  value       = aws_dynamodb_table.this.name
  description = "DynamoDB table name — passed to the SSM module as a parameter value"
}

output "table_arn" {
  value       = aws_dynamodb_table.this.arn
  description = "DynamoDB table ARN — available for IAM policy scoping if needed"
}
