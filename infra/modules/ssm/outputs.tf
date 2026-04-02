output "parameter_arns" {
  value = {
    sns_topic_arn         = aws_ssm_parameter.sns_topic_arn.arn
    dynamodb_table_name   = aws_ssm_parameter.dynamodb_table_name.arn
    unused_days_threshold = aws_ssm_parameter.unused_days_threshold.arn
  }
  description = "ARNs of all SSM parameters — used for IAM policy scoping in the Lambda execution role"
}
