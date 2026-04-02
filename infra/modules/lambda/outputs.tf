output "function_arn" {
  value       = aws_lambda_function.this.arn
  description = "Lambda function ARN — used by EventBridge target and for reference"
}

output "function_name" {
  value       = aws_lambda_function.this.function_name
  description = "Lambda function name — used for CloudWatch log group naming and CLI invocations"
}
