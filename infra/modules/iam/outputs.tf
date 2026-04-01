output "lambda_role_arn" {
  value       = aws_iam_role.lambda.arn
  description = "Lambda execution role ARN — passed to the Lambda module"
}

output "cicd_role_arn" {
  value       = aws_iam_role.cicd.arn
  description = "GitHub Actions CI/CD role ARN — referenced in the pipeline spec"
}
