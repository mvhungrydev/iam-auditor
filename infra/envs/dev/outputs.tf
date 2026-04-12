# -----------------------------------------------------------------------------
# Lambda outputs
# -----------------------------------------------------------------------------
output "lambda_function_name" {
  value       = module.lambda.function_name
  description = "Lambda function name — use with: aws lambda invoke --function-name <value>"
}

output "lambda_function_arn" {
  value       = module.lambda.function_arn
  description = "Lambda function ARN — referenced by EventBridge target"
}

# -----------------------------------------------------------------------------
# ECR outputs
# -----------------------------------------------------------------------------
output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "Full ECR URL — use for docker tag and docker push commands in Story 5.2"
}

# -----------------------------------------------------------------------------
# IAM outputs
# -----------------------------------------------------------------------------
output "cicd_role_arn" {
  value       = module.iam.cicd_role_arn
  description = "GitHub Actions OIDC role ARN — set as role-to-assume in the CI/CD workflow"
}

# -----------------------------------------------------------------------------
# DynamoDB outputs
# -----------------------------------------------------------------------------
output "dynamodb_table_name" {
  value       = module.dynamodb.table_name
  description = "Findings table name — use with: aws dynamodb scan --table-name <value>"
}

# -----------------------------------------------------------------------------
# SNS outputs
# -----------------------------------------------------------------------------
output "sns_topic_arn" {
  value       = module.sns.topic_arn
  description = "SNS topic ARN — check subscription confirmation email before first Lambda run"
}
