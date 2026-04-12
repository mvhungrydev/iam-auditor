output "lambda_function_name" {
  value       = module.lambda.function_name
  description = "Lambda function name"
}

output "lambda_function_arn" {
  value       = module.lambda.function_arn
  description = "Lambda function ARN"
}

output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "ECR repository URL"
}

output "cicd_role_arn" {
  value       = module.iam.cicd_role_arn
  description = "GitHub Actions OIDC role ARN"
}

output "dynamodb_table_name" {
  value       = module.dynamodb.table_name
  description = "Findings table name"
}

output "sns_topic_arn" {
  value       = module.sns.topic_arn
  description = "SNS alert topic ARN"
}
