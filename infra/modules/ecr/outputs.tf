output "repository_url" {
  value       = aws_ecr_repository.this.repository_url
  description = "Full ECR URL — used by CI/CD to push images and by Lambda to pull them"
}

output "repository_arn" {
  value       = aws_ecr_repository.this.arn
  description = "ECR repository ARN — used in the Lambda execution role IAM policy"
}
