variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region to deploy all resources into"
}

variable "project_name" {
  type        = string
  default     = "iam-auditor"
  description = "Project name — used for resource naming and default_tags throughout all modules"
}

variable "alert_email" {
  type        = string
  description = "Email address that receives the weekly IAM audit report via SNS. Must be confirmed after first terraform apply."
}

variable "unused_days_threshold" {
  type        = number
  default     = 90
  description = "Number of days of inactivity before a credential or role is flagged as unused (rules R06, R07)"
}

variable "ecr_image_tag" {
  type        = string
  default     = "latest"
  description = "ECR image tag to deploy to Lambda. Set to a Git SHA in CI/CD for traceability. Overridden by terraform apply -var='ecr_image_tag=<sha>' in the pipeline."
}

variable "github_org" {
  type        = string
  description = "GitHub username or organization name. Scopes the OIDC trust policy so only your repo can assume the CI/CD IAM role."
}

variable "github_repo" {
  type        = string
  default     = "iam-auditor"
  description = "GitHub repository name. Combined with github_org to form the OIDC subject: repo:<org>/<repo>:ref:refs/heads/dev"
}

variable "create_demo_data" {
  type        = bool
  default     = true
  description = "When true, creates intentionally misconfigured IAM resources that trigger rules R03, R06, R07, R09, R10. Set to false to destroy demo resources. Never set to true in prod."
}
