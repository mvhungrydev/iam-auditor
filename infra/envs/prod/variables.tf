# Same variable set as envs/dev — prod uses the same modules with different values.
# See envs/dev/variables.tf for full descriptions.

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "iam-auditor"
}

variable "account_id" {
  type    = string
  default = "000000000000" # Placeholder value — must be overridden with real account ID in prod.tfvars
}
variable "alert_email" {
  type        = string
  description = "Email address that receives weekly IAM audit reports in prod"
}

variable "unused_days_threshold" {
  type    = number
  default = 90
}

variable "ecr_image_tag" {
  type    = string
  default = "latest"
}

variable "github_org" {
  type        = string
  description = "GitHub username or organization — scopes OIDC trust policy"
}

variable "github_repo" {
  type    = string
  default = "iam-auditor"
}

variable "create_demo_data" {
  type    = bool
  default = false # Never true in prod
}
