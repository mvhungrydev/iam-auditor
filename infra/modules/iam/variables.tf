variable "project_name" {
  type        = string
  description = "Used for resource naming and tagging"
}

variable "github_org" {
  type        = string
  description = "GitHub username or org — scopes the OIDC trust to your repo only"
}

variable "github_repo" {
  type        = string
  default     = "iam-auditor"
  description = "GitHub repository name"
}
