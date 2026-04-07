variable "lambda_role_arn" {
  type        = string
  description = "Lambda execution role ARN — passed from the IAM module output"
}

variable "image_uri" {
  type        = string
  description = "ECR image URI (repo:tag) — set in terraform.tfvars after the image is pushed"
}
variable "project_name" {
  type        = string
  description = "Used for resource naming and tagging"
}
