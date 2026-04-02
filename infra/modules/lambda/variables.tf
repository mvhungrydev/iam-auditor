variable "vpc_id" {
  type        = string
  description = "VPC ID — passed from the VPC module output"
}

variable "subnet_id" {
  type        = string
  description = "Private subnet ID — Lambda runs here, passed from the VPC module output"
}

variable "lambda_role_arn" {
  type        = string
  description = "Lambda execution role ARN — passed from the IAM module output"
}

variable "image_uri" {
  type        = string
  description = "ECR image URI (repo:tag) — set in terraform.tfvars after the image is pushed"
}