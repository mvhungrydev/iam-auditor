variable "project_name" {
  type        = string
  description = "Used for tagging demo resources"
}

variable "create_demo_data" {
  type        = bool
  default     = false
  description = "Set to true to create intentionally misconfigured IAM resources for demo purposes. Set to false to destroy them."
}
