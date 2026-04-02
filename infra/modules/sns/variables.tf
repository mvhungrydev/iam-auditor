variable "project_name" {
  type        = string
  description = "Used for resource naming and tagging"
}

variable "alert_email" {
  type        = string
  description = "Email address to receive weekly IAM audit reports"
}
