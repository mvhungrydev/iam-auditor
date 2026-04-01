variable "project_name" {
  type        = string
  description = "Used for resource naming and tagging"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block for the VPC"
}

variable "public_subnet_cidr" {
  type        = string
  default     = "10.0.1.0/24"
  description = "CIDR block for the public subnet"
}

variable "private_subnet_cidr" {
  type        = string
  default     = "10.0.2.0/24"
  description = "CIDR block for the private subnet"
}

variable "az" {
  type        = string
  default     = "us-east-1a"
  description = "Availability zone for both subnets"
}
