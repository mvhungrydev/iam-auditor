output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC ID — passed to Lambda security group and VPC endpoints"
}

output "public_subnet_id" {
  value       = aws_subnet.public.id
  description = "Public subnet ID"
}

output "private_subnet_id" {
  value       = aws_subnet.private.id
  description = "Private subnet ID — Lambda runs here"
}

output "private_route_table_id" {
  value       = aws_route_table.private.id
  description = "Private route table ID — Gateway Endpoints attach here"
}
