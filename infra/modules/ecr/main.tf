#checkov:skip=CKV_AWS_136:KMS CMK not used — AES256 encryption is sufficient for a free tier portfolio project; KMS would incur additional cost
#checkov:skip=CKV_AWS_51:Image tag mutability set to MUTABLE intentionally — CI/CD must overwrite the :latest tag on every deploy
resource "aws_ecr_repository" "this" {
  name                 = "${var.project_name}-lambda"
  image_tag_mutability = "MUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "${var.project_name}-ecr" }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 3 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 3
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
