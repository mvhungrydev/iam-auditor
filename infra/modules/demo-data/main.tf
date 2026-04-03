# ── R03 — User with no MFA ────────────────────────────────────────────────────

resource "aws_iam_user" "no_mfa" {
  count = var.create_demo_data ? 1 : 0
  name  = "demo-no-mfa-user"
  tags  = { Name = "demo-no-mfa-user", demo = "true" }
}

resource "aws_iam_user_login_profile" "no_mfa" {
  count                   = var.create_demo_data ? 1 : 0
  user                    = aws_iam_user.no_mfa[0].name
  password_reset_required = false
}

# ── R06 — User with stale access key ─────────────────────────────────────────

resource "aws_iam_user" "stale_key" {
  count = var.create_demo_data ? 1 : 0
  name  = "demo-stale-key-user"
  tags  = { Name = "demo-stale-key-user", demo = "true" }
}

resource "aws_iam_access_key" "stale_key" {
  count = var.create_demo_data ? 1 : 0
  user  = aws_iam_user.stale_key[0].name
}

# ── R09 — Role with inline wildcard policy ────────────────────────────────────

resource "aws_iam_role" "wildcard_inline" {
  count = var.create_demo_data ? 1 : 0
  name  = "demo-wildcard-inline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  inline_policy {
    name = "WildcardS3Policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }]
    })
  }

  tags = { Name = "demo-wildcard-inline-role", demo = "true" }
}

# ── R10 — Role with customer-managed wildcard policy ─────────────────────────

resource "aws_iam_role" "wildcard_managed" {
  count = var.create_demo_data ? 1 : 0
  name  = "demo-wildcard-managed-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "demo-wildcard-managed-role", demo = "true" }
}

resource "aws_iam_policy" "wildcard_iam" {
  count = var.create_demo_data ? 1 : 0
  name  = "demo-wildcard-iam-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:*"
      Resource = "*"
    }]
  })

  tags = { demo = "true" }
}

resource "aws_iam_role_policy_attachment" "wildcard_managed" {
  count      = var.create_demo_data ? 1 : 0
  role       = aws_iam_role.wildcard_managed[0].name
  policy_arn = aws_iam_policy.wildcard_iam[0].arn
}

# ── R07 — Role never used ─────────────────────────────────────────────────────

resource "aws_iam_role" "unused" {
  count = var.create_demo_data ? 1 : 0
  name  = "demo-unused-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "demo-unused-role", demo = "true" }
}
