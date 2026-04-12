# CI/CD Pipeline Specification
## Project: IAM Auditor

**Version:** 1.0
**Date:** 2026-03-21
**CI/CD Platform:** GitHub Actions

---

## 1. Overview

Every code change goes through a security-gated pipeline before reaching production. No AWS credentials are stored in GitHub — authentication uses GitHub OIDC with a short-lived IAM role assumption.

```
Developer pushes code
        │
        ▼
┌───────────────────────────────────────────────────────┐
│                   GitHub Actions                      │
│                                                       │
│  On Pull Request:                                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │
│  │ gitleaks │→│  bandit  │→│ checkov  │→│  trivy  │  │
│  └──────────┘ └──────────┘ └──────────┘ └────┬────┘  │
│                                               │       │
│                                    ┌──────────▼────┐  │
│                                    │ terraform plan│  │
│                                    │ (PR comment)  │  │
│                                    └───────────────┘  │
│                                                       │
│  On Merge to dev:                                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │
│  │ gitleaks │→│  bandit  │→│ checkov  │→│  trivy  │  │
│  └──────────┘ └──────────┘ └──────────┘ └────┬────┘  │
│                                               │       │
│                            ┌──────────────────▼────┐  │
│                            │  docker build + push  │  │
│                            │  to ECR               │  │
│                            └──────────────┬────────┘  │
│                                           │           │
│                            ┌──────────────▼────────┐  │
│                            │  terraform apply      │  │
│                            │  (new image digest)   │  │
│                            └───────────────────────┘  │
└───────────────────────────────────────────────────────┘
        │
        ▼
   Lambda updated with new container image
```

---

## 2. Tooling Decision — GitHub Actions vs CodeBuild/CodePipeline

GitHub Actions was chosen over AWS-native CI/CD (CodeBuild + CodePipeline) for the following reasons:

| Factor | GitHub Actions | CodeBuild / CodePipeline |
|--------|---------------|--------------------------|
| Industry adoption | Dominant in DevOps teams today | Common in AWS-only orgs |
| Cost | 2,000 free minutes/month on public repos | Per-build-minute + per-pipeline charges |
| OIDC auth | First-class support — no stored credentials | IAM roles configured implicitly |
| Visibility | Pipeline YAML lives in the repo — reviewable alongside code | Config spread across AWS console |
| Portfolio signal | Recognizable to any DevOps reviewer | Signals AWS-only exposure |

**When CodeBuild/CodePipeline would be the right choice:**
- The organization mandates AWS-native tooling only
- The pipeline requires deep integration with CodeArtifact, CodeDeploy, or CodeCommit
- The source repository is not GitHub

For this project, GitHub Actions is the correct choice: it is free, credential-free via OIDC, and demonstrates tooling breadth relevant to the target role.

---

## 3. Pipeline Triggers

| Event | Jobs Run |
|-------|----------|
| Pull Request opened/updated against `dev` | Security scans + `terraform plan` |
| Push / merge to `dev` | Security scans + Docker build/push + `terraform apply` |
| Manual workflow dispatch | Security scans + Docker build/push + `terraform apply` |

---

## 3. Pipeline Stages

### Stage 1 — Secret Scanning (gitleaks)
**Tool:** [gitleaks](https://github.com/gitleaks/gitleaks) (open source, free)
**Purpose:** Detect hardcoded credentials, API keys, tokens in source code and git history
**Failure behavior:** Block pipeline immediately — no further stages run

```yaml
- name: Run gitleaks
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**What it catches:** AWS keys, private keys, generic high-entropy strings, common secret patterns

---

### Stage 2 — Python SAST (bandit)
**Tool:** [bandit](https://github.com/PyCQA/bandit) (open source, free)
**Purpose:** Static analysis of Python source code for security vulnerabilities
**Scope:** `src/lambda/` directory only
**Failure behavior:** Block on HIGH or CRITICAL severity findings

```yaml
- name: Run bandit
  run: |
    pip install bandit
    bandit -r src/lambda/ -ll -ii --exit-zero-on-skipped
```

**What it catches:** Hardcoded passwords, insecure random, SQL injection patterns, shell injection, use of `eval()`

---

### Stage 3 — IaC Security Scan (checkov)
**Tool:** [checkov](https://github.com/bridgecrewio/checkov) (open source, free)
**Purpose:** Scan Terraform files for infrastructure misconfigurations
**Scope:** `infra/` directory
**Failure behavior:** Block on HIGH or CRITICAL findings

```yaml
- name: Run checkov
  uses: bridgecrewio/checkov-action@master
  with:
    directory: infra/
    framework: terraform
    soft_fail: false
```

**What it catches:** S3 buckets without encryption, IAM policies with `*`, Lambda without VPC, missing CloudWatch logging, unencrypted DynamoDB

---

### Stage 4 — Container Vulnerability Scan (trivy)
**Tool:** [trivy](https://github.com/aquasecurity/trivy) (open source, free)
**Purpose:** Scan Docker image for OS and dependency CVEs before pushing to ECR
**Failure behavior:** Block on CRITICAL or HIGH CVEs with a fix available

```yaml
- name: Build image for scanning
  run: docker build -t iam-auditor-lambda:scan src/lambda/

- name: Run trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: iam-auditor-lambda:scan
    format: table
    exit-code: 1
    severity: CRITICAL,HIGH
    ignore-unfixed: true
```

**What it catches:** CVEs in the base image OS packages, outdated Python dependencies, known vulnerable library versions

---

### Stage 5 — Terraform Plan (PR only)
**Purpose:** Preview infrastructure changes before merge, post as PR comment
**Auth:** GitHub OIDC → IAM Role (no stored AWS credentials)

> **Local only:** LocalStack (`tflocal apply`) is used in Story 4.9 for local wiring validation
> before this stage is ever reached. It is not a CI pipeline stage — `terraform validate`,
> `checkov`, and the real `terraform plan` here provide equivalent coverage in CI.

**How `terraform init` finds the S3 backend:**
`infra/envs/dev/backend.tf` is committed to the repository and specifies the S3 bucket, key, region, and `use_lockfile = true`. When `terraform init` runs in CI, it reads `backend.tf` automatically — no extra flags or environment variables are needed. The OIDC role credentials already in the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` set by `configure-aws-credentials`) give Terraform the access it needs to reach S3.

The S3 bucket must already exist (bootstrapped in Story 5.0) before this stage can succeed. No DynamoDB table is required — locking uses `use_lockfile = true` (Terraform 1.10+ native S3 locking).

```yaml
- name: Terraform Init
  run: |
    cd infra/envs/dev
    # Reads backend config from backend.tf automatically — no -backend-config flags needed.
    # Authenticates to S3 + DynamoDB using OIDC role credentials from the previous step.
    terraform init

- name: Terraform Plan
  run: |
    cd infra/envs/dev
    terraform plan -no-color 2>&1 | tee plan.txt
  env:
    AWS_REGION: us-east-1

- name: Post plan to PR
  uses: actions/github-script@v7
  with:
    script: |
      const plan = require('fs').readFileSync('infra/envs/dev/plan.txt', 'utf8')
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: '### Terraform Plan\n```\n' + plan.slice(0, 65000) + '\n```'
      })
```

---

### Stage 6 — Docker Build + Push to ECR (dev only)
**Purpose:** Build the Lambda container and push to ECR with a unique image tag
**Tag strategy:** Use the Git SHA for traceability — `latest` also updated

```yaml
- name: Configure AWS credentials via OIDC
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-iam-auditor
    aws-region: us-east-1

- name: Login to ECR
  uses: aws-actions/amazon-ecr-login@v2

- name: Build, tag, and push image
  env:
    ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
    IMAGE_TAG: ${{ github.sha }}
  run: |
    docker build -t $ECR_REGISTRY/iam-auditor-lambda:$IMAGE_TAG src/lambda/
    docker tag $ECR_REGISTRY/iam-auditor-lambda:$IMAGE_TAG \
               $ECR_REGISTRY/iam-auditor-lambda:latest
    docker push $ECR_REGISTRY/iam-auditor-lambda:$IMAGE_TAG
    docker push $ECR_REGISTRY/iam-auditor-lambda:latest
    echo "IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' \
         $ECR_REGISTRY/iam-auditor-lambda:latest)" >> $GITHUB_ENV
```

---

### Stage 7 — Terraform Apply (dev only)
**Purpose:** Apply infrastructure changes and update Lambda to the new image digest

**State locking during apply:**
Before modifying any resource, `terraform apply` writes a `.tflock` file to S3 at `dev/terraform.tfstate.tflock`. No other `apply` can run while the lock file exists. After apply completes (or fails), the lock file is deleted. If a pipeline is killed mid-apply, the lock can be manually released with `terraform force-unlock <lock_id>`.

```yaml
- name: Terraform Init
  run: |
    cd infra/envs/dev
    # Reads S3 backend from backend.tf — authenticates using OIDC role credentials.
    # Downloads current dev/terraform.tfstate from S3 before computing the apply diff.
    terraform init

- name: Terraform Apply
  run: |
    cd infra/envs/dev
    terraform apply -auto-approve \
      -var="ecr_image_tag=${{ github.sha }}"
  env:
    AWS_REGION: us-east-1
```

Terraform updates `aws_lambda_function.image_uri` to the new ECR image tag, triggering Lambda to use the newly pushed container on next invocation. After apply, the updated state file is written back to `s3://iam-auditor-tf-state-<account_id>/dev/terraform.tfstate` and the S3 lock file (`dev/terraform.tfstate.tflock`) is deleted.

---

## 4. GitHub OIDC Authentication

No long-lived AWS credentials stored in GitHub Secrets. Instead:

1. GitHub Actions assumes an IAM role via OIDC token exchange
2. The IAM role has a trust policy that only allows the specific repo and branch to assume it
3. Credentials are short-lived (1 hour max)

### IAM Role Trust Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_GITHUB_USERNAME/iam-auditor:*"
        }
      }
    }
  ]
}
```

### IAM Role Permissions (CI/CD role)

The CI/CD role uses broad permissions to support Terraform's control-plane operations. Many AWS APIs (e.g. `ec2:DescribeVpcs`, `iam:CreateRole`) do not support resource-level scoping and require `Resource = "*"`. The security boundary is the OIDC trust condition — only your specific GitHub repo can assume this role.

**ECR — Docker image push**
- `ecr:GetAuthorizationToken` — authenticate Docker to ECR registry
- `ecr:BatchCheckLayerAvailability`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`

**Lambda — update function after image push**
- `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`
- `lambda:GetFunction`, `lambda:GetFunctionConfiguration`

**Terraform provisioning — manage all project resources**
- `ec2:*`, `iam:*`, `lambda:*`, `dynamodb:*`, `sns:*`, `ssm:*`, `logs:*`, `events:*`, `ecr:*`, `access-analyzer:*` on `Resource = "*"`
- Broad permissions required — Terraform cannot be scoped below service-level for control-plane operations

**Terraform remote state — read/write state file and acquire lock**
- `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket` scoped to `arn:aws:s3:::iam-auditor-tf-state-<account_id>` and its objects

> **Why state permissions are required:** `terraform init` downloads the current state from S3 before computing a plan. `terraform apply` writes a `.tflock` file to S3 before modifying resources, writes the updated state file after apply, then deletes the lock file. All locking is handled via S3 (`use_lockfile = true`) — no DynamoDB table is needed. Without these S3 permissions the pipeline fails at `terraform init` with an `AccessDenied` error.

All permissions are managed via Terraform in `infra/modules/iam/main.tf`.

---

## 5. GitHub Repository Configuration

Configure these in GitHub repo → Settings → Secrets and variables → Actions before the pipeline can run.

### Variables (non-sensitive, visible in UI)

| Name | Value | Used By | How to set |
|------|-------|---------|------------|
| `AWS_ACCOUNT_ID` | `548931596025` | OIDC role ARN in `configure-aws-credentials` step | Variables tab → New repository variable |
| `GH_ORG` | `mvhungrydev` | `TF_VAR_github_org` → Terraform IAM OIDC trust policy | Variables tab → New repository variable |

### Secrets (sensitive, masked in logs)

| Name | Value | Used By | How to set |
|------|-------|---------|------------|
| `ALERT_EMAIL` | your email address | `TF_VAR_alert_email` → SNS subscription in Terraform | Secrets tab → New repository secret |

> **Why `TF_VAR_*` prefix?** Terraform automatically reads environment variables prefixed with `TF_VAR_` as input variable values. Setting `TF_VAR_alert_email` in the pipeline environment is equivalent to passing `-var="alert_email=..."` on the command line — no hardcoded values in the workflow file.

---

## 6. Branch Protection Rules

Configure in GitHub repo → Settings → Branches → Add rule → Branch name pattern: `dev`

| Rule | Setting |
|------|---------|
| Require a pull request before merging | ✅ |
| Require status checks to pass before merging | ✅ |
| — Status check: `security-scan` | Exact job name from `deploy.yml` |
| — Status check: `terraform-plan` | Exact job name from `deploy.yml` |
| Require branches to be up to date before merging | ✅ |
| Do not allow bypassing the above settings | ✅ |

> **Note:** The status check names (`security-scan`, `terraform-plan`) will not appear in the GitHub dropdown until the workflow has run at least once. Complete Story 6.3 first, trigger a PR, then come back and add the status checks by name.

---

## 6. Full Workflow File Reference

**File location:** `.github/workflows/deploy.yml`

```yaml
name: IAM Auditor CI/CD

on:
  push:
    branches: [dev]
  pull_request:
    branches: [dev]
  workflow_dispatch:

permissions:
  id-token: write    # required for OIDC
  contents: read
  pull-requests: write  # for terraform plan PR comment

env:
  AWS_REGION: us-east-1
  ECR_REPO: iam-auditor-lambda

jobs:
  security-scan:
    name: Security Scans
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # gitleaks needs full history

      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Run bandit
        run: |
          pip install bandit
          bandit -r src/lambda/ -ll -ii

      - name: Run checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: infra/
          framework: terraform
          soft_fail: false

      - name: Build image for trivy scan
        run: docker build -t iam-auditor-scan src/lambda/

      - name: Run trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: iam-auditor-scan
          exit-code: 1
          severity: CRITICAL,HIGH
          ignore-unfixed: true

  terraform-plan:
    name: Terraform Plan
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-iam-auditor
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        # Reads S3 backend from infra/envs/dev/backend.tf automatically.
        # Downloads current state from S3 using OIDC role credentials.
        # Prerequisite: S3 bucket must already exist (bootstrapped in Story 5.0). No DynamoDB needed.
        run: cd infra/envs/dev && terraform init

      - name: Terraform Plan
        run: |
          cd infra/envs/dev
          terraform plan -no-color 2>&1 | tee plan.txt

      - name: Post plan to PR
        uses: actions/github-script@v7
        with:
          script: |
            const plan = require('fs').readFileSync('infra/envs/dev/plan.txt', 'utf8')
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '### Terraform Plan\n```\n' + plan.slice(0, 65000) + '\n```'
            })

  deploy:
    name: Build, Push, Deploy
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.ref == 'refs/heads/dev' && github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-iam-auditor
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Build, tag, push to ECR
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPO:${{ github.sha }} src/lambda/
          docker tag $ECR_REGISTRY/$ECR_REPO:${{ github.sha }} $ECR_REGISTRY/$ECR_REPO:latest
          docker push $ECR_REGISTRY/$ECR_REPO:${{ github.sha }}
          docker push $ECR_REGISTRY/$ECR_REPO:latest

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        # Reads S3 backend from infra/envs/dev/backend.tf automatically.
        # Downloads current state from S3, acquires S3 lock file before apply.
        run: cd infra/envs/dev && terraform init

      - name: Terraform Apply
        run: |
          cd infra/envs/dev
          terraform apply -auto-approve -var="ecr_image_tag=${{ github.sha }}"
```

---

## 7. Pipeline Failure Behavior

| Stage | Failure Action |
|-------|---------------|
| gitleaks | Block entire pipeline, flag commit in PR |
| bandit | Block pipeline, annotate PR with file + line number |
| checkov | Block pipeline, list failing Terraform resources |
| trivy | Block pipeline, list CVEs with fix versions |
| terraform plan | Post plan to PR, do not block (informational) |
| docker push | Block deploy stage, Lambda not updated |
| terraform apply | Post failure to workflow summary, rollback is manual |
