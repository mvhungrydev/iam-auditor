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

```yaml
- name: Terraform Plan
  run: |
    cd infra
    terraform init
    terraform plan -no-color -out=tfplan
  env:
    AWS_REGION: us-east-1

- name: Post plan to PR
  uses: actions/github-script@v7
  with:
    script: |
      const plan = require('fs').readFileSync('infra/tfplan.txt', 'utf8')
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: '```terraform\n' + plan + '\n```'
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

```yaml
- name: Terraform Apply
  run: |
    cd infra
    terraform init
    terraform apply -auto-approve \
      -var="ecr_image_tag=${{ github.sha }}"
  env:
    AWS_REGION: us-east-1
```

Terraform updates `aws_lambda_function.image_uri` to the new ECR image tag, triggering Lambda to use the newly pushed container on next invocation.

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
          "token.actions.githubusercontent.com:sub": "repo:YOUR_GITHUB_USERNAME/iam-auditor:ref:refs/heads/dev"
        }
      }
    }
  ]
}
```

### IAM Role Permissions (CI/CD role)
Minimum permissions for the GitHub Actions role:
- `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`, `ecr:PutImage`, etc.
- `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`
- `terraform:*` scoped to this project's resources
- Managed via Terraform in `infra/modules/iam/cicd_role.tf`

---

## 5. Branch Protection Rules

Configure in GitHub repo Settings → Branches → Branch protection rules for `dev`:

| Rule | Setting |
|------|---------|
| Require status checks to pass | ✅ All 4 scan stages + terraform plan |
| Require branches to be up to date | ✅ |
| Require pull request before merging | ✅ |
| Do not allow bypassing above settings | ✅ |

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

      - name: Terraform Plan
        run: |
          cd infra && terraform init && terraform plan -no-color 2>&1 | tee plan.txt

      - name: Post plan to PR
        uses: actions/github-script@v7
        with:
          script: |
            const plan = require('fs').readFileSync('infra/plan.txt', 'utf8')
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

      - name: Terraform Apply
        run: |
          cd infra
          terraform init
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
