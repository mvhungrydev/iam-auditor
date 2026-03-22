# IAM Auditor — Full Development Plan

## Sequenced Stories & Tasks (Local First)

**Version:** 1.0
**Date:** 2026-03-21

> **Guiding rule:** Stay local until there's no other option. Each phase builds on the previous.
> AWS is not touched until Phase 5. Everything before that runs on your machine.

---

## PHASE 1 — Local Dev Environment

**Goal:** Get a working, runnable project skeleton. `pytest` passes. Docker builds.

---

### Story 1.1 — Scaffold the Lambda source tree

_As a developer, I need the source file structure in place so I can write and import code._

**Tasks:**

- [ ] Create `src/lambda/Dockerfile` (per spec in `docs/03-technical-design.md §4`)
- [ ] Create `src/lambda/handler.py` — skeleton only: `def lambda_handler(event, context): pass`
- [ ] Create `src/lambda/auditors/__init__.py` — empty file (Python package marker)
- [ ] Create `src/lambda/auditors/access_analyzer.py` — skeleton: `def run(session, run_id): return []`
- [ ] Create `src/lambda/auditors/credential_report.py` — skeleton: `def run(session, run_id, unused_days): return []`
- [ ] Create `src/lambda/auditors/last_accessed.py` — skeleton: `def run(session, run_id, unused_days): return []`
- [ ] Create `src/lambda/auditors/policy_scanner.py` — skeleton: `def run(session, run_id): return []`

**Done when:** All files exist and `python -c "from auditors import access_analyzer, policy_scanner"` succeeds from within `src/lambda/`.

---

### Story 1.2 — Wire up the test infrastructure

_As a developer, I need moto-based fixtures so tests never touch real AWS._

**Tasks:**

- [ ] Create `pytest.ini` at project root:
  ```ini
  [pytest]
  testpaths = tests
  addopts = -v --tb=short
  ```
- [ ] Create `tests/__init__.py` — empty
- [ ] Create `tests/unit/__init__.py` — empty
- [ ] Create `tests/conftest.py` with:
  - Fake AWS env vars (`AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) — required by moto even though no real calls are made
  - `@pytest.fixture` `aws_credentials` — sets fake env vars
  - `@pytest.fixture` `boto3_session` — returns a real boto3 Session pointed at moto
  - `@pytest.fixture` `dynamodb_table` — creates `iam-audit-findings` table with correct key schema (`run_id` PK, `finding_id` SK), TTL on `expires_at`
  - `@pytest.fixture` `sns_topic` — creates SNS topic, returns ARN
  - `@pytest.fixture` `ssm_params` — seeds the 3 SSM params: `/iam-auditor/sns-topic-arn`, `/iam-auditor/dynamodb-table-name`, `/iam-auditor/unused-days-threshold`
  - All fixtures decorated with `@mock_aws` from moto

**Done when:** `pytest tests/` runs and collects 0 errors (no tests yet, but no import errors either).
cd iam-auditor
source .venv/bin/activate
pytest tests/

---

### Story 1.3 — Verify the dev environment end-to-end

_As a developer, I need `setup.sh` to run clean so any team member can onboard in one command._

**Tasks:**

- [ ] Run `bash setup.sh` from a clean shell — verify no errors
- [ ] Run `docker build -t iam-auditor-lambda src/lambda/` — verify image builds
- [ ] Confirm `pytest tests/ -q` exits 0 (no collected tests yet is fine)
- [ ] Add a `.gitignore` entry for `.venv/` if not already present

**Done when:** `setup.sh` passes, `docker build` succeeds, no errors.

---

## PHASE 2 — Lambda Business Logic (TDD with moto)

**Goal:** All 8 detection rules implemented, tested, passing. 100% local — no AWS needed.

**Order matters:** Build and test each auditor in isolation first, then wire them into `handler.py`.

---

### Story 2.1 — Credential Report Auditor (Rules R02, R03, R05, R06, R08)

_As the auditor, I need to parse the IAM Credential Report CSV to detect user hygiene issues._

**Background:** `iam:GenerateCredentialReport` + `iam:GetCredentialReport` return a CSV of all IAM users.
The CSV has columns: `user`, `password_enabled`, `password_last_used`, `mfa_active`, `access_key_1_active`,
`access_key_1_last_used_date`, `access_key_1_last_rotated`, etc.

**Tasks:**

- [ ] Write `tests/unit/test_credential_report.py` first (TDD):
  - Test R02: root row with `access_key_1_active=true` → CRITICAL finding `{"rule_id": "R02", "severity": "CRITICAL", ...}`
  - Test R03: user with `mfa_active=false` and `password_enabled=true` → HIGH finding
  - Test R05: user with `access_key_1_last_used_date` > 90 days ago → MEDIUM finding
  - Test R06: user with `access_key_1_last_rotated` > 90 days ago → MEDIUM finding
  - Test R08: user with `password_last_used` > 90 days ago → MEDIUM finding
  - Test: user with everything compliant → empty list returned
  - Test: `unused_days` threshold is respected (89 days = no finding, 91 days = finding)

- [ ] Implement `src/lambda/auditors/credential_report.py`:
  - `run(session, run_id: str, unused_days: int) -> list[dict]`
  - Call `generate_credential_report()`, poll until status is `COMPLETE`, then `get_credential_report()`
  - Decode the base64 CSV content, parse with `csv.DictReader`
  - Apply rules, return list of finding dicts (schema: `run_id`, `finding_id`, `rule_id`, `severity`, `resource_arn`, `detail`, `data_source`, `created_at`, `expires_at`)
  - `run_id` is passed in as a parameter (not generated inside the auditor — handler owns it)

**Done when:** All credential report tests pass.

---

### Story 2.2 — Policy Scanner Auditor (Rule R04)

_As the auditor, I need to detect inline IAM policies that grant wildcard actions on sensitive services._

**Background:** R04 requires fetching inline policies attached directly to IAM users (not managed policies).
The API chain is: `iam:ListUsers` → `iam:ListUserPolicies` (per user) → `iam:GetUserPolicy` (per policy name) →
parse the JSON policy document. A finding is raised if any `Statement` has `Effect=Allow` AND
`Action` contains `*` or a service-wildcard like `s3:*`, `iam:*`, `ec2:*`, or `lambda:*`.

**Tasks:**

- [ ] Write `tests/unit/test_policy_scanner.py` first (TDD):
  - Test R04: user with inline policy `Action: "*", Resource: "*"` → HIGH finding
  - Test R04: user with inline policy `Action: "s3:*"` → HIGH finding (service-level wildcard)
  - Test R04: user with inline policy `Action: ["iam:*", "ec2:DescribeInstances"]` → HIGH finding (mixed)
  - Test: user with inline policy `Action: "s3:GetObject"` (no wildcard) → no finding
  - Test: user with no inline policies → empty list returned
  - Test: multiple users, only one has a wildcard policy → only 1 finding returned
  - Test: `Effect=Deny` with wildcard action → no finding (only Allow statements flagged)

- [ ] Implement `src/lambda/auditors/policy_scanner.py`:
  - `run(session, run_id: str) -> list[dict]`
  - `list_users()` with pagination
  - For each user: `list_user_policies(UserName=...)` → list of inline policy names
  - For each policy name: `get_user_policy(UserName=..., PolicyName=...)` → policy document JSON
  - Parse statements: flag any `Effect=Allow` where `Action` is `*` or matches `s3:*`, `iam:*`, `ec2:*`, `lambda:*`
  - Sensitive services list: `["s3", "iam", "ec2", "lambda"]` (matches R04 spec)
  - `resource_arn` = user ARN; `detail` = policy name + offending action(s)
  - Return findings with `rule_id=R04`, `severity=HIGH`

**Done when:** All policy scanner tests pass.

---

### Story 2.3 — Access Analyzer Auditor (Rule R01)

_As the auditor, I need to detect external access findings from IAM Access Analyzer._

**Background:** `access-analyzer:ListAnalyzers` lists analyzers in the account. For each,
`access-analyzer:ListFindings` returns external access findings (status=ACTIVE only).

**Tasks:**

- [ ] Write `tests/unit/test_access_analyzer.py` first:
  - Test R01: analyzer with 1 active ACTIVE finding → 1 CRITICAL finding returned
  - Test: finding with status=ARCHIVED → not returned
  - Test: no analyzers in account → empty list returned (graceful, not an error)
  - Test: analyzer exists but 0 findings → empty list returned

- [ ] Implement `src/lambda/auditors/access_analyzer.py`:
  - `run(session, run_id: str) -> list[dict]`
  - `list_analyzers()`, iterate; for each call `list_findings(analyzerArn=..., filter={"status": {"eq": ["ACTIVE"]}})`
  - Map each finding to the finding schema with `rule_id=R01`, `severity=CRITICAL`
  - `resource_arn` = finding's `resource` field; `detail` = finding's `action` list joined

**Done when:** All access analyzer tests pass.

---

### Story 2.4 — Last Accessed Auditor (Rule R07)

_As the auditor, I need to detect IAM roles that haven't been used in 90+ days._

**Background:** `iam:ListRoles` lists all roles. For each, `iam:GenerateServiceLastAccessedDetails`
kicks off an async job. Poll `iam:GetServiceLastAccessedDetails` until `JobStatus=COMPLETED`.
If `LastAuthenticated` is null or > 90 days ago, the role is flagged.

**Tasks:**

- [ ] Write `tests/unit/test_last_accessed.py` first:
  - Test R07: role with `LastAuthenticated` = 91 days ago → MEDIUM finding
  - Test: role with `LastAuthenticated` = 10 days ago → no finding
  - Test: role with `LastAuthenticated` = null (never used) → MEDIUM finding
  - Test: service role (trust policy principal is a service like `lambda.amazonaws.com`) → still flagged (no exclusion)
  - Test: empty roles list → empty list returned

- [ ] Implement `src/lambda/auditors/last_accessed.py`:
  - `run(session, run_id: str, unused_days: int) -> list[dict]`
  - `list_roles()` with pagination; skip roles with path prefix `/aws-service-role/` (AWS-managed)
  - For each role: `generate_service_last_accessed_details(Arn=role_arn)` → `job_id`
  - Poll `get_service_last_accessed_details(JobId=job_id)` until `JobStatus == COMPLETED`
  - Find the most recent `LastAuthenticated` across all services for the role
  - Apply 90-day threshold, emit R07 finding if exceeded

**Done when:** All last accessed tests pass.

---

### Story 2.5 — Handler (Orchestration + DynamoDB + SNS)

_As the Lambda entry point, handler.py must read config, run all auditors, store findings, and send the email._

**Tasks:**

- [ ] Write `tests/unit/test_handler.py` first:
  - Use conftest `dynamodb_table`, `sns_topic`, `ssm_params` fixtures
  - Monkeypatch all 4 auditors' `run()` to return controlled sets of findings
  - Test: handler reads the 3 SSM params correctly
  - Test: handler writes each finding to DynamoDB (`PutItem` for each) with correct key schema
  - Test: handler publishes 1 SNS message with the correct subject format `[IAM Auditor] Weekly Report — YYYY-MM-DD`
  - Test: SNS body contains `CRITICAL`, `HIGH`, `MEDIUM` counts
  - Test: handler returns dict with `run_id`, `total`, `critical`, `high`, `medium`
  - Test: if all auditors return empty lists → runs fine, SNS published with 0 findings

- [ ] Implement `src/lambda/handler.py`:
  - `lambda_handler(event, context)` entry point
  - Generate `run_id = f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"`
  - Read 3 SSM params via `ssm.get_parameter()`
  - Call all 4 auditors, collect `findings = []`
  - Write each finding to DynamoDB with `put_item()`
  - Build SNS email body per the format in `docs/03-technical-design.md §8`
  - Publish to SNS
  - Return summary dict

**Done when:** All handler tests pass. Full `pytest tests/` suite is green.

---

### Story 2.6 — Coverage gate

_As a developer, I want to see coverage before moving on to containers._

**Tasks:**

- [ ] Run `pytest --cov=src/lambda --cov-report=term-missing tests/`
- [ ] Confirm >= 80% coverage on all 4 modules (`handler.py`, each auditor)
- [ ] Fix any untested branches surfaced by the report

**Done when:** Coverage report shows ≥ 80% across all Lambda modules.

---

## PHASE 3 — Docker Container (Local)

**Goal:** The Lambda container builds and is invokable locally. No AWS needed.

---

### Story 3.1 — Build and smoke-test the container

_As a developer, I want to build the Lambda container and invoke it locally to prove the entry point works._

**Background:** AWS provides the Lambda Runtime Interface Emulator (RIE) inside the
`public.ecr.aws/lambda/python:3.12` base image. Running it locally exposes a REST endpoint
that accepts invocation payloads.

**Tasks:**

- [ ] Run `docker build -t iam-auditor-lambda src/lambda/` — should succeed
- [ ] Run the container with RIE:
  ```bash
  docker run -p 9000:8080 \
    -e AWS_DEFAULT_REGION=us-east-1 \
    -e AWS_ACCESS_KEY_ID=fake \
    -e AWS_SECRET_ACCESS_KEY=fake \
    iam-auditor-lambda
  ```
- [ ] Send a test invocation:
  ```bash
  curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
  ```
- [ ] Verify the response is a valid JSON dict (will likely fail on real AWS calls — that's expected at this stage)
- [ ] Verify no import errors or syntax errors in the response

**Done when:** Container starts, accepts invocations, returns JSON (not a crash).

---

### Story 3.2 — Container security scan (local)

_As a developer, I want to run Trivy locally before CI to catch CVEs early._

**Tasks:**

- [ ] Install Trivy locally: `brew install trivy`
- [ ] Run `trivy image --severity CRITICAL,HIGH --ignore-unfixed iam-auditor-lambda`
- [ ] Investigate any findings; pin or update `requirements.txt` if needed
- [ ] Document any accepted risks (e.g. base image OS CVEs with no fix available)

**Done when:** Trivy scan passes with no CRITICAL or HIGH fixable CVEs.

---

## PHASE 4 — Terraform (Local Validation, No AWS Yet)

**Goal:** All Terraform is written and passes `validate`, `fmt`, and `checkov`. No `terraform apply` yet.

---

### Story 4.1 — Scaffold Terraform module structure

_As a developer, I need the directory skeleton created before writing any `.tf` content._

**Tasks:**

- [ ] Create `infra/modules/vpc/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/modules/ecr/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/modules/iam/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/modules/lambda/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/modules/dynamodb/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/modules/sns/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/modules/ssm/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Create `infra/envs/dev/` with `main.tf`, `variables.tf`, `terraform.tfvars`, `outputs.tf`, `versions.tf`, `backend.tf`
- [ ] Create `infra/envs/prod/` with same file set (placeholder — not deployed initially)
- [ ] Add `infra/envs/dev/terraform.tfvars` to `.gitignore` (contains email address)

**Done when:** Directory structure matches `docs/04-infrastructure-spec.md §1` exactly.

---

### Story 4.2 — Write the VPC module

_Resources: VPC, 2 subnets, IGW, 2 route tables, S3 + DynamoDB Gateway Endpoints_

**Tasks:**

- [ ] Write `infra/modules/vpc/main.tf` for all resources in `docs/04-infrastructure-spec.md §2`
- [ ] Expose outputs: `vpc_id`, `private_subnet_id`, `public_subnet_id`, `private_route_table_id`
- [ ] Run `terraform fmt` and `terraform validate` from `infra/envs/dev/`

---

### Story 4.3 — Write the ECR module

_Resources: ECR repository + lifecycle policy (keep last 3 images)_

**Tasks:**

- [ ] Write `infra/modules/ecr/main.tf`
- [ ] Expose outputs: `repository_url`, `repository_arn`
- [ ] Lifecycle policy JSON matches `docs/04-infrastructure-spec.md §5`

---

### Story 4.4 — Write the IAM module

_Resources: Lambda execution role + least-privilege policy (4 statements from `docs/03-technical-design.md §6`)_

**Tasks:**

- [ ] Write `infra/modules/iam/main.tf`
- [ ] Embed the full 4-statement IAM policy from the technical design doc
- [ ] Also create the CI/CD OIDC role and its trust policy (from `docs/05-cicd-pipeline-spec.md §4`)
- [ ] Expose outputs: `lambda_role_arn`, `cicd_role_arn`

---

### Story 4.5 — Write the DynamoDB module

_Resources: DynamoDB table with PAY_PER_REQUEST billing, TTL on `expires_at`_

**Tasks:**

- [ ] Write `infra/modules/dynamodb/main.tf`
- [ ] Key schema: `run_id` (HASH) + `finding_id` (RANGE) per `docs/04-infrastructure-spec.md §3`
- [ ] Enable TTL on `expires_at` attribute
- [ ] Expose outputs: `table_name`, `table_arn`

---

### Story 4.6 — Write the SNS module

_Resources: SNS topic + email subscription_

**Tasks:**

- [ ] Write `infra/modules/sns/main.tf`
- [ ] Topic name: `iam-auditor-alerts`
- [ ] Email subscription protocol with `alert_email` variable
- [ ] Expose outputs: `topic_arn`

---

### Story 4.7 — Write the SSM module

_Resources: 3 SSM Standard parameters_

**Tasks:**

- [ ] Write `infra/modules/ssm/main.tf`
- [ ] Parameters: `/iam-auditor/sns-topic-arn`, `/iam-auditor/dynamodb-table-name`, `/iam-auditor/unused-days-threshold`
- [ ] Values are passed in as variables (wired from other module outputs in `envs/dev/main.tf`)
- [ ] Expose outputs: `parameter_arns` map

---

### Story 4.8 — Write the Lambda module

_Resources: Security group, Lambda function (container), CloudWatch log group, EventBridge rule + target + permission_

**Tasks:**

- [ ] Write `infra/modules/lambda/main.tf`
- [ ] Security group: no inbound, HTTPS egress to `0.0.0.0/0`
- [ ] Lambda: `package_type = "Image"`, `image_uri` variable for ECR image
- [ ] CloudWatch log group: retention 7 days
- [ ] EventBridge rule: `cron(0 8 ? * MON *)` (every Monday 08:00 UTC)
- [ ] Expose outputs: `function_arn`, `function_name`

---

### Story 4.9 — Wire up `infra/envs/dev/main.tf`

_The env entrypoint calls all modules, passing outputs between them._

**Tasks:**

- [ ] Write `infra/envs/dev/versions.tf`: Terraform >= 1.6, AWS provider ~> 5.0
- [ ] Write `infra/envs/dev/backend.tf`: local backend for now (comment shows S3 upgrade path)
- [ ] Write `infra/envs/dev/main.tf`: call all 7 modules, wire outputs (SNS ARN → SSM, etc.)
- [ ] Write `infra/envs/dev/variables.tf`: expose `alert_email`, `aws_region`, `ecr_image_tag`, `unused_days_threshold`
- [ ] Write `infra/envs/dev/terraform.tfvars`: set your email, region = `us-east-1`, threshold = `90`
- [ ] Copy `envs/dev/` structure to `envs/prod/` (placeholder — not deployed)

---

### Story 4.10 — Local Terraform validation

_Catch all config errors before any AWS calls._

**Tasks:**

- [ ] Run `terraform init` from `infra/envs/dev/` (downloads providers locally — no AWS auth needed)
- [ ] Run `terraform validate` — fix all errors
- [ ] Run `terraform fmt -recursive infra/` — enforce formatting
- [ ] Run `checkov -d infra/ --framework terraform` locally:
  - Install: `pip install checkov` (add to `requirements-dev.txt`)
  - Address or suppress each finding with documented justification
- [ ] Run `bandit -r src/lambda/ -ll -ii` locally — fix any findings

**Done when:** `validate` passes, `checkov` passes (or all suppressions are documented), `bandit` clean.

---

## PHASE 5 — AWS First Deploy (Dev Environment)

**Goal:** Infrastructure is live in AWS. Lambda invokes successfully against real AWS APIs.
_This is the first time you touch AWS._

**Prerequisites:** AWS CLI configured (`aws configure`), account has IAM Access Analyzer enabled.

---

### Story 5.1 — Bootstrap AWS prerequisites (one-time, manual)

_Resources that Terraform can't create itself (the bootstrapping paradox)._

**Tasks:**

- [ ] Confirm your AWS CLI identity: `aws sts get-caller-identity`
- [ ] Verify IAM Access Analyzer is enabled in `us-east-1` (console → Security → IAM Access Analyzer)
- [ ] Run `terraform apply -target=module.ecr` first to create the ECR repo before pushing the image

---

### Story 5.2 — Push the first Docker image to ECR

**Tasks:**

- [ ] Authenticate Docker to ECR:
  ```bash
  aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin <account_id>.dkr.ecr.us-east-1.amazonaws.com
  ```
- [ ] Build + tag + push:
  ```bash
  docker build -t iam-auditor-lambda src/lambda/
  docker tag iam-auditor-lambda:latest <ecr_url>:latest
  docker push <ecr_url>:latest
  ```

---

### Story 5.3 — `terraform apply` to dev

**Tasks:**

- [ ] `cd infra/envs/dev && terraform apply`
- [ ] Confirm all resources created: VPC, subnets, endpoints, DynamoDB, SNS, SSM, Lambda, EventBridge
- [ ] Check email inbox for SNS subscription confirmation — click the link

---

### Story 5.4 — Manual Lambda invocation test

_Verify the real Lambda calls real AWS APIs and produces real findings._

**Tasks:**

- [ ] Invoke the Lambda manually:
  ```bash
  aws lambda invoke \
    --function-name iam-auditor \
    --payload '{}' \
    response.json && cat response.json
  ```
- [ ] Check CloudWatch Logs: `aws logs tail /aws/lambda/iam-auditor --follow`
- [ ] Check DynamoDB for findings: scan the `iam-audit-findings` table
- [ ] Check email inbox for the weekly report (SNS message)
- [ ] Verify findings match expected rules for your account

**Done when:** Lambda invokes successfully, findings are in DynamoDB, email is received.

---

## PHASE 6 — CI/CD Pipeline (GitHub Actions)

**Goal:** Automated security scanning + deploy on every push to `main`.

---

### Story 6.1 — GitHub repository setup

**Tasks:**

- [ ] Push all local code to GitHub (`git push origin dev`)
- [ ] Set up branch protection on `main`: require PR, require status checks
- [ ] Set GitHub repo variable `AWS_ACCOUNT_ID` (repo Settings → Variables)

---

### Story 6.2 — GitHub OIDC trust (one-time AWS setup)

**Tasks:**

- [ ] Create the GitHub OIDC identity provider in IAM (Terraform-managed in `infra/modules/iam/`)
- [ ] Verify the OIDC provider was created: `aws iam list-open-id-connect-providers`
- [ ] Verify the CI/CD role trust policy matches your repo and `main` branch

---

### Story 6.3 — Write the GitHub Actions workflow

**Tasks:**

- [ ] Create `.github/workflows/deploy.yml` per the full YAML in `docs/05-cicd-pipeline-spec.md §6`
- [ ] Jobs: `security-scan` → `terraform-plan` (PR only) → `deploy` (main only)
- [ ] Verify gitleaks, bandit, checkov, trivy stages match the spec
- [ ] Verify OIDC credential step uses `role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-iam-auditor`

---

### Story 6.4 — End-to-end pipeline test

**Tasks:**

- [ ] Create a feature branch, make a small change, open a PR to `main`
- [ ] Verify all 4 security scans pass in GitHub Actions
- [ ] Verify `terraform plan` output is posted as a PR comment
- [ ] Merge the PR, verify the deploy job runs: Docker build → ECR push → `terraform apply`
- [ ] Verify Lambda is updated to the new image (check `image_uri` in Lambda console)

**Done when:** Full pipeline runs green on a real PR merge.

---

## Summary: Phase Gate Checklist

| Phase               | Gate Condition                                       | AWS?    |
| ------------------- | ---------------------------------------------------- | ------- |
| 1 — Dev Environment | `setup.sh` passes, `docker build` succeeds           | No      |
| 2 — Lambda Logic    | `pytest` 100% green, ≥80% coverage                   | No      |
| 3 — Container       | Container starts, passes Trivy scan                  | No      |
| 4 — Terraform       | `validate` + `checkov` + `bandit` all pass           | No      |
| 5 — First Deploy    | Lambda invokes, findings in DynamoDB, email received | **Yes** |
| 6 — CI/CD           | PR pipeline green, deploy pipeline green             | **Yes** |

---

## Key File Paths (Reference)

| Artifact                   | Path                                                   |
| -------------------------- | ------------------------------------------------------ |
| Lambda entry point         | `src/lambda/handler.py`                                |
| Auditor: credential report | `src/lambda/auditors/credential_report.py`             |
| Auditor: access analyzer   | `src/lambda/auditors/access_analyzer.py`               |
| Auditor: last accessed     | `src/lambda/auditors/last_accessed.py`                 |
| Auditor: policy scanner    | `src/lambda/auditors/policy_scanner.py`                |
| Dockerfile                 | `src/lambda/Dockerfile`                                |
| Test fixtures              | `tests/conftest.py`                                    |
| Unit tests                 | `tests/unit/test_*.py`                                 |
| Terraform modules          | `infra/modules/{vpc,ecr,iam,lambda,dynamodb,sns,ssm}/` |
| Dev environment            | `infra/envs/dev/`                                      |
| CI/CD workflow             | `.github/workflows/deploy.yml`                         |
| Dev setup                  | `setup.sh`                                             |
