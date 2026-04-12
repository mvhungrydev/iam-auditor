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

- [x] Create `src/lambda/Dockerfile` (per spec in `docs/03-technical-design.md §4`)
- [x] Create `src/lambda/handler.py` — skeleton only: `def lambda_handler(event, context): pass`
- [x] Create `src/lambda/auditors/__init__.py` — empty file (Python package marker)
- [x] Create `src/lambda/auditors/access_analyzer.py` — skeleton: `def run(session, run_id): return []`
- [x] Create `src/lambda/auditors/credential_report.py` — skeleton: `def run(session, run_id, unused_days): return []`
- [x] Create `src/lambda/auditors/last_accessed.py` — skeleton: `def run(session, run_id, unused_days): return []`
- [x] Create `src/lambda/auditors/policy_scanner.py` — skeleton: `def run(session, run_id): return []`

**Done when:** All files exist and `python -c "from auditors import access_analyzer, policy_scanner"` succeeds from within `src/lambda/`.

---

### Story 1.2 — Wire up the test infrastructure

_As a developer, I need moto-based fixtures so tests never touch real AWS._

**Tasks:**

- [x] Create `pytest.ini` at project root:
  ```ini
  [pytest]
  testpaths = tests
  addopts = -v --tb=short
  ```
- [x] Create `tests/__init__.py` — empty
- [x] Create `tests/unit/__init__.py` — empty
- [x] Create `tests/conftest.py` with:
  - Fake AWS env vars (`AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) — required by moto even though no real calls are made
  - `@pytest.fixture` `aws_credentials` — sets fake env vars
  - `@pytest.fixture` `boto3_session` — returns a real boto3 Session pointed at moto
  - `@pytest.fixture` `dynamodb_table` — creates `iam-audit-findings` table with correct key schema (`run_id` PK, `finding_id` SK), TTL on `expires_at`
  - `@pytest.fixture` `sns_topic` — creates SNS topic, returns ARN
  - `@pytest.fixture` `ssm_params` — seeds the 3 SSM params: `/iam-auditor/sns-topic-arn`, `/iam-auditor/dynamodb-table-name`, `/iam-auditor/unused-days-threshold`
  - All fixtures decorated with `@mock_aws` from moto

**Done when:** `pytest tests/` runs and collects 0 errors (no tests yet, but no import errors either).

---

### Story 1.3 — Verify the dev environment end-to-end

_As a developer, I need `setup.sh` to run clean so any team member can onboard in one command._

**Tasks:**

- [x] Run `bash setup.sh` from a clean shell — verify no errors
- [x] Run `docker build -t iam-auditor-lambda src/lambda/` — verify image builds
- [x] Confirm `pytest tests/ -q` exits 0 (no collected tests yet is fine)
- [x] Add a `.gitignore` entry for `.venv/` if not already present

**Done when:** `setup.sh` passes, `docker build` succeeds, no errors.

---

## PHASE 2 — Lambda Business Logic (TDD with moto)

**Goal:** All 8 detection rules implemented, tested, passing. 100% local — no AWS needed.

**Order matters:** Build and test each auditor in isolation first, then wire them into `handler.py`.

---

### Story 2.1 — Credential Report Auditor (Rules R02, R03, R05, R06, R08)

_As the auditor, I need to parse the IAM Credential Report CSV to detect user hygiene issues._

**Background:** `iam:GenerateCredentialReport` is async — it kicks off a background job and returns
immediately. You must poll `iam:GetCredentialReport` until the response `State` field equals `COMPLETE`
before reading the CSV. The report is returned as base64-encoded bytes; decode with `.decode("utf-8")`
before parsing.

The CSV always has a `<root_account>` row as its first data row. This row uses the string literal
`"<root_account>"` as the username — not a real IAM user. R02 targets this row specifically.
`resource_arn` for the root row is set to the string `"root"` since root has no ARN in IAM.

The CSV columns relevant to these rules:
- `user` — IAM username (or `<root_account>`)
- `password_enabled` — `"true"` / `"false"` / `"not_supported"` (root uses `"not_supported"`)
- `mfa_active` — `"true"` / `"false"`
- `access_key_1_active` — `"true"` / `"false"`
- `access_key_1_last_used_date` — ISO date string or `"N/A"`
- `access_key_1_last_rotated` — ISO date string or `"N/A"`
- `password_last_used` — ISO date string, `"no_information"`, or `"N/A"`

**Tasks:**

- [x] Write `tests/unit/test_credential_report.py` first (TDD):

  **Why botocore patching is needed for R02 and R06:**
  moto's `generate_credential_report` always returns a report built from whatever IAM state you've
  set up in moto — you cannot inject a root access key or a specific `last_rotated` date directly
  through the moto API. For these two rules, the test patches `botocore.client.BaseClient._make_api_call`
  to return a hand-crafted CSV response. This bypasses moto entirely for those two calls.
  Using `patch.object` on the class does not work here — boto3 creates new client instances inside
  `run()`, and `patch.object` only affects the specific instance it was called on. Patching the
  class-level method via `patch("botocore.client.BaseClient._make_api_call", ...)` intercepts all
  instances including ones created after the patch is applied.

  - Test R02: patch `GetCredentialReport` to return CSV with root row `access_key_1_active=true` → CRITICAL finding with `resource_arn="root"`
  - Test R03: create moto IAM user with no MFA, `password_enabled=true` → HIGH finding
  - Test R05: create moto IAM user with access key last used > 90 days ago → MEDIUM finding
  - Test R06: patch `GetCredentialReport` to return CSV with `access_key_1_last_rotated` > 90 days ago → MEDIUM finding
  - Test R08: create moto IAM user with `password_last_used` > 90 days ago → MEDIUM finding
  - Test: user with everything compliant → empty list returned
  - Test: `unused_days` threshold is respected (89 days = no finding, 91 days = finding)

- [x] Implement `src/lambda/auditors/credential_report.py`:
  - `run(session, run_id: str, unused_days: int) -> list[dict]`
  - Call `generate_credential_report()`, then poll `get_credential_report()` in a `while True` loop
    until `response["State"] == "COMPLETE"`
  - The report content is at `response["Content"]` — a bytes object. Decode with `.decode("utf-8")`
    then parse with `csv.DictReader(io.StringIO(content))`
  - Skip any date field that equals `"N/A"` or `"no_information"` — treat as no data
  - Apply rules, return list of finding dicts (schema: `run_id`, `finding_id`, `rule_id`, `severity`,
    `resource_arn`, `detail`, `data_source`, `created_at`, `expires_at`)
  - `run_id` is passed in as a parameter — the handler owns `run_id` generation, not the auditor

**Done when:** All credential report tests pass. ✅ (7/7 green)

---

### Story 2.2 — Policy Scanner Auditor (Rules R04, R09, R10)

_As the auditor, I need to detect inline IAM policies that grant wildcard actions on sensitive services._

**Background:** There are two types of IAM policies — inline and managed.
- **Inline policies** are embedded directly on a user or role and only exist for that principal.
  R04 (users) and R09 (roles) target inline policies.
- **Managed policies** are standalone objects that can be attached to multiple principals.
  AWS-managed policies (ARN prefix `arn:aws:iam::aws:`) are maintained by AWS and are intentionally
  broad — skip them. R10 only targets customer-managed policies (no `arn:aws:iam::aws:` prefix).

**Why `get_user_policy` returns URL-encoded JSON:**
The IAM API returns inline policy documents as URL-encoded JSON strings, not plain JSON. Before
parsing with `json.loads()`, decode with `urllib.parse.unquote()`. Skipping this step causes a
JSON parse error.

**Why `DefaultVersionId` is needed for R10:**
A managed policy can have multiple versions. `get_policy()` returns the policy metadata including
`DefaultVersionId` (e.g. `"v3"`). You then call `get_policy_version(PolicyArn=..., VersionId="v3")`
to retrieve the actual policy document. The document is also URL-encoded — apply `unquote()` before
parsing.

**Why only SENSITIVE_SERVICES are flagged:**
A service wildcard like `sqs:*` or `cloudwatch:*` is overly permissive but lower risk than `iam:*`
or `ec2:*`. The auditor scopes findings to the highest-impact services: `{"s3", "iam", "ec2", "lambda"}`.
A full wildcard `"*"` is always flagged regardless of service.

**Tasks:**

- [x] Write `tests/unit/test_policy_scanner.py` first (TDD):
  - Test R04: user with inline policy `Action: "*", Resource: "*"` → HIGH finding
  - Test R04: user with inline policy `Action: "s3:*"` → HIGH finding (service-level wildcard)
  - Test R04: user with inline policy `Action: ["iam:*", "ec2:DescribeInstances"]` → HIGH finding (mixed — one wildcard in a list is enough)
  - Test: user with inline policy `Action: "s3:GetObject"` (no wildcard) → no finding
  - Test: user with no inline policies → empty list returned
  - Test: multiple users, only one has a wildcard policy → only 1 finding returned
  - Test: `Effect=Deny` with wildcard action → no finding (only `Effect=Allow` is flagged)
  - Test R09: role with inline policy `Action: "*"` → HIGH finding
  - Test R09: role with inline policy `Action: "s3:*"` → HIGH finding
  - Test R09: role with inline policy `Action: ["iam:*", "ec2:DescribeInstances"]` → HIGH finding (mixed)
  - Test: role with inline policy `Action: "s3:GetObject"` → no finding
  - Test: role with no inline policies → no finding
  - Test: multiple roles, only one flagged → only 1 R09 finding
  - Test: `Effect=Deny` with wildcard on role → no finding
  - Test R10: role with customer-managed policy `Action: "*"` attached → HIGH finding
  - Test R10: role with customer-managed policy `Action: "s3:*"` attached → HIGH finding
  - Test R10: role with customer-managed policy `Action: ["iam:*", "ec2:DescribeInstances"]` → HIGH finding
  - Test: role with scoped customer-managed policy → no finding
  - Test: role with no attached managed policies → no finding
  - Test: multiple roles, only one flagged → only 1 R10 finding
  - Test: AWS-managed policy (ARN `arn:aws:iam::aws:`) attached to role → no R10 finding (skipped)
  - Test: role with two wildcard managed policies → 2 R10 findings

- [x] Implement `src/lambda/auditors/policy_scanner.py`:
  - `run(session, run_id: str) -> list[dict]`
  - R04: paginate `list_users()` → for each user call `list_user_policies` → for each policy name
    call `get_user_policy` → URL-decode and parse the document → check statements
    resource_arn = user ARN, rule_id = R04, severity = HIGH
  - R09: paginate `list_roles()` → `list_role_policies` → `get_role_policy` per role → same
    document parsing as R04. resource_arn = role ARN, rule_id = R09, severity = HIGH
  - R10: paginate `list_roles()` → `list_attached_role_policies` → skip any ARN starting with
    `arn:aws:iam::aws:` → `get_policy` returns `DefaultVersionId` → `get_policy_version` returns
    the document → URL-decode, parse, check statements. rule_id = R10, severity = HIGH
  - `_is_wildcard_action(action)` helper: returns `True` for `"*"` or `"<service>:*"` where service
    is in SENSITIVE_SERVICES. Normalises to lowercase before checking.
  - SENSITIVE_SERVICES = `{"s3", "iam", "ec2", "lambda"}`
  - `detail` = resource name + policy name + offending action(s) joined into a readable string

**Done when:** All policy scanner tests pass. ✅ (R04/R09/R10 — 25 tests green)

---

### Story 2.3 — Access Analyzer Auditor (Rule R01)

_As the auditor, I need to detect external access findings from IAM Access Analyzer._

**Background:** IAM Access Analyzer continuously monitors resource-based policies (S3 buckets, IAM roles,
KMS keys, etc.) and flags any resource that grants access to a principal outside the AWS account.
`list_analyzers()` returns all analyzers configured in the account — an account may have zero (if the
feature is not enabled) or more than one (e.g. one per region). For each analyzer, `list_findings()`
returns the findings it has detected.

**Finding statuses:**
- `ACTIVE` — the resource is currently externally accessible. This is what we flag.
- `ARCHIVED` — the account owner acknowledged and dismissed the finding. Do not flag these.
- `RESOLVED` — the policy was fixed and the finding is no longer active. Do not flag these.

We filter at the API level with `filter={"status": {"eq": ["ACTIVE"]}}` to reduce response size, but
also re-check `status == "ACTIVE"` client-side as a belt-and-suspenders guard in case the API returns
unexpected results.

**Why botocore patching is used instead of `mock_aws()`:**
moto does not implement the `accessanalyzer` service — calling `session.client("accessanalyzer")`
inside `mock_aws()` would raise a `NotImplementedError`. Instead, tests patch
`botocore.client.BaseClient._make_api_call` directly to intercept `ListAnalyzers` and `ListFindings`
calls and return hand-crafted responses. All other calls fall through to the real moto backend.
This is the same approach used in Story 2.4 for `GenerateServiceLastAccessedDetails`.

**Tasks:**

- [x] Write `tests/unit/test_access_analyzer.py` first (TDD):
  - Define `FAKE_ANALYZER` and `ACTIVE_FINDING` as module-level constants — reused across tests
  - Define `patch_access_analyzer(analyzers, findings)` helper: returns a `mock_api_call` function
    that intercepts `ListAnalyzers` and `ListFindings`, falls through for everything else
  - Test R01: analyzer with 1 ACTIVE finding → 1 CRITICAL finding; assert `resource_arn` = finding's
    `resource` field; assert `detail` contains the action strings
  - Test: finding with `status=ARCHIVED` → empty list (archived findings must never produce R01)
  - Test: no analyzers in account → empty list returned (graceful, not an error — many accounts
    don't have Access Analyzer enabled)
  - Test: analyzer exists but 0 findings → empty list returned (clean account, no false positives)

- [x] Implement `src/lambda/auditors/access_analyzer.py`:
  - `run(session, run_id: str) -> list[dict]`
  - `aa = session.client("accessanalyzer")`
  - `list_analyzers()` — if empty, return `[]` immediately
  - For each analyzer: call `list_findings(analyzerArn=..., filter={"status": {"eq": ["ACTIVE"]}})`
  - For each finding: skip if `status != "ACTIVE"` (client-side guard)
  - `resource_arn` = `finding["resource"]`; `detail` = `", ".join(finding.get("action", []))`
    or `"unknown"` if the action list is empty
  - Emit `rule_id=R01`, `severity=CRITICAL`

**Done when:** All access analyzer tests pass. ✅ (4/4 green)

---

### Story 2.4 — Last Accessed Auditor (Rule R07)

_As the auditor, I need to detect IAM roles that haven't been used in 90+ days._

**Background:** `iam:GenerateServiceLastAccessedDetails` is async — it accepts a role ARN and returns
a `JobId` immediately. You must then poll `iam:GetServiceLastAccessedDetails(JobId=...)` until
`JobStatus == COMPLETED` before reading the results. In real AWS this may take 1–2 seconds; in moto
it completes on the first poll.

The response contains a `ServicesLastAccessed` list — one entry per AWS service that the role has
permission to call. Each entry may or may not have a `LastAuthenticated` timestamp. A role that has
never been used will have no `LastAuthenticated` on any service. A role that has been used will have
it on at least one service. We take the **most recent** `LastAuthenticated` across all services as the
role's effective last-used date.

**Why `/aws-service-role/` roles are skipped:**
Roles under this path are created and managed by AWS on behalf of services (e.g. the role that allows
EC2 Auto Scaling to terminate instances). The customer cannot modify or delete them — flagging them
as unused would generate noise with no actionable remediation.

**Why `isinstance(svc_auth, str)` check is needed:**
moto returns `LastAuthenticated` as an ISO string. Real AWS returns it as a `datetime` object.
The isinstance check normalises both to `datetime` before comparison.

**Why botocore patching is used for `GenerateServiceLastAccessedDetails`:**
moto does not fully implement these calls. `list_roles()` is handled natively by moto (so real IAM
state can be set up via the moto IAM API), but the generate/get last-accessed calls are intercepted
at the botocore level. The patch maps each role ARN to a `days_ago` value, making it easy to control
exactly how stale each role appears.

**Tasks:**

- [x] Write `tests/unit/test_last_accessed.py` first (TDD):
  - Define `last_accessed_response(days_ago)` helper — builds a `GetServiceLastAccessedDetails`
    response with `JobStatus=COMPLETED` and a single service entry. `days_ago=None` means never used
    (no `LastAuthenticated` key in the service entry).
  - Define `patch_last_accessed(days_ago_by_role)` helper — intercepts
    `GenerateServiceLastAccessedDetails` (returns `{"JobId": role_arn}` so the ARN doubles as the
    job ID) and `GetServiceLastAccessedDetails` (looks up days_ago by job ID). All other calls fall
    through to moto.
  - Define `make_role(boto3_session, role_name, path="/")` helper — creates a real IAM role in moto
    and returns its ARN. This lets `list_roles()` inside `run()` find the role naturally via moto.
  - Test R07: role with `LastAuthenticated` = 91 days ago → MEDIUM finding; assert `resource_arn` = role ARN
  - Test: role used 10 days ago → no finding
  - Test: role never used (`LastAuthenticated` = null) → MEDIUM finding with "never been used" detail
  - Test: threshold boundary — 89 days = no finding, 91 days = finding (both roles in same run)
  - Test: role under `/aws-service-role/` path with 200 days → no finding (skipped at list stage)
  - Test: no roles in account → empty list returned

- [x] Implement `src/lambda/auditors/last_accessed.py`:
  - `run(session, run_id: str, unused_days: int) -> list[dict]`
  - Pre-compute `threshold = timedelta(days=unused_days)` and `now = datetime.now(timezone.utc)`
    once before the loop — consistent timestamp across all role comparisons in the run
  - Paginate `list_roles()` — skip any role where `role["Path"].startswith("/aws-service-role/")`
  - For each remaining role: call `generate_service_last_accessed_details(Arn=role_arn)` → `job_id`
  - Poll `get_service_last_accessed_details(JobId=job_id)` in a `while True` loop until
    `details["JobStatus"] == "COMPLETED"`
  - Loop `details["ServicesLastAccessed"]`, find the most recent `LastAuthenticated`; normalise
    strings to `datetime` via `datetime.fromisoformat()`
  - If `last_auth is None` or `(now - last_auth) > threshold` → emit R07, MEDIUM finding
  - `detail` distinguishes the two cases: `"Role X has never been used"` vs
    `"Role X last used N days ago"`

**Done when:** All last accessed tests pass. ✅ (6/6 green)

---

### Story 2.5 — Handler (Orchestration + DynamoDB + SNS)

_As the Lambda entry point, handler.py must read config, run all auditors, store findings, and send the email._

**Background:** `lambda_handler(event, context)` is called directly by the AWS Lambda runtime — it receives
only `event` and `context`, never a boto3 session. This means it creates its own `boto3.Session()` internally,
unlike the auditors which receive a session as a parameter. This distinction matters for testing: moto must
be active at the time `lambda_handler` is called, not just at fixture setup time.

**Tasks:**

- [ ] Write `tests/unit/test_handler.py` first:

  **Fixture setup:**
  - Request all 3 conftest fixtures: `dynamodb_table`, `sns_topic`, `ssm_params`
  - These have dependencies — `ssm_params` depends on `sns_topic` (it reads the SNS ARN to seed the SSM
    parameter), and `dynamodb_table` provides the table the handler will write findings to. Requesting all
    3 guarantees the full environment is in place before the handler runs.
  - Since `boto3_session` uses `with mock_aws(): yield`, moto is already active for the duration of every
    test that uses these fixtures — `lambda_handler` creates its own session inside that active mock context.

  **Monkeypatching the auditors:**
  - Use `unittest.mock.patch` to replace each auditor's `run()` with a function returning a controlled
    list of findings. The auditors have already been tested in isolation — handler tests should control
    what auditors return, not re-test their logic.
  - Patch at the handler's import path, e.g. `patch("handler.credential_report.run", return_value=[...])`.
    Patching at the source module path won't work because `handler.py` already has a reference to the
    imported name.

  **Tests:**
  - Test: handler reads the 3 SSM params — assert the correct parameter names are read:
    `/iam-auditor/sns-topic-arn`, `/iam-auditor/dynamodb-table-name`, `/iam-auditor/unused-days-threshold`
  - Test: handler writes each finding to DynamoDB — after calling `lambda_handler`, scan the table and
    assert each finding is present with correct `run_id` (PK) and `finding_id` (SK)
  - Test: handler publishes exactly 1 SNS message with subject `[IAM Auditor] Weekly Report — YYYY-MM-DD`
    (date matches the run date, not hardcoded)
  - Test: SNS body contains severity counts — assert the strings `CRITICAL`, `HIGH`, `MEDIUM` appear in
    the message body with correct counts
  - Test: handler returns a summary dict with keys `run_id`, `total`, `critical`, `high`, `medium` and
    correct integer counts
  - Test: all auditors return empty lists → handler runs without error, SNS is still published, all counts
    are 0

- [ ] Implement `src/lambda/handler.py`:

  **Entry point and session:**
  - `lambda_handler(event, context)` — AWS Lambda calls this directly
  - Create `session = boto3.Session()` inside the function (region comes from the Lambda environment,
    not hardcoded)
  - Generate `run_id = f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"`

  **Read SSM parameters:**
  - Create `ssm = session.client("ssm")`
  - Call `ssm.get_parameter(Name="/iam-auditor/sns-topic-arn")` — value is at `["Parameter"]["Value"]`
  - Call `ssm.get_parameter(Name="/iam-auditor/dynamodb-table-name")` — same path in response
  - Call `ssm.get_parameter(Name="/iam-auditor/unused-days-threshold")` — value is a string, cast to `int`

  **Run auditors:**
  - Import all 4 auditors at the top of the file
  - Call each in sequence, passing `session` and `run_id`; `credential_report` and `last_accessed` also
    receive `unused_days`
  - Collect all results into a single `findings = []` list

  **Write to DynamoDB:**
  - Create `table = session.resource("dynamodb").Table(table_name)`
  - Iterate `findings` and call `table.put_item(Item=finding)` for each — one item per finding

  **Build and publish SNS email:**
  - Subject: `f"[IAM Auditor] Weekly Report — {datetime.utcnow().strftime('%Y-%m-%d')}"`
  - Body: follow the format in `docs/03-technical-design.md §8` — include run metadata, counts by severity,
    and a detail block listing CRITICAL findings by rule ID, resource ARN, and detail string
  - Call `sns.publish(TopicArn=topic_arn, Subject=subject, Message=body)`

  **Return summary:**
  - Return `{"run_id": run_id, "total": len(findings), "critical": critical_count, "high": high_count, "medium": medium_count}`

**Done when:** All handler tests pass. Full `pytest tests/` suite is green.

---

### Story 2.6 — Coverage gate

_As a developer, I want to see coverage before moving on to containers._

**Tasks:**

- [x] Run `pytest --cov=src/lambda --cov-report=term-missing tests/`
- [x] Confirm >= 80% coverage on all 4 modules (`handler.py`, each auditor)
- [x] Fix any untested branches surfaced by the report

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

- [x] Run `docker build -t iam-auditor-lambda src/lambda/` — should succeed
- [x] Run the container with RIE:
  ```bash
  docker run -p 9000:8080 \
    -e AWS_DEFAULT_REGION=us-east-1 \
    -e AWS_ACCESS_KEY_ID=fake \
    -e AWS_SECRET_ACCESS_KEY=fake \
    iam-auditor-lambda
  ```
- [x] Send a test invocation:
  ```bash
  curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
  ```
- [x] Verify the response is a valid JSON dict (will likely fail on real AWS calls — that's expected at this stage)
- [x] Verify no import errors or syntax errors in the response

**Done when:** Container starts, accepts invocations, returns JSON (not a crash).

---

### Story 3.2 — Container security scan (local)

_As a developer, I want to run Trivy locally before CI to catch CVEs early._

**Tasks:**

- [x] Install Trivy locally: `brew install trivy`
- [x] Run `trivy image --severity CRITICAL,HIGH --ignore-unfixed iam-auditor-lambda`
- [x] Investigate any findings; pin or update `requirements.txt` if needed
- [x] Document any accepted risks (e.g. base image OS CVEs with no fix available)

**Done when:** Trivy scan passes with no CRITICAL or HIGH fixable CVEs.

---

## PHASE 4 — Terraform (Local Validation, No AWS Yet)

**Goal:** All Terraform is written and passes `validate`, `fmt`, and `checkov`. No `terraform apply` yet.

---

### Story 4.1 — Scaffold Terraform module structure

_As a developer, I need the directory skeleton created before writing any `.tf` content._

**Tasks:**

- [x] Create `infra/modules/vpc/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/modules/ecr/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/modules/iam/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/modules/lambda/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/modules/dynamodb/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/modules/sns/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/modules/ssm/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Create `infra/envs/dev/` with `main.tf`, `variables.tf`, `terraform.tfvars`, `outputs.tf`, `versions.tf`, `backend.tf`
- [x] Create `infra/envs/prod/` with same file set (placeholder — not deployed initially)
- [x] Add `infra/envs/dev/terraform.tfvars` to `.gitignore` (contains email address)

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

- [x] Write `infra/modules/ssm/main.tf`
- [x] Parameters: `/iam-auditor/sns-topic-arn`, `/iam-auditor/dynamodb-table-name`, `/iam-auditor/unused-days-threshold`
- [x] Values are passed in as variables (wired from other module outputs in `envs/dev/main.tf`)
- [x] Expose outputs: `parameter_arns` map

---

### Story 4.8 — Write the Lambda module

_Resources: Security group, Lambda function (container), CloudWatch log group, EventBridge rule + target + permission_

**Tasks:**

- [x] Write `infra/modules/lambda/main.tf`
- [x] Security group: no inbound, HTTPS egress to `0.0.0.0/0`
- [x] Lambda: `package_type = "Image"`, `image_uri` variable for ECR image
- [x] CloudWatch log group: retention 7 days
- [x] EventBridge rule: `cron(0 8 ? * MON *)` (every Monday 08:00 UTC)
- [x] Expose outputs: `function_arn`, `function_name`

---

### Story 4.9 — Wire up `infra/envs/dev/main.tf`

_The env entrypoint calls all modules, passing outputs between them._

**Tasks:**

- [x] Write `infra/envs/dev/versions.tf`: Terraform >= 1.6, AWS provider ~> 5.0
- [x] Write `infra/envs/dev/backend.tf`: S3 backend per `docs/04-infrastructure-spec.md §7`
  - Bucket: `iam-auditor-tf-state-<your_account_id>` (replace with actual account ID)
  - Key: `dev/terraform.tfstate`
  - DynamoDB lock table: `iam-auditor-tf-state-lock`
  - `encrypt = true`
  - **Note:** This file is safe to commit — it contains no secrets. The S3 bucket and DynamoDB lock table are bootstrapped manually in Story 5.0 before `terraform init` is ever run.
- [x] Write `infra/envs/dev/main.tf`: call all 8 modules, wire outputs (SNS ARN → SSM, ECR URL + tag → Lambda, etc.)
- [x] Write `infra/envs/dev/variables.tf`: expose `alert_email`, `aws_region`, `ecr_image_tag`, `unused_days_threshold`, `github_org`, `github_repo`, `create_demo_data`
- [x] Write `infra/envs/dev/terraform.tfvars.example`: committed template (actual `terraform.tfvars` is gitignored — copy example and fill in real values locally)
- [x] Write `infra/envs/dev/outputs.tf`: `lambda_function_name`, `lambda_function_arn`, `ecr_repository_url`, `cicd_role_arn`, `dynamodb_table_name`, `sns_topic_arn`, `vpc_id`
- [x] Write `infra/envs/prod/backend.tf`: same bucket, key = `prod/terraform.tfstate`
- [x] Copy remaining `envs/dev/` structure to `envs/prod/` (placeholder — not deployed, `create_demo_data` defaults to false)

**LocalStack smoke test (run after all modules are wired):**

- [ ] Install LocalStack dependencies (one-time, add to `requirements-dev.txt`):
  ```bash
  pip install localstack terraform-local awscli-local
  ```
- [ ] Start LocalStack (requires Docker running):
  ```bash
  localstack start
  ```
  LocalStack pulls its Docker image on first run and exposes all AWS service APIs at `http://localhost:4566`.

- [ ] Run `tflocal init` from `infra/envs/dev/`

  `tflocal` is a thin wrapper around `terraform` that automatically overrides all AWS provider
  endpoints to point at LocalStack. No changes to `.tf` files are needed.

- [ ] Run `tflocal apply -auto-approve` — creates all resources in LocalStack.
  Expected: all 7 modules apply without error.

- [ ] Verify key resources were created using `awslocal` (LocalStack-aware AWS CLI):
  ```bash
  awslocal ec2 describe-vpcs --query 'Vpcs[*].CidrBlock'
  awslocal dynamodb list-tables
  awslocal sns list-topics
  awslocal ssm get-parameter --name /iam-auditor/sns-topic-arn
  awslocal ssm get-parameter --name /iam-auditor/dynamodb-table-name
  awslocal ssm get-parameter --name /iam-auditor/unused-days-threshold
  ```

- [ ] Run `tflocal destroy` to clean up LocalStack state

**Done when:** `tflocal apply` completes with no errors and all 6 verification commands return expected output.

---

### Story 4.10 — Local Terraform validation

_Catch all config errors before any AWS calls._

**Tasks:**

- [x] Run `terraform init -backend=false` from `infra/envs/dev/` (downloads providers locally — no AWS auth needed)
- [x] Run `terraform validate` — Success, 1 deprecation warning on inline_policy (known, acceptable)
- [x] Run `terraform fmt -recursive infra/` — reformatted terraform.tfvars, all other files clean
- [x] Run `checkov -d infra/ --framework terraform` locally:
  - Install: `pipx install checkov`
  - 69 passed, 0 failed, 34 suppressed — all suppressions documented with justification inside resource blocks
- [x] Run `bandit -r src/lambda/ -ll -ii` locally — 0 issues across 623 lines

**Done when:** `validate` passes, `checkov` passes (or all suppressions are documented), `bandit` clean.

---

### Story 4.11 — Demo data module

_As a developer, I want intentionally misconfigured IAM resources in the account so the Lambda has real findings to detect during the Phase 5 demo._

**Background:** A clean AWS account produces zero findings, which makes for a poor portfolio demo.
This module creates deliberately non-compliant IAM resources that trigger 5 of the 8 detection rules.
It lives in its own module so it can be applied and destroyed independently — never deployed to prod.

**Resources created:**

| Resource | Misconfiguration | Rule triggered | Severity |
|---|---|---|---|
| IAM user `demo-no-mfa-user` | Console access, MFA disabled | R03 | HIGH |
| IAM user `demo-stale-key-user` | Access key created 120 days ago | R06 | MEDIUM |
| IAM role `demo-wildcard-inline-role` | Inline policy with `s3:*` | R09 | HIGH |
| IAM role `demo-wildcard-managed-role` | Customer-managed policy with `iam:*` | R10 | HIGH |
| IAM role `demo-unused-role` | Role with no activity (never used) | R07 | MEDIUM |

**Notes:**
- R01 (Access Analyzer) and R02 (root access key) cannot be safely or programmatically created — excluded
- R04 (user inline wildcard) and R05 (unused key) omitted to keep demo concise — R09/R10 cover wildcard risk
- All demo resources are tagged `demo = "true"` for easy identification and cleanup
- Module is called from `envs/dev/main.tf` with a `create_demo_data = true` variable — set to `false` to skip

**Tasks:**

- [x] Create `infra/modules/demo-data/` with `main.tf`, `variables.tf`, `outputs.tf`
- [x] Write demo IAM users, roles, and policies per the table above
- [x] Add `create_demo_data` variable to `infra/envs/dev/variables.tf` and `terraform.tfvars.example`
- [x] Call the module conditionally from `infra/envs/dev/main.tf` using `count = var.create_demo_data ? 1 : 0`

**Done when:** `terraform apply` creates all 5 demo resources and a Lambda run produces at least 5 findings across R03, R06, R07, R09, R10.

---

## PHASE 5 — AWS First Deploy (Dev Environment)

**Goal:** Infrastructure is live in AWS. Lambda invokes successfully against real AWS APIs.
_This is the first time you touch AWS._

**Prerequisites:** AWS CLI configured (`aws configure`), account has IAM Access Analyzer enabled.

---

### Story 5.0 — Bootstrap Terraform remote state (one-time, manual)

_Resources that Terraform cannot create for itself — must exist before `terraform init` ever runs._

**Background:** Terraform needs a remote backend to persist state across CI/CD pipeline runs. GitHub Actions runners are ephemeral — local state is destroyed at the end of every run. Without remote state, Terraform would treat every pipeline execution as a fresh account and attempt to re-create all resources. The S3 bucket and DynamoDB lock table must be created manually once, before `terraform init`.

**Tasks:**

- [x] Confirm your AWS CLI identity and capture your account ID:
  ```bash
  aws sts get-caller-identity
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
  echo "Account ID: ${ACCOUNT_ID}"
  ```

- [x] Create the S3 state bucket — name must be globally unique; account ID ensures this:
  ```bash
  aws s3api create-bucket \
    --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
    --region us-east-1
  ```

- [x] Enable versioning — allows state recovery if a file is accidentally overwritten:
  ```bash
  aws s3api put-bucket-versioning \
    --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
    --versioning-configuration Status=Enabled
  ```

- [x] Enable AES-256 server-side encryption — state files contain resource ARNs and config values:
  ```bash
  aws s3api put-bucket-encryption \
    --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
    --server-side-encryption-configuration '{
      "Rules": [{
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }]
    }'
  ```

- [x] Block all public access — state files must never be publicly readable:
  ```bash
  aws s3api put-public-access-block \
    --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  ```

- [x] Create the DynamoDB state lock table — prevents concurrent `apply` operations from corrupting state:
  ```bash
  aws dynamodb create-table \
    --table-name iam-auditor-tf-state-lock \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1
  ```
  > `LockID` is the partition key name the Terraform S3 backend expects. PAY_PER_REQUEST billing keeps this within free tier — the table has very low write volume (one lock/unlock per apply).

- [x] Verify both resources exist and are ready:
  ```bash
  aws s3 ls | grep iam-auditor-tf-state
  aws dynamodb describe-table \
    --table-name iam-auditor-tf-state-lock \
    --query 'Table.TableStatus'
  ```
  Expected: bucket name appears in S3 list, DynamoDB status = `"ACTIVE"`

- [x] Update `infra/envs/dev/backend.tf` — replace `<your_account_id>` with your actual account ID:
  ```bash
  echo "Your account ID is: ${ACCOUNT_ID}"
  # Open infra/envs/dev/backend.tf and replace the placeholder
  ```

**Done when:** S3 bucket exists with versioning + encryption enabled, DynamoDB table status is ACTIVE, and `backend.tf` has the real account ID. `terraform init` (run in Story 5.1) will confirm the backend is reachable.

---

### Story 5.1 — Bootstrap remaining AWS prerequisites (one-time, manual)

_Resources that Terraform can't create itself (the bootstrapping paradox) — continued from Story 5.0._

**Tasks:**

- [x] Verify IAM Access Analyzer is enabled in `us-east-1` (console → Security → IAM Access Analyzer)
  - If not enabled: `aws accessanalyzer create-analyzer --analyzer-name iam-auditor-analyzer --type ACCOUNT --region us-east-1`
- [x] Run `terraform init` from `infra/envs/dev/` to verify the S3 backend is reachable:
  ```bash
  cd infra/envs/dev && terraform init
  ```
  Expected: `Successfully configured the backend "s3"!` — confirms Story 5.0 bootstrap succeeded.
- [x] Run `terraform apply -target=module.ecr` first to create the ECR repo before pushing the Lambda image:
  ```bash
  terraform apply -target=module.ecr
  ```
  > ECR must exist before the Docker push in Story 5.2. Targeting a single module avoids trying to create Lambda before the image exists.

**Done when:** IAM Access Analyzer is ACTIVE, `terraform init` confirms S3 backend is reachable, and ECR repo exists. ✅

---

### Story 5.2 — Push the first Docker image to ECR

**Tasks:**

- [x] Authenticate Docker to ECR:
  ```bash
  aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin <account_id>.dkr.ecr.us-east-1.amazonaws.com
  ```
- [x] Build + tag + push:
  ```bash
  docker build --platform linux/amd64 --provenance=false -t iam-auditor-lambda src/lambda/
  docker tag iam-auditor-lambda:latest <ecr_url>:latest
  docker push <ecr_url>:latest
  ```
  > **Note:** `--platform linux/amd64` targets Lambda's runtime architecture. `--provenance=false` disables the BuildKit attestation manifest — without it, Docker pushes an OCI image index which Lambda does not support (`InvalidParameterValueException: image manifest media type not supported`).

**Done when:** Image appears in ECR as a single `vnd.oci.image.manifest.v1+json` entry with `latest` tag. ✅

---

### Story 5.3 — `terraform apply` to dev

**Tasks:**

- [x] `cd infra/envs/dev && terraform apply`
- [x] Confirm all resources created: VPC, subnets, endpoints, DynamoDB, SNS, SSM, Lambda, EventBridge
  > 3 resources added on final apply (Lambda function, EventBridge permission, EventBridge target). All prior resources already existed from `-target=module.ecr` and earlier runs.
- [x] Check email inbox for SNS subscription confirmation — click the link

**Done when:** `Apply complete! Resources: 3 added, 0 changed, 0 destroyed.` and all outputs populated. ✅
> Note: `inline_policy` deprecation warning in `module.demo_data` — non-blocking, does not affect functionality.

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

- [x] Push all local code to GitHub (`git push origin dev`)
- [ ] Set up branch protection on `dev` — full rule details in `docs/05-cicd-pipeline-spec.md §5`:
  - GitHub repo → Settings → Branches → Add rule → Branch name pattern: `dev`
  - ✅ Require a pull request before merging
  - ✅ Require status checks to pass before merging
    - Add status checks: `security-scan`, `terraform-plan` (exact job names from the workflow)
    - ✅ Require branches to be up to date before merging
  - ✅ Do not allow bypassing the above settings
  > Note: status check names won't appear in the dropdown until the first pipeline run. Add them after Story 6.3 is complete and the first PR runs the workflow.
- [ ] Set GitHub repo variable `AWS_ACCOUNT_ID`:
  - GitHub repo → Settings → Secrets and variables → Actions → Variables tab → New repository variable
  - Name: `AWS_ACCOUNT_ID`
  - Value: `548931596025`

---

### Story 6.2 — Verify GitHub OIDC trust (already provisioned by Terraform)

_The OIDC identity provider and CI/CD role were created by `terraform apply` in Story 5.3. These tasks confirm they are correctly configured._

**Tasks:**

- [ ] Verify the OIDC provider exists:
  ```bash
  aws iam list-open-id-connect-providers
  ```
  Expected: entry for `token.actions.githubusercontent.com`
- [ ] Verify the CI/CD role trust policy matches your repo and `dev` branch:
  ```bash
  aws iam get-role --role-name github-actions-iam-auditor \
    --query 'Role.AssumeRolePolicyDocument'
  ```
  Expected: condition `repo:mvhungrydev/iam-auditor:ref:refs/heads/dev`

---

### Story 6.3 — Write the GitHub Actions workflow

**Tasks:**

- [ ] Create `.github/workflows/deploy.yml` per the full YAML in `docs/05-cicd-pipeline-spec.md §6`
- [ ] Jobs: `security-scan` → `terraform-plan` (PR only) → `deploy` (push to `dev` only)
- [ ] Verify gitleaks, bandit, checkov, trivy stages match the spec
- [ ] Verify OIDC credential step uses `role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-actions-iam-auditor`

---

### Story 6.4 — End-to-end pipeline test

**Tasks:**

- [ ] Create a feature branch, make a small change, open a PR to `dev`
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
