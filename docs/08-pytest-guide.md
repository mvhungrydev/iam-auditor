# Pytest Guide — IAM Auditor

How the test infrastructure is wired together in this project as it relates to pytest

Pytest is Python's most popular testing framework, designed for writing simple, readable, and scalable tests. It emphasizes convention over configuration, with minimal boilerplate.

---

## 1. Entry Point — how pytest finds and runs tests

Running `pytest` from the project root reads `pytest.ini` first:

```ini
[pytest]
testpaths = tests
addopts   = -v --tb=short
```

| Setting             | What it does                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------- |
| `testpaths = tests` | Only look inside the `tests/` directory — ignore everything else (`.venv/`, `src/`, etc.) |
| `-v`                | Verbose output — print each test name and PASS/FAIL as it runs                            |
| `--tb=short`        | On failure, print a short traceback instead of the full one                               |

**Test discovery rules (pytest defaults):**

- Files must match `test_*.py` or `*_test.py`
- Functions inside those files must start with `test_`
- `conftest.py` is special — loaded automatically before any test file, never collected as a test file itself

---

## 2. Project Test Layout

```
tests/
├── conftest.py          ← shared fixtures, auto-loaded by pytest
├── __init__.py          ← empty, marks tests/ as a Python package
└── unit/
    ├── __init__.py      ← empty, marks unit/ as a Python package
    ├── test_credential_report.py
    ├── test_policy_scanner.py
    ├── test_access_analyzer.py
    ├── test_last_accessed.py
    └── test_handler.py
```

---

## 3. conftest.py — Shared Fixture Registry

`conftest.py` lives at the `tests/` root. Pytest loads it automatically before running
any test — all fixtures defined here are available to every test file in `tests/`
and `tests/unit/` without any import.

### Fixture dependency chain

```
aws_credentials         Sets fake AWS env vars (required by moto)
      │
      ▼
boto3_session           Opens mock_aws() context + yields a real boto3.Session
      │                 mock_aws() stays open for the ENTIRE test (see section 6)
      │
      ├──────────────────────────┐
      ▼                          ▼
dynamodb_table              sns_topic
Creates iam-audit-findings  Creates iam-auditor-alerts SNS topic
table, enables TTL,         Yields the topic ARN string
yields the table object          │
                                 ▼
                            ssm_params
                            Seeds 3 SSM parameters using the
                            real sns_topic ARN. Yields None.
```

### What each fixture yields

| Fixture           | Yields            | Type                              |
| ----------------- | ----------------- | --------------------------------- |
| `aws_credentials` | nothing           | sets env vars as side effect      |
| `boto3_session`   | a `boto3.Session` | `boto3.Session`                   |
| `dynamodb_table`  | the table object  | `boto3` DynamoDB `Table` resource |
| `sns_topic`       | the topic ARN     | `str`                             |
| `ssm_params`      | nothing           | seeds SSM as side effect          |

### The 3 SSM parameters seeded by `ssm_params`

| Parameter name                       | Value                  | Notes                                      |
| ------------------------------------ | ---------------------- | ------------------------------------------ |
| `/iam-auditor/sns-topic-arn`         | SNS topic ARN          | Uses the real ARN from `sns_topic` fixture |
| `/iam-auditor/dynamodb-table-name`   | `"iam-audit-findings"` | Table name as string                       |
| `/iam-auditor/unused-days-threshold` | `"90"`                 | Stored as string — handler converts to int |

---

## 4. How Fixtures Are Injected Into Test Functions

Pytest matches **parameter names** to **fixture names** automatically.
You never call fixtures yourself — pytest resolves them by name.

```python
# pytest sees this signature:
def test_handler_writes_findings_to_dynamodb(dynamodb_table, sns_topic, ssm_params):
                                                    │              │          │
                                                    ▼              ▼          ▼
#                                           conftest fixture  conftest   conftest
#                                           (table object)    (ARN str)  (None)
```

Pytest builds the dependency chain before calling the test:

```
1. ssm_params needs sns_topic
2. sns_topic needs boto3_session
3. dynamodb_table needs boto3_session
4. boto3_session needs aws_credentials

Execution order (innermost dependency first):
  aws_credentials → boto3_session → sns_topic → ssm_params
                                 → dynamodb_table

Then pytest calls:
  test_handler_writes_findings_to_dynamodb(table_object, arn_string, None)
```

---

## 5. Per-File Breakdown

### `test_credential_report.py`

**Fixture used:** `boto3_session`

**What it tests:** R02, R03, R05, R06, R08 — credential report rules

**Mocking strategy:**

```
Real moto IAM API
  └── used for: creating users, login profiles, access keys (R03, R05, R08)

botocore._make_api_call patch
  └── used for: injecting custom CSV content (R02 root account, R06 stale rotation date)
       Reason: moto cannot simulate the root account row or stale dates
```

**Call flow:**

```
test_r03_user_no_mfa(boto3_session)
        │
        ├── iam.create_user(UserName="no-mfa-user")
        ├── iam.create_login_profile(...)
        │
        └── credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
                │
                ├── iam.generate_credential_report()
                ├── iam.get_credential_report()  → parses CSV
                └── returns [finding, ...]
```

---

### `test_policy_scanner.py`

**Fixture used:** `boto3_session`

**What it tests:** R04, R09, R10 — wildcard policy rules

**Mocking strategy:**

```
Real moto IAM API
  └── used for: creating users, roles, inline policies, managed policies (most tests)

botocore._make_api_call patch
  └── used for: injecting AWS-managed policy ARN (test_r10_aws_managed_policy_skipped)
       Reason: moto does not pre-load real AWS-managed policies like AdministratorAccess
```

**Call flow:**

```
test_r04_full_wildcard(boto3_session)
        │
        ├── iam.create_user(UserName="wildcard-user")
        ├── iam.put_user_policy(...)   ← inline policy with Action: "*"
        │
        └── policy_scanner.run(boto3_session, RUN_ID)
                │
                ├── paginator list_users → list_user_policies → get_user_policy
                ├── paginator list_roles → list_role_policies → get_role_policy        (R09)
                ├── paginator list_roles → list_attached_role_policies → get_policy    (R10)
                └── returns [finding, ...]
```

---

### `test_access_analyzer.py`

**Fixture used:** `boto3_session`

**What it tests:** R01 — external access findings from IAM Access Analyzer

**Mocking strategy:**

```
botocore._make_api_call patch (always)
  └── used for: ALL access analyzer calls
       Reason: moto does not implement the accessanalyzer service at all
```

**Call flow:**

```
test_r01_active_finding(boto3_session)
        │
        ├── patch ListAnalyzers → returns [FAKE_ANALYZER]
        ├── patch ListFindings  → returns [ACTIVE_FINDING]
        │
        └── access_analyzer.run(boto3_session, RUN_ID)
                │
                ├── aa.list_analyzers()        → intercepted by patch
                ├── aa.list_findings(...)      → intercepted by patch
                └── returns [finding, ...]
```

---

### `test_last_accessed.py`

**Fixture used:** `boto3_session`

**What it tests:** R07 — unused roles

**Mocking strategy:**

```
Real moto IAM API
  └── used for: iam.list_roles, iam.create_role

botocore._make_api_call patch
  └── used for: GenerateServiceLastAccessedDetails, GetServiceLastAccessedDetails
       Reason: moto does not fully implement these async job APIs
       Trick: JobId is set to the role ARN so the mock knows which role to look up
```

**Call flow:**

```
test_r07_role_unused_91_days(boto3_session)
        │
        ├── iam.create_role(RoleName="old-role") → returns real ARN
        ├── patch GenerateServiceLastAccessedDetails → returns {JobId: role_arn}
        ├── patch GetServiceLastAccessedDetails     → returns last_accessed_response(91)
        │
        └── last_accessed.run(boto3_session, RUN_ID, unused_days=90)
                │
                ├── paginator list_roles               → real moto
                ├── generate_service_last_accessed_details(Arn=role_arn) → patched
                ├── get_service_last_accessed_details(JobId=job_id)      → patched
                └── returns [finding, ...]
```

---

### `test_handler.py`

**Fixtures used:** `dynamodb_table` + `sns_topic` + `ssm_params`

**What it tests:** orchestration — SSM reads, auditor calls, DynamoDB writes, SNS publish

**Mocking strategy:**

```
Real moto (via fixtures)
  └── used for: SSM GetParameter, DynamoDB PutItem, SNS Publish

patch at handler's import path
  └── used for: all 4 auditor run() functions
       Reason: isolates handler logic from auditor logic
       Rule: patch where the name is used, not where it's defined
         CORRECT → patch("handler.credential_report.run", ...)
         WRONG   → patch("auditors.credential_report.run", ...)

botocore._make_api_call patch (test_handler_publishes_sns only)
  └── used for: capturing SNS Publish call args to assert subject format
```

**Call flow:**

```
test_handler_returns_correct_summary(dynamodb_table, sns_topic, ssm_params)
        │
        ├── patch handler.credential_report.run → returns [HIGH finding]
        ├── patch handler.policy_scanner.run    → returns [HIGH finding]
        ├── patch handler.access_analyzer.run   → returns [CRITICAL finding]
        ├── patch handler.last_accessed.run     → returns [MEDIUM finding]
        │
        └── handler.lambda_handler({}, None)
                │
                ├── boto3.Session()                          ← handler creates its own session
                ├── ssm.get_parameter(sns-topic-arn)         ← reads from moto SSM
                ├── ssm.get_parameter(dynamodb-table-name)   ← reads from moto SSM
                ├── ssm.get_parameter(unused-days-threshold) ← reads from moto SSM, converts to int
                ├── credential_report.run(session, run_id, 90)  ← intercepted by patch
                ├── policy_scanner.run(session, run_id)         ← intercepted by patch
                ├── access_analyzer.run(session, run_id)        ← intercepted by patch
                ├── last_accessed.run(session, run_id, 90)      ← intercepted by patch
                ├── dynamodb table.put_item(finding) × 4    ← writes to moto DynamoDB
                ├── sns.publish(Subject=..., Message=...)    ← publishes to moto SNS
                └── returns {run_id, total, critical, high, medium}
```

---

## 6. Why `mock_aws()` Stays Open for the Entire Test

The `boto3_session` fixture uses `yield` inside a `with` block:

```python
@pytest.fixture
def boto3_session(aws_credentials):
    with mock_aws():        # ← moto intercept starts here
        yield boto3.Session(region_name="us-east-1")
    # ← moto intercept ends here (after test finishes)
```

`yield` pauses execution inside the `with` block and hands control to pytest,
which runs the test. When the test finishes, pytest resumes the fixture from
after the `yield` — which is still inside the `with` block — and the `with`
block's `__exit__` fires, shutting down moto.

```
Fixture setup:    mock_aws().__enter__() → moto active
                  boto3.Session() created
                  yield ──────────────────────────────────────────┐
                                                                   │
Test runs:        test function executes                           │  moto active
                  all AWS calls intercepted by moto               │  the entire time
                  ─────────────────────────────────────────────────┘
Fixture teardown: mock_aws().__exit__() → moto stopped
                  in-memory AWS state wiped
```

This means any `boto3.Session()` created during the test — including one
created inside `handler.lambda_handler()` — is also intercepted by moto,
because moto patches boto3 globally, not per-session.

---

## 7. Pytest vs Interactive Window — Side by Side

The Interactive Window (VS Code) does not run pytest. It executes Python cells
directly, with no fixture injection system. Each test file includes a `run_test`
helper inside a docstring block that replicates what pytest does automatically.

```
PYTEST                              INTERACTIVE WINDOW
──────────────────────────────────  ──────────────────────────────────
pytest discovers conftest.py        You run the # %% Setup cell manually

pytest calls aws_credentials        os.environ["AWS_ACCESS_KEY_ID"] = ...
                                    (done manually in the setup cell)

pytest calls boto3_session          with mock_aws():
  → opens mock_aws()                    session = boto3.Session(...)
  → yields session                      (done inside run_test)

pytest calls dynamodb_table         dynamodb.create_table(...)
  → creates table                       (done inside run_test)

pytest calls sns_topic              sns.create_topic(...)
  → creates topic, yields ARN           (done inside run_test)

pytest calls ssm_params             ssm.put_parameter(...) × 3
  → seeds SSM params                    (done inside run_test)

pytest injects fixtures             run_test passes (table, sns_arn, None)
  as function arguments               as positional arguments to test_fn

pytest calls test_function          run_test calls test_fn(table, sns_arn, None)

pytest tears down fixtures          mock_aws() context exits at end of
  → mock_aws() exits                  run_test's with block
```

The docstring wrapper means the interactive block is never executed by pytest
(Python ignores string literals as statements), so there is no risk of the
interactive scaffolding interfering with the test suite.
