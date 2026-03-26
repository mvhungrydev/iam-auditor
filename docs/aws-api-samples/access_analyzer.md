# AWS API Samples — Access Analyzer Auditor

Two API calls. moto does not implement the `accessanalyzer` service —
both calls are intercepted via botocore patching in tests.

---

## 1. accessanalyzer:ListAnalyzers

Returns all IAM Access Analyzer instances configured in the account.
Many accounts have none — the auditor returns an empty list gracefully
without raising an error.

**Request**
```python
aa = session.client("accessanalyzer")
aa.list_analyzers()
```

**Response — analyzer exists**
```json
{
  "analyzers": [
    {
      "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer",
      "name": "my-analyzer",
      "type": "ACCOUNT",
      "status": "ACTIVE",
      "createdAt": "2024-01-01T00:00:00+00:00",
      "lastResourceAnalyzed": "arn:aws:s3:::my-bucket",
      "lastResourceAnalyzedAt": "2026-03-25T08:00:00+00:00"
    }
  ]
}
```

**Response — no analyzers configured**
```json
{
  "analyzers": []
}
```

**Analyzer types**

| Type | Scope |
|---|---|
| `ACCOUNT` | Finds resources accessible outside the AWS account |
| `ORGANIZATION` | Finds resources accessible outside the AWS Organization |

**What the auditor uses:** `analyzers[*].arn` — passed to
`ListFindings` for each analyzer.

---

## 2. accessanalyzer:ListFindings

Returns external access findings for one analyzer. The auditor passes
a server-side filter to request only `ACTIVE` findings — it also
performs a client-side status check as a belt-and-suspenders guard.

**Request**
```python
aa.list_findings(
    analyzerArn="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer",
    filter={"status": {"eq": ["ACTIVE"]}}
)
```

**Response — active finding present (triggers R01)**
```json
{
  "findings": [
    {
      "id": "a1b2c3d4-1234-5678-abcd-example11111",
      "type": "S3Bucket",
      "resource": "arn:aws:s3:::my-exposed-bucket",
      "resourceType": "AWS::S3::Bucket",
      "status": "ACTIVE",
      "action": ["s3:GetObject", "s3:ListBucket"],
      "condition": {},
      "principal": {"AWS": "*"},
      "isPublic": true,
      "createdAt": "2026-03-01T00:00:00+00:00",
      "analyzedAt": "2026-03-25T08:00:00+00:00",
      "updatedAt": "2026-03-25T08:00:00+00:00"
    }
  ]
}
```

**Response — finding has been archived (no R01 finding)**
```json
{
  "findings": [
    {
      "id": "a1b2c3d4-1234-5678-abcd-example11111",
      "type": "S3Bucket",
      "resource": "arn:aws:s3:::my-exposed-bucket",
      "resourceType": "AWS::S3::Bucket",
      "status": "ARCHIVED",
      "action": ["s3:GetObject"],
      "isPublic": true,
      "createdAt": "2026-03-01T00:00:00+00:00",
      "analyzedAt": "2026-03-25T08:00:00+00:00",
      "updatedAt": "2026-03-25T08:00:00+00:00"
    }
  ]
}
```

**Response — no findings**
```json
{
  "findings": []
}
```

**Finding statuses**

| Status | Meaning | Auditor action |
|---|---|---|
| `ACTIVE` | Resource is currently externally accessible | R01 finding emitted |
| `ARCHIVED` | Account owner acknowledged and dismissed it | Skipped |
| `RESOLVED` | Access was removed — finding auto-closed | Not returned by the `ACTIVE` filter |

**What the auditor uses:**
- `findings[*].status` — client-side check, must be `ACTIVE`
- `findings[*].resource` — becomes `resource_arn` in the finding
- `findings[*].action` — joined into the `detail` field

---

## R01 Finding Logic

| Condition | Result |
|---|---|
| No analyzers in account | Empty list — graceful, no error |
| Analyzer exists, 0 findings | Empty list |
| Finding with `status == ACTIVE` | CRITICAL finding |
| Finding with `status == ARCHIVED` | Skipped |
