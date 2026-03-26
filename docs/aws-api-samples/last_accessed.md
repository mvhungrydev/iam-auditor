# AWS API Samples — Last Accessed Auditor

Three API calls, in order of execution.

---

## 1. iam:ListRoles (paginated)

Used to get all roles in the account. The auditor skips roles with
Path starting with `/aws-service-role/`.

**Request**
```python
iam.list_roles()
# paginated via get_paginator("list_roles")
```

**Response**
```json
{
  "Roles": [
    {
      "RoleName": "my-lambda-role",
      "RoleId": "AROAEXAMPLEID",
      "Arn": "arn:aws:iam::123456789012:role/my-lambda-role",
      "Path": "/",
      "CreateDate": "2024-01-15T10:00:00+00:00",
      "AssumeRolePolicyDocument": "..."
    },
    {
      "RoleName": "AWSServiceRoleForLambda",
      "RoleId": "AROAEXAMPLEID2",
      "Arn": "arn:aws:iam::123456789012:role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda",
      "Path": "/aws-service-role/",
      "CreateDate": "2023-06-01T00:00:00+00:00",
      "AssumeRolePolicyDocument": "..."
    }
  ],
  "IsTruncated": false
}
```

**What the auditor uses:** `Role.Arn`, `Role.Path`, `Role.RoleName`

---

## 2. iam:GenerateServiceLastAccessedDetails

Kicks off an async job for a single role. Returns immediately with a
job ID — does not block until data is ready.

**Request**
```python
iam.generate_service_last_accessed_details(Arn="arn:aws:iam::123456789012:role/my-lambda-role")
```

**Response**
```json
{
  "JobId": "a1b2c3d4-1234-5678-abcd-example11111"
}
```

**What the auditor uses:** `JobId` — stored and passed to the next call.

---

## 3. iam:GetServiceLastAccessedDetails

Polls the job until `JobStatus == COMPLETED`, then reads the results.

**Request**
```python
iam.get_service_last_accessed_details(JobId="a1b2c3d4-1234-5678-abcd-example11111")
```

**Response — job still running**
```json
{
  "JobStatus": "IN_PROGRESS",
  "ServicesLastAccessed": []
}
```

**Response — completed, role has been used**
```json
{
  "JobStatus": "COMPLETED",
  "ServicesLastAccessed": [
    {
      "ServiceName": "AWS Lambda",
      "ServiceNamespace": "lambda",
      "LastAuthenticated": "2026-03-01T08:00:00+00:00",
      "LastAuthenticatedEntity": "arn:aws:iam::123456789012:role/my-lambda-role",
      "TotalAuthenticatedEntities": 3
    },
    {
      "ServiceName": "Amazon S3",
      "ServiceNamespace": "s3",
      "LastAuthenticated": "2026-02-10T14:30:00+00:00",
      "LastAuthenticatedEntity": "arn:aws:iam::123456789012:role/my-lambda-role",
      "TotalAuthenticatedEntities": 12
    },
    {
      "ServiceName": "Amazon DynamoDB",
      "ServiceNamespace": "dynamodb",
      "TotalAuthenticatedEntities": 0
    }
  ]
}
```

**Response — completed, role has never been used**
```json
{
  "JobStatus": "COMPLETED",
  "ServicesLastAccessed": [
    {
      "ServiceName": "Amazon S3",
      "ServiceNamespace": "s3",
      "TotalAuthenticatedEntities": 0
    }
  ]
}
```

**What the auditor uses:**
- `JobStatus` — loop until `COMPLETED`
- `ServicesLastAccessed[*].LastAuthenticated` — find the most recent
  timestamp across all services; if absent on all entries, the role
  has never been used → R07 finding

---

## R07 Finding Logic

| Condition | Result |
|---|---|
| `LastAuthenticated` absent on all services | MEDIUM finding — never used |
| Most recent `LastAuthenticated` > `unused_days` ago | MEDIUM finding |
| Most recent `LastAuthenticated` ≤ `unused_days` ago | No finding |
| Role path starts with `/aws-service-role/` | Skipped entirely |
