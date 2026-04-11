# Future Enhancements

## Ability to exclude a finding

Some findings may potentially have business impact and may require some form of exemption.

---

## Persistent Finding Tracking

### Problem

The current design writes a new finding record per weekly run. Each record has a 30-day TTL and expires automatically regardless of whether the underlying misconfiguration was ever fixed. There is no way to tell:

- How long a finding has been open
- Whether a finding was resolved between runs
- How many times a specific misconfiguration has recurred

### Proposed Solution

Add a second DynamoDB table — `iam-audit-finding-tracker` — that maintains one persistent record per unique misconfiguration, keyed on `rule_id + resource_arn`.

#### Table Schema

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | S (PK) | Detection rule (e.g. `R03`) |
| `resource_arn` | S (SK) | Affected resource ARN |
| `status` | S | `OPEN` or `RESOLVED` |
| `first_seen` | S | ISO 8601 timestamp of first detection |
| `last_seen` | S | ISO 8601 timestamp of most recent detection |
| `occurrence_count` | N | Number of weekly runs this finding appeared in |
| `last_run_id` | S | `run_id` of the most recent run that detected it |

No TTL on this table — records persist until the finding is resolved.

#### Handler Logic Change

After each auditor run, for every finding:
1. Check if a record already exists in `iam-audit-finding-tracker` for this `rule_id + resource_arn`
2. If it exists → update `last_seen`, `last_run_id`, increment `occurrence_count`, keep `status = OPEN`
3. If it does not exist → write a new record with `status = OPEN`, `first_seen = now`, `occurrence_count = 1`

After writing findings, scan for any tracker records whose `last_run_id` does not match the current `run_id` — those resources were not flagged this run, meaning the misconfiguration was fixed. Set their `status = RESOLVED` and record a `resolved_at` timestamp.

#### What This Enables

- **Age of a finding** — `last_seen - first_seen` tells you how long a misconfiguration has been open
- **Recurrence detection** — `occurrence_count` shows chronic vs. one-time issues
- **Resolution tracking** — `status = RESOLVED` records when a fix was confirmed by a clean scan
- **SNS email improvement** — weekly report can include "X findings newly resolved, Y findings open for 30+ days"

#### Implementation Requirements

- New Terraform `aws_dynamodb_table` resource (can go in the existing `dynamodb` module or a new sub-resource)
- Lambda execution role needs `dynamodb:GetItem`, `dynamodb:UpdateItem`, `dynamodb:Scan` on the new table
- Handler logic update to upsert tracker records after each auditor run
- TDD — new moto-based tests for the upsert and resolution logic
