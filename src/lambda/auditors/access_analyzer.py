import uuid
from datetime import datetime, timezone, timedelta


def _finding(run_id, rule_id, severity, arn, detail):
    """Build a finding dict matching the DynamoDB schema."""
    now = datetime.now(timezone.utc)
    return {
        "run_id": run_id,
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "severity": severity,
        "resource_arn": arn,
        "detail": detail,
        "data_source": "access_analyzer",
        "created_at": now.isoformat(),
        "expires_at": int((now + timedelta(days=90)).timestamp()),
    }


"""
# %%
# Interactive development — replicate the boto3_session fixture manually

import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
import boto3, botocore
from unittest.mock import patch


session = boto3.Session(region_name="us-east-1")
aa = session.client("accessanalyzer")


original_call = botocore.client.BaseClient._make_api_call

#%%
def mock_api_call(self, operation_name, api_params):
    if operation_name == "ListAnalyzers":
        return {
            "analyzers": [{
                "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer",
                "name": "test-analyzer",
                "type": "ACCOUNT",
                "status": "ACTIVE",
                "createdAt": "2024-01-01T00:00:00+00:00",
            }]
        }
    if operation_name == "ListFindings":
        return {
            "findings": [{
                "id": "test-finding-id",
                "type": "S3Bucket",
                "resource": "arn:aws:s3:::my-exposed-bucket",
                "resourceType": "AWS::S3::Bucket",
                "status": "ACTIVE",
                "action": ["s3:GetObject", "s3:ListBucket"],
                "condition": {},
                "createdAt": "2024-01-01T00:00:00+00:00",
                "analyzedAt": "2024-01-01T00:00:00+00:00",
                "updatedAt": "2024-01-01T00:00:00+00:00",
                "isPublic": True,
                "principal": {"AWS": "*"},
            }]
        }
    return original_call(self, operation_name, api_params)


run_id = "run_test_123"
with patch("botocore.client.BaseClient._make_api_call", mock_api_call):
    findings = run(session, run_id)

for f in findings:
    print(f["rule_id"], f["resource_arn"], f["detail"])

#%%
"""
# %%


def run(session, run_id):
    """Scan IAM Access Analyzer for external access findings.

    Returns:
      R01 — resource with an ACTIVE external access finding (CRITICAL)

    Only ACTIVE findings are returned — ARCHIVED findings have been acknowledged
    and dismissed by the account owner.
    If no analyzers are configured in the account, returns [] gracefully.
    """
    aa = session.client("accessanalyzer")
    findings = []

    analyzers = aa.list_analyzers().get("analyzers", [])
    print(f"Found {len(analyzers)} analyzers: {[a['name'] for a in analyzers]}")
    if not analyzers:
        return []

    for analyzer in analyzers:
        analyzer_arn = analyzer["arn"]
        print(f"Processing analyzer {analyzer['name']} with ARN {analyzer_arn}")

        # Request only ACTIVE findings — ARCHIVED ones are acknowledged by the owner.
        resp = aa.list_findings(
            analyzerArn=analyzer_arn,
            filter={"status": {"eq": ["ACTIVE"]}},
        )

        for finding in resp.get("findings", []):
            # Client-side status check — belt and suspenders in case the API
            # returns a non-ACTIVE finding despite the filter.
            if finding.get("status") != "ACTIVE":
                print(
                    f"Skipping non-ACTIVE finding {finding.get('id')} with status {finding.get('status')}"
                )
                continue

            resource_arn = finding.get("resource", "")
            actions = finding.get("action", [])
            detail = ", ".join(actions) if actions else "unknown"
            print(f"Adding finding for resource {resource_arn} with actions: {detail}")
            findings.append(_finding(run_id, "R01", "CRITICAL", resource_arn, detail))

    return findings
