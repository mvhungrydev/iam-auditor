# %%
import os
import sys
import pytest
import botocore
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

try:
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/lambda")
    )
except NameError:
    sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))

from auditors import last_accessed
from moto import mock_aws
import boto3

RUN_ID = "run_test_123"
JOB_ID = "test-job-id"

# %%
# Interactive development — replicate the boto3_session fixture manually
"""

import os, sys

sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
import boto3, botocore
from moto import mock_aws
from unittest.mock import patch


def find_project_root(marker="pytest.ini"):
    path = os.getcwd()
    while path != os.path.dirname(path):  # stop at filesystem root
        if os.path.exists(os.path.join(path, marker)):
            return path
        path = os.path.dirname(path)
    raise FileNotFoundError(f"Could not find project root containing {marker}")


sys.path.insert(0, os.path.join(find_project_root(), "src/lambda"))
from auditors import last_accessed

mock = mock_aws()
mock.start()
session = boto3.Session(region_name="us-east-1")
iam = session.client("iam")

# Create a test role in moto
iam.create_role(
    RoleName="old-role",
    Path="/",
    AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
)
role_arn = "arn:aws:iam::123456789012:role/old-role"

original_call = botocore.client.BaseClient._make_api_call


# %%
def mock_api_call(self, operation_name, api_params):
    if operation_name == "GenerateServiceLastAccessedDetails":
        return {"jobId": "test-job-id"}
    if operation_name == "GetServiceLastAccessedDetails":
        from datetime import datetime, timezone, timedelta

        last_auth = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
        return {
            "jobStatus": "COMPLETED",
            "servicesLastAccessed": [
                {
                    "serviceName": "Amazon S3",
                    "serviceNamespace": "s3",
                    "lastAuthenticated": last_auth,
                    "totalAuthenticatedEntities": 1,
                }
            ],
        }
    return original_call(self, operation_name, api_params)

run_id = "run_test_123"
with patch("botocore.client.BaseClient._make_api_call", mock_api_call):
    findings = last_accessed.run(session, run_id, unused_days=90)

print("Findings: {}".format(len(findings)))
for f in findings:
    print(f["rule_id"], f["resource_arn"], f["detail"])

"""
# %%


def last_accessed_response(days_ago=None):
    """Build a GetServiceLastAccessedDetails response.

    days_ago=None simulates a role that has never been used.
    """
    if days_ago is None:
        last_auth = None
    else:
        last_auth = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()

    service = {
        "serviceName": "Amazon S3",
        "serviceNamespace": "s3",
        "totalAuthenticatedEntities": 0,
    }
    if last_auth:
        service["lastAuthenticated"] = last_auth

    return {
        "jobStatus": "COMPLETED",
        "servicesLastAccessed": [service],
    }


def patch_last_accessed(days_ago_by_role):
    """Patch GenerateServiceLastAccessedDetails and GetServiceLastAccessedDetails.

    moto does not fully implement these calls, so we intercept at the botocore level.
    list_roles is handled natively by moto.

    Args:
        days_ago_by_role: dict mapping role ARN → days_ago (None = never used)
    """
    original_call = botocore.client.BaseClient._make_api_call

    def mock_api_call(self, operation_name, api_params):
        if operation_name == "GenerateServiceLastAccessedDetails":
            return {"jobId": JOB_ID}
        if operation_name == "GetServiceLastAccessedDetails":
            role_arn = api_params.get("Arn")
            days = days_ago_by_role.get(role_arn)
            return last_accessed_response(days)
        return original_call(self, operation_name, api_params)

    return mock_api_call


def make_role(boto3_session, role_name, path="/"):
    """Create an IAM role in moto and return its ARN."""
    iam = boto3_session.client("iam")
    resp = iam.create_role(
        RoleName=role_name,
        Path=path,
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )
    return resp["Role"]["Arn"]


def test_r07_role_unused_91_days(boto3_session):
    """R07: Role with LastAuthenticated 91 days ago → MEDIUM finding."""
    arn = make_role(boto3_session, "old-role")
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_last_accessed({arn: 91}),
    ):
        findings = last_accessed.run(boto3_session, RUN_ID, unused_days=90)

    r07 = [f for f in findings if f["rule_id"] == "R07"]
    assert len(r07) == 1
    assert r07[0]["severity"] == "MEDIUM"
    assert r07[0]["resource_arn"] == arn


def test_r07_role_used_recently_no_finding(boto3_session):
    """Role used 10 days ago → no finding."""
    arn = make_role(boto3_session, "active-role")
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_last_accessed({arn: 10}),
    ):
        findings = last_accessed.run(boto3_session, RUN_ID, unused_days=90)

    assert findings == []


def test_r07_role_never_used(boto3_session):
    """Role with no LastAuthenticated (never used) → MEDIUM finding."""
    arn = make_role(boto3_session, "never-used-role")
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_last_accessed({arn: None}),
    ):
        findings = last_accessed.run(boto3_session, RUN_ID, unused_days=90)

    r07 = [f for f in findings if f["rule_id"] == "R07"]
    assert len(r07) == 1
    assert r07[0]["severity"] == "MEDIUM"


def test_r07_threshold_respected(boto3_session):
    """Threshold boundary: 89 days → no finding, 91 days → finding."""
    arn_ok = make_role(boto3_session, "role-89")
    arn_flag = make_role(boto3_session, "role-91")
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_last_accessed({arn_ok: 89, arn_flag: 91}),
    ):
        findings = last_accessed.run(boto3_session, RUN_ID, unused_days=90)

    r07 = [f for f in findings if f["rule_id"] == "R07"]
    assert len(r07) == 1
    assert r07[0]["resource_arn"] == arn_flag


def test_r07_skips_aws_service_roles(boto3_session):
    """Roles under /aws-service-role/ path → skipped, no finding."""
    arn = make_role(
        boto3_session, "AWSServiceRoleForSomething", path="/aws-service-role/"
    )
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_last_accessed({arn: 200}),
    ):
        findings = last_accessed.run(boto3_session, RUN_ID, unused_days=90)

    assert findings == []


def test_r07_empty_roles_returns_empty(boto3_session):
    """No roles in account → empty list returned."""
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_last_accessed({}),
    ):
        findings = last_accessed.run(boto3_session, RUN_ID, unused_days=90)

    assert findings == []
