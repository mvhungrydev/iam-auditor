# %%
import os
import sys
import pytest
import botocore
from unittest.mock import patch

# %%
# Add src/lambda to the module search path so we can import the auditors package.
try:
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/lambda")
    )
except NameError:
    sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))

from auditors import access_analyzer

RUN_ID = "run_test_123"

# %%
"""
# %% Setup — run once
import os
import sys
import pytest
import botocore
from unittest.mock import patch
import os, sys, boto3, botocore
from moto import mock_aws
from unittest.mock import patch

def find_project_root(marker="pytest.ini"):
    path = os.getcwd()
    while path != os.path.dirname(path):
        if os.path.exists(os.path.join(path, marker)):
            return path
        path = os.path.dirname(path)
    raise FileNotFoundError(f"Could not find project root containing {marker}")

sys.path.insert(0, os.path.join(find_project_root(), "src/lambda"))
from auditors import access_analyzer

RUN_ID = "run_test_123"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

def run_test(test_fn):
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        test_fn(session)
        print(f"PASS: {test_fn.__name__}")

# %%
run_test(test_r01_active_finding)

# %%
run_test(test_r01_archived_finding_not_returned)

# %%
run_test(test_no_analyzers_returns_empty)

# %%
run_test(test_analyzer_with_no_findings)
#%%
"""

# %%
FAKE_ANALYZER = {
    "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer",
    "name": "test-analyzer",
    "type": "ACCOUNT",
    "status": "ACTIVE",
    "createdAt": "2024-01-01T00:00:00+00:00",
}

# Reusable finding shape — mirrors what list_findings returns from IAM Access Analyzer.
# An ACTIVE finding means a resource is currently externally accessible.
ACTIVE_FINDING = {
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
}


def patch_access_analyzer(analyzers, findings):
    """Patch ListAnalyzers and ListFindings at the botocore level.

    moto does not implement the accessanalyzer service, so we intercept both
    calls directly. All other operations are forwarded to the real moto backend.

    Args:
        analyzers: list of analyzer dicts returned by ListAnalyzers
        findings:  list of finding dicts returned by ListFindings
    """
    original_call = botocore.client.BaseClient._make_api_call

    def mock_api_call(self, operation_name, api_params):
        if operation_name == "ListAnalyzers":
            return {"analyzers": analyzers}
        if operation_name == "ListFindings":
            return {"findings": findings}
        return original_call(self, operation_name, api_params)

    return mock_api_call


def test_r01_active_finding(boto3_session):
    """R01: Analyzer with 1 ACTIVE finding → 1 CRITICAL finding returned.

    An ACTIVE finding means a resource is currently exposed outside the account.
    The finding's resource field becomes resource_arn.
    The finding's action list is joined into detail.
    """
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_access_analyzer([FAKE_ANALYZER], [ACTIVE_FINDING]),
    ):
        findings = access_analyzer.run(boto3_session, RUN_ID)

    r01 = [f for f in findings if f["rule_id"] == "R01"]
    assert len(r01) == 1
    assert r01[0]["severity"] == "CRITICAL"
    assert r01[0]["resource_arn"] == "arn:aws:s3:::my-exposed-bucket"
    assert "s3:GetObject" in r01[0]["detail"]


def test_r01_archived_finding_not_returned(boto3_session):
    """Finding with status=ARCHIVED → not returned.

    ARCHIVED means the account owner acknowledged the finding and dismissed it.
    The auditor also checks status client-side — archived findings must never
    produce R01 even if the API filter is bypassed.
    """
    archived = {**ACTIVE_FINDING, "status": "ARCHIVED"}
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_access_analyzer([FAKE_ANALYZER], [archived]),
    ):
        findings = access_analyzer.run(boto3_session, RUN_ID)

    assert findings == []


def test_no_analyzers_returns_empty(boto3_session):
    """No analyzers in the account → empty list returned (graceful, not an error).

    Many AWS accounts don't have IAM Access Analyzer enabled.
    list_analyzers returns [] and the auditor returns [] without raising.
    """
    with patch(
        "botocore.client.BaseClient._make_api_call", patch_access_analyzer([], [])
    ):
        findings = access_analyzer.run(boto3_session, RUN_ID)

    assert findings == []


def test_analyzer_with_no_findings(boto3_session):
    """Analyzer exists but 0 findings → empty list returned.

    A well-locked-down account will have an analyzer but no external access findings.
    Verifies no false positives when the account is clean.
    """
    with patch(
        "botocore.client.BaseClient._make_api_call",
        patch_access_analyzer([FAKE_ANALYZER], []),
    ):
        findings = access_analyzer.run(boto3_session, RUN_ID)

    assert findings == []


# %%
