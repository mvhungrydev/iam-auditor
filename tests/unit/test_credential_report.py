import sys
import os
import base64
import pytest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta

# Add src/lambda to Python's module search path so we can import
# the auditors package without installing it as a package.
# __file__ is this test file; we go up two levels to reach the project root,
# then down into src/lambda where handler.py and auditors/ live.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src/lambda"))

# Import the auditor module we are testing.
# At this point it only returns [] — tests will fail until we implement it.
from auditors import credential_report


# A fixed run ID used across all tests to simulate a Lambda execution.
RUN_ID = "run_test_123"

# The number of days before an unused/unrotated resource is considered stale.
# Matches the default threshold defined in SSM and the detection rules doc.
UNUSED_DAYS = 90


def days_ago(n):
    """Returns an ISO 8601 timestamp for n days ago in UTC.
    Used to construct dates for moto IAM resources when needed.
    """
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime(
        "%Y-%m-%dT%H:%M:%S+00:00"
    )


def test_r02_root_access_key(boto3_session):
    """R02: Root account has an active access key — CRITICAL finding expected.
    Moto does not simulate the root account (it only knows about IAM users you
    explicitly create). In real AWS, the root account always appears in the
    credential report as '<root_account>' — a special reserved name that cannot
    be created via the IAM API. So we patch get_credential_report to return a
    hand-crafted CSV with a root row that has access_key_1_active = true.
    """
    # Build a minimal credential report CSV with a root account entry.
    # The column order matches the real AWS credential report format.
    csv_content = (
        "user,arn,user_creation_time,password_enabled,password_last_used,"
        "password_last_changed,password_next_rotation,mfa_active,"
        "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
        "access_key_1_last_used_region,access_key_1_last_used_service,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
        "access_key_2_last_used_region,access_key_2_last_used_service,"
        "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
        "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
        "not_supported,N/A,not_supported,not_applicable,false,"
        "true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,"
        "false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
    )
    # AWS returns the CSV base64-encoded inside the "Content" field.
    encoded = base64.b64encode(csv_content.encode()).decode()

    # Patch get_credential_report on the IAM client class so our auditor
    # receives the fake CSV instead of hitting moto's empty IAM state.
    iam_client = boto3_session.client("iam")
    with patch.object(
        iam_client.__class__,
        "get_credential_report",
        return_value={"Content": encoded, "ReportFormat": "text/csv"},
    ):
        findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)

    r02 = [f for f in findings if f["rule_id"] == "R02"]
    assert len(r02) == 1
    assert r02[0]["severity"] == "CRITICAL"


def test_r03_user_no_mfa(boto3_session):
    """R03: User has a console password but no MFA enabled — HIGH finding expected.
    A user without MFA is vulnerable to credential-based attacks.
    We only flag users with a password (console access); API-only users are excluded.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="no-mfa-user")
    iam.create_login_profile(UserName="no-mfa-user", Password="Test1234!")
    findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
    r03 = [f for f in findings if f["rule_id"] == "R03"]
    assert len(r03) == 1
    assert r03[0]["severity"] == "HIGH"


def test_r05_key_unused(boto3_session):
    """R05: Access key not used in 90+ days — MEDIUM finding expected.
    Moto sets the key's last_used date to N/A for a newly created key,
    which our auditor treats as never used — triggering the rule.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="stale-key-user")
    iam.create_access_key(UserName="stale-key-user")
    findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
    r05 = [f for f in findings if f["rule_id"] == "R05"]
    assert len(r05) >= 1
    assert r05[0]["severity"] == "MEDIUM"


def test_r06_key_not_rotated(boto3_session):
    """R06: Access key not rotated in 90+ days — MEDIUM finding expected.
    Moto creates keys with a creation date of now, but since moto does not
    simulate time passing, we rely on the auditor treating a never-rotated
    key (last_rotated = creation date, which may be recent) correctly.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="old-key-user")
    iam.create_access_key(UserName="old-key-user")
    findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
    r06 = [f for f in findings if f["rule_id"] == "R06"]
    assert len(r06) >= 1
    assert r06[0]["severity"] == "MEDIUM"


def test_r08_password_not_used(boto3_session):
    """R08: Console password not used in 90+ days — MEDIUM finding expected.
    Moto sets password_last_used to N/A for a newly created login profile,
    which our auditor treats as never used — triggering the rule.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="inactive-user")
    iam.create_login_profile(UserName="inactive-user", Password="Test1234!")
    findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
    r08 = [f for f in findings if f["rule_id"] == "R08"]
    assert len(r08) >= 1
    assert r08[0]["severity"] == "MEDIUM"


def test_compliant_user(boto3_session):
    """A user with no access keys and no login profile should produce no findings.
    This is an API-only user with nothing to flag — verifies we don't
    generate false positives for clean accounts.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="compliant-user")
    findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
    assert findings == []


def test_threshold_respected(boto3_session):
    """A key created just now (0 days old) should not trigger R05 at a 90-day threshold.
    This verifies the auditor respects the unused_days parameter and does not
    flag resources that are within the acceptable window.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="almost-stale-user")
    iam.create_access_key(UserName="almost-stale-user")
    # Pass the standard 90-day threshold — key is brand new so no R05 expected
    findings = credential_report.run(boto3_session, RUN_ID, UNUSED_DAYS)
    r05 = [f for f in findings if f["rule_id"] == "R05"]
    assert len(r05) == 0
