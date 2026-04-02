import csv
import io
import time
import uuid
from datetime import datetime, timezone, timedelta


def _days_since(date_str):
    """Return days elapsed since the given ISO 8601 date string.
    Returns None if the value is N/A (meaning the resource was never used).
    """
    if not date_str or date_str in ("N/A", "no_information"):
        return None
    dt = datetime.fromisoformat(date_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


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
        "data_source": "credential_report",
        "created_at": now.isoformat(),
        # expires_at is a Unix timestamp — DynamoDB TTL requires an integer epoch second
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }


# %%
""" For development
source .venv/bin/activate

import os, sys, csv, io, uuid
from datetime import datetime, timezone, timedelta
sys.path.insert(0, "src/lambda")
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


import boto3
from moto import mock_aws

mock = mock_aws()
mock.start()
session = boto3.Session(region_name="us-east-1")
iam = session.client("iam")

# create test user 
iam.create_user(UserName="no-mfa-user")
iam.create_login_profile(UserName="no-mfa-user", Password="Test1234!")


# Generate the credential report
resp = iam.generate_credential_report()
print(resp)

report = iam.get_credential_report()
content = report["Content"].decode("utf-8")
reader = csv.DictReader(io.StringIO(content))
rows = list(reader)
row = rows[0]
print(row["user"])
print(row["password_enabled"])
print(row["mfa_active"])

if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
    print("R03 triggered!")

now = datetime.now(timezone.utc)
finding = {
    "run_id": "run_test_123",
    "finding_id": str(uuid.uuid4()),
    "rule_id": "R03",
    "severity": "HIGH",
    "resource_arn": row["arn"],
    "detail": f"User '{row['user']}' has a console password but no MFA device registered.",
    "data_source": "credential_report",
    "created_at": now.isoformat(),
    "expires_at": int((now + timedelta(days=90)).timestamp()),
}
print(finding)

# pytest tests/unit/test_credential_report.py -v --tb=long

"""
# %%


def run(session, run_id, unused_days):
    """Parse the IAM Credential Report CSV and return findings for rules R02, R03, R05, R06, R08."""
    iam = session.client("iam")

    # Trigger report generation, then poll until AWS signals it is ready.
    # Moto returns COMPLETE on the first call; real AWS may take several seconds.
    for _ in range(30):
        resp = iam.generate_credential_report()
        if resp.get("State") == "COMPLETE":
            break
        time.sleep(2)

    # Fetch the CSV — Content is returned as bytes by boto3.
    report = iam.get_credential_report()
    content = report["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")

    findings = []
    for row in csv.DictReader(io.StringIO(content)):

        user = row["user"]
        arn = row["arn"]
        print(f"Processing user: {user}, ARN: {arn}")

        # R02: Root account has an active access key — CRITICAL
        # The root row is identified by the special username "<root_account>".
        if user == "<root_account>":
            print("Checking root account access keys...")
            if (
                row.get("access_key_1_active") == "true"
                or row.get("access_key_2_active") == "true"
            ):
                print("Finding: Root account has an active access key.")
                findings.append(
                    _finding(
                        run_id,
                        "R02",
                        "CRITICAL",
                        arn,
                        "Root account has an active access key. "
                        "Root keys cannot be scoped by IAM policies.",
                    )
                )
            continue  # Root is exempt from all other rules

        # R03: Console password enabled but no MFA — HIGH
        if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
            print(
                f"Finding: User '{user}' has a console password but no MFA device registered."
            )
            findings.append(
                _finding(
                    run_id,
                    "R03",
                    "HIGH",
                    arn,
                    f"User '{user}' has a console password but no MFA device registered.",
                )
            )

        # R05: Access key not used in unused_days+ days, or never used (N/A) — MEDIUM
        if row.get("access_key_1_active") == "true":
            days = _days_since(row.get("access_key_1_last_used_date", "N/A"))
            print(f"User '{user}' access key 1 last used: {days} days ago")
            if days is None or days > unused_days:
                print(
                    f"Finding: User '{user}' access key 1 last used: {days} days ago (threshold: {unused_days} days)."
                )
                label = "never" if days is None else f"{days} days ago"
                findings.append(
                    _finding(
                        run_id,
                        "R05",
                        "MEDIUM",
                        arn,
                        f"User '{user}' access key 1 last used: {label} (threshold: {unused_days} days).",
                    )
                )

        # R06: Access key not rotated in unused_days+ days — MEDIUM
        if row.get("access_key_1_active") == "true":
            print(
                f"User '{user}' access key 1 last rotated: {row.get('access_key_1_last_rotated')}"
            )
            days = _days_since(row.get("access_key_1_last_rotated", "N/A"))
            if days is not None and days > unused_days:
                print(
                    f"Finding: User '{user}' access key 1 not rotated in {days} days (threshold: {unused_days} days)."
                )
                findings.append(
                    _finding(
                        run_id,
                        "R06",
                        "MEDIUM",
                        arn,
                        f"User '{user}' access key 1 not rotated in {days} days (threshold: {unused_days} days).",
                    )
                )

        # R08: Console password not used in unused_days+ days, or never used (N/A) — MEDIUM
        if row.get("password_enabled") == "true":
            print(
                f"User '{user}' console password last used: {row.get('password_last_used')}"
            )
            days = _days_since(row.get("password_last_used", "N/A"))
            if days is None or days > unused_days:
                print(
                    f"Finding: User '{user}' console password last used: {days} days ago (threshold: {unused_days} days)."
                )
                label = "never" if days is None else f"{days} days ago"
                findings.append(
                    _finding(
                        run_id,
                        "R08",
                        "MEDIUM",
                        arn,
                        f"User '{user}' console password last used: {label} (threshold: {unused_days} days).",
                    )
                )

    return findings
