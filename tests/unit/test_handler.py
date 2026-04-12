# %%
import os
import sys
import uuid
import pytest
import botocore
from datetime import datetime, timezone
from unittest.mock import patch

# %%
# Add src/lambda to the module search path so we can import handler.
# Works in both pytest (uses __file__) and the VS Code Interactive Window (uses cwd).
try:
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/lambda")
    )
except NameError:
    sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))

import handler

# %%
"""
# %% Setup — run once
import os, sys, boto3
from moto import mock_aws
from unittest.mock import patch
from datetime import datetime, timezone
import uuid

def find_project_root(marker="pytest.ini"):
    path = os.getcwd()
    while path != os.path.dirname(path):
        if os.path.exists(os.path.join(path, marker)):
            return path
        path = os.path.dirname(path)
    raise FileNotFoundError(f"Could not find project root containing {marker}")
sys.path.insert(0, os.path.join(find_project_root(), "src/lambda"))

import handler

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

def run_test(test_fn):
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        dynamodb = session.resource("dynamodb")
        table = dynamodb.create_table(
            TableName="iam-audit-findings",
            KeySchema=[
                {"AttributeName": "run_id", "KeyType": "HASH"},
                {"AttributeName": "finding_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "run_id", "AttributeType": "S"},
                {"AttributeName": "finding_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        table.meta.client.get_waiter("table_exists").wait(TableName="iam-audit-findings")
        sns = session.client("sns")
        sns_arn = sns.create_topic(Name="iam-auditor-alerts")["TopicArn"]
        ssm = session.client("ssm")
        ssm.put_parameter(Name="/iam-auditor/sns-topic-arn", Value=sns_arn, Type="String")
        ssm.put_parameter(Name="/iam-auditor/dynamodb-table-name", Value="iam-audit-findings", Type="String")
        ssm.put_parameter(Name="/iam-auditor/unused-days-threshold", Value="90", Type="String")
        test_fn(table, sns_arn, None)
        print(f"PASS: {test_fn.__name__}")

# %%
run_test(test_handler_returns_correct_summary)
# %%
run_test(test_handler_writes_findings_to_dynamodb)
# %%
run_test(test_handler_publishes_sns)
# %%
run_test(test_handler_no_findings)
# %%
run_test(test_handler_reads_ssm_threshold)

#%%
"""
# %%


def make_finding(rule_id, severity):
    """Build a minimal finding dict for patching auditor return values.

    Uses a fixed run_id placeholder — the handler patches return these as-is,
    so the run_id in the items won't match the handler-generated one.
    That's fine: tests only care about counts and shapes, not the run_id value.
    expires_at is a far-future epoch so TTL never fires during tests.
    """
    return {
        "run_id": "mock-run",
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "severity": severity,
        "resource_arn": "arn:aws:iam::123456789012:user/test-user",
        "detail": f"Test finding for {rule_id}",
        "data_source": "test",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": 9999999999,
    }


def test_handler_returns_correct_summary(dynamodb_table, sns_topic, ssm_params):
    """lambda_handler returns a dict with run_id and correct severity counts.

    Auditors are patched to return a known mix:
      - 1 CRITICAL (R01 from access_analyzer)
      - 2 HIGH (R04 from policy_scanner, R03 from credential_report)
      - 1 MEDIUM (R07 from last_accessed)
    Return dict must have total=4, critical=1, high=2, medium=1.
    run_id must be a non-empty string.
    """
    with patch(
        "handler.credential_report.run", return_value=[make_finding("R03", "HIGH")]
    ), patch(
        "handler.policy_scanner.run", return_value=[make_finding("R04", "HIGH")]
    ), patch(
        "handler.access_analyzer.run", return_value=[make_finding("R01", "CRITICAL")]
    ), patch(
        "handler.last_accessed.run", return_value=[make_finding("R07", "MEDIUM")]
    ):
        result = handler.lambda_handler({}, None)

    assert isinstance(result["run_id"], str) and result["run_id"]
    assert result["total"] == 4
    assert result["critical"] == 1
    assert result["high"] == 2
    assert result["medium"] == 1


def test_handler_writes_findings_to_dynamodb(dynamodb_table, sns_topic, ssm_params):
    """All findings returned by auditors are written to DynamoDB as separate items.

    3 auditors return 1 finding each → expect 3 items in the table after the run.
    We scan (not query) because findings have a placeholder run_id from make_finding,
    not the handler-generated one — scan sees all items regardless of key values.
    """
    with patch(
        "handler.credential_report.run", return_value=[make_finding("R03", "HIGH")]
    ), patch(
        "handler.policy_scanner.run", return_value=[make_finding("R04", "HIGH")]
    ), patch(
        "handler.access_analyzer.run", return_value=[make_finding("R01", "CRITICAL")]
    ), patch(
        "handler.last_accessed.run", return_value=[]
    ):
        handler.lambda_handler({}, None)

    items = dynamodb_table.scan()["Items"]
    assert len(items) == 3


def test_handler_publishes_sns(dynamodb_table, sns_topic, ssm_params):
    """SNS Publish fires once with the correct subject format.

    Subject must be: '[IAM Auditor] Weekly Report — YYYY-MM-DD'
    We intercept Publish at the botocore level to capture call args while
    letting all other moto calls (SSM, DynamoDB) go through normally.
    """
    original_call = botocore.client.BaseClient._make_api_call
    publish_calls = []

    def capture_publish(self, operation_name, api_params):
        if operation_name == "Publish":
            publish_calls.append(api_params)
            return {"MessageId": "test-message-id"}
        return original_call(self, operation_name, api_params)

    with patch("handler.credential_report.run", return_value=[]), patch(
        "handler.policy_scanner.run", return_value=[]
    ), patch("handler.access_analyzer.run", return_value=[]), patch(
        "handler.last_accessed.run", return_value=[]
    ), patch(
        "botocore.client.BaseClient._make_api_call", capture_publish
    ):
        handler.lambda_handler({}, None)

    assert len(publish_calls) == 1
    subject = publish_calls[0]["Subject"]
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert subject == f"[IAM Auditor] Weekly Report \u2014 {date_str}"


def test_handler_sns_message_format(dynamodb_table, sns_topic, ssm_params):
    """SNS message body contains severity counts, grouped findings, and DynamoDB query hint.

    Patch auditors to return 1 CRITICAL, 1 HIGH, 1 MEDIUM finding.
    Assert the message has:
      - correct severity counts in the header block
      - a section for each severity tier that fired
      - the rule_id and resource_arn of each finding
      - the DynamoDB table name and run_id at the bottom
    """
    original_call = botocore.client.BaseClient._make_api_call
    publish_calls = []

    def capture_publish(self, operation_name, api_params):
        if operation_name == "Publish":
            publish_calls.append(api_params)
            return {"MessageId": "test-message-id"}
        return original_call(self, operation_name, api_params)

    with patch(
        "handler.credential_report.run", return_value=[make_finding("R03", "HIGH")]
    ), patch(
        "handler.policy_scanner.run", return_value=[]
    ), patch(
        "handler.access_analyzer.run", return_value=[make_finding("R01", "CRITICAL")]
    ), patch(
        "handler.last_accessed.run", return_value=[make_finding("R07", "MEDIUM")]
    ), patch(
        "botocore.client.BaseClient._make_api_call", capture_publish
    ):
        result = handler.lambda_handler({}, None)

    assert len(publish_calls) == 1
    msg = publish_calls[0]["Message"]

    # Severity summary block
    assert "CRITICAL : 1" in msg
    assert "HIGH     : 1" in msg
    assert "MEDIUM   : 1" in msg
    assert "TOTAL    : 3" in msg

    # Each severity section header is present
    assert "--- CRITICAL ---" in msg
    assert "--- HIGH ---" in msg
    assert "--- MEDIUM ---" in msg

    # Finding details appear in the message
    assert "[R01]" in msg
    assert "[R03]" in msg
    assert "[R07]" in msg
    assert "arn:aws:iam::123456789012:user/test-user" in msg

    # DynamoDB query hint
    assert "iam-audit-findings" in msg
    assert f"Query by run_id: {result['run_id']}" in msg


def test_build_message_no_findings():
    """_build_message with an empty findings list omits all severity sections.

    No '--- CRITICAL ---' / '--- HIGH ---' / '--- MEDIUM ---' headers should
    appear when there are no findings — only the summary block and footer.
    """
    msg = handler._build_message("test-run-id", [])

    assert "CRITICAL : 0" in msg
    assert "HIGH     : 0" in msg
    assert "MEDIUM   : 0" in msg
    assert "TOTAL    : 0" in msg
    assert "--- CRITICAL ---" not in msg
    assert "--- HIGH ---" not in msg
    assert "--- MEDIUM ---" not in msg
    assert "Query by run_id: test-run-id" in msg


def test_handler_no_findings(dynamodb_table, sns_topic, ssm_params):
    """All auditors return [] → counts are all 0, DynamoDB is empty, SNS still fires.

    A clean account should produce a valid run with zero findings — not an error.
    The handler must publish SNS and return the summary dict even with no findings.
    """
    with patch("handler.credential_report.run", return_value=[]), patch(
        "handler.policy_scanner.run", return_value=[]
    ), patch("handler.access_analyzer.run", return_value=[]), patch(
        "handler.last_accessed.run", return_value=[]
    ):
        result = handler.lambda_handler({}, None)

    assert result["total"] == 0
    assert result["critical"] == 0
    assert result["high"] == 0
    assert result["medium"] == 0
    assert dynamodb_table.scan()["Count"] == 0


def test_handler_reads_ssm_threshold(dynamodb_table, sns_topic, ssm_params):
    """Handler reads unused-days-threshold from SSM and passes it as int to auditors.

    SSM stores the value as the string "90". The handler must convert it to int
    before passing to credential_report.run and last_accessed.run.
    policy_scanner and access_analyzer do not take unused_days — verified by
    checking they are called with only 2 positional args (session, run_id).
    """
    with patch("handler.credential_report.run", return_value=[]) as mock_cr, patch(
        "handler.policy_scanner.run", return_value=[]
    ) as mock_ps, patch(
        "handler.access_analyzer.run", return_value=[]
    ) as mock_aa, patch(
        "handler.last_accessed.run", return_value=[]
    ) as mock_la:
        handler.lambda_handler({}, None)

    # Third positional arg must be int 90, not string "90"
    assert mock_cr.call_args[0][2] == 90
    assert mock_la.call_args[0][2] == 90
    # policy_scanner and access_analyzer take only (session, run_id)
    assert len(mock_ps.call_args[0]) == 2
    assert len(mock_aa.call_args[0]) == 2


# %%
