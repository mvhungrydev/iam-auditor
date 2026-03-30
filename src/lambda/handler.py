import uuid
import boto3
from datetime import datetime, timezone
from auditors import credential_report, policy_scanner, access_analyzer, last_accessed


def lambda_handler(event, context):
    session = boto3.Session()
    ssm = session.client("ssm")

    sns_topic_arn = ssm.get_parameter(Name="/iam-auditor/sns-topic-arn")["Parameter"]["Value"]
    table_name = ssm.get_parameter(Name="/iam-auditor/dynamodb-table-name")["Parameter"]["Value"]
    unused_days = int(ssm.get_parameter(Name="/iam-auditor/unused-days-threshold")["Parameter"]["Value"])
    print(f"[handler] SSM loaded — table={table_name}, unused_days={unused_days}")

    run_id = str(uuid.uuid4())
    print(f"[handler] Starting run {run_id}")

    findings = []
    findings += credential_report.run(session, run_id, unused_days)
    print(f"[handler] credential_report: {len(findings)} findings so far")
    findings += policy_scanner.run(session, run_id)
    print(f"[handler] policy_scanner: {len(findings)} findings so far")
    findings += access_analyzer.run(session, run_id)
    print(f"[handler] access_analyzer: {len(findings)} findings so far")
    findings += last_accessed.run(session, run_id, unused_days)
    print(f"[handler] last_accessed: {len(findings)} findings so far")

    dynamodb = session.resource("dynamodb")
    table = dynamodb.Table(table_name)
    for finding in findings:
        table.put_item(Item=finding)
    print(f"[handler] Wrote {len(findings)} findings to DynamoDB")

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sns = session.client("sns")
    sns.publish(
        TopicArn=sns_topic_arn,
        Subject=f"[IAM Auditor] Weekly Report \u2014 {date_str}",
        Message=f"IAM Auditor run {run_id} complete. Total findings: {len(findings)}",
    )
    print(f"[handler] SNS published for run {run_id}")

    severities = [f["severity"] for f in findings]
    return {
        "run_id": run_id,
        "total": len(findings),
        "critical": severities.count("CRITICAL"),
        "high": severities.count("HIGH"),
        "medium": severities.count("MEDIUM"),
    }