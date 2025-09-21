import boto3
from datetime import datetime, timezone
from decimal import Decimal

iam = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

DDB_TABLE = 'RemediationLog'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'

def lambda_handler(event, context):
    time_detected = datetime.now(timezone.utc)

    detail = event.get("detail", {})
    user_info = detail.get("resource", {}).get("accessKeyDetails", {})
    username = user_info.get("userName", "unknown")
    user_arn = user_info.get("userArn", "unknown")
    account_id = detail.get("accountId", "unknown")
    region = detail.get("region", "<ACCOUNT_REGION>")
    finding_id = detail.get("id", "unknown")
    finding_type = detail.get("type", "Exfiltration:IAMUser/AnomalousBehavior")
    severity_num = float(detail.get("severity", 7))
    if severity_num < 4:
        severity = "Low"
    elif severity_num < 7:
        severity = "Medium"
    elif severity_num < 9:
        severity = "High"
    else:
        severity = "Critical"

    source_ip = detail.get("service", {}).get("action", {}).get("awsApiCallAction", {}).get("remoteIpDetails", {}).get("ipAddressV4", "unknown")
    geo_location = detail.get("service", {}).get("action", {}).get("awsApiCallAction", {}).get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode", "unknown")

    print(f"[+] IAM Key Exfiltration detected for user: {username}")

    # Step 1: Deactivate access key (if known)
    try:
        access_key_id = user_info.get("accessKeyId")
        if access_key_id and username != "unknown":
            iam.update_access_key(
                UserName=username,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            print(f"[+] Access key for user {username} deactivated.")
    except Exception as e:
        print(f"[!] Failed to deactivate access key: {str(e)}")

    time_responded = datetime.now(timezone.utc)
    time_occurred = detail.get("updatedAt", time_detected.isoformat())
    latency = Decimal(str((time_responded - time_detected).total_seconds()))
    incident_id = f"iamkey_exfiltration-{time_detected.strftime('%Y%m%d%H%M%S')}"

    # Step 3: Log to DynamoDB
    table = dynamodb.Table(DDB_TABLE)
    try:
        table.put_item(Item={
            "id": incident_id,
            "finding_id": finding_id,
            "timestamp": time_responded.isoformat(),
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": source_ip,
            "resource_id": user_arn,
            "affected_service": "IAM",
            "iam_user": username,
            "iam_user_arn": user_arn,
            "account_id": account_id,
            "action_taken": "Deactivated IAM access key",
            "action_status": "completed",
            "response_type": "access_revocation",
            "playbook_name": "iam_key_exfil_response",
            "review_required": True,
            "sns_sent": False,
            "time_occurred": time_occurred,
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["iam", "high_risk", "manual_review"]
        })
        print("[+] Logged to DynamoDB")
    except Exception as e:
        print(f"[!] Failed to log to DynamoDB: {str(e)}")

    # Step 4: Notify via SNS and update sns_sent
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='SOAR Alert: IAM Key Exfiltration',
            Message=f"Access key for IAM user '{username}' has been deactivated due to suspected exfiltration.\nUser ARN: {user_arn}"
        )
        print("[+] SNS alert sent")

        table.update_item(
            Key={"id": incident_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True")
    except Exception as e:
        print(f"[!] Failed to send SNS or update flag: {str(e)}")

    return {"status": "success", "message": "IAM key exfiltration handled."}
