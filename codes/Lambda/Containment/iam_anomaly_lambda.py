import boto3
from datetime import datetime, timezone
from decimal import Decimal

iam = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

DDB_TABLE = 'RemediationLog'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'

def lambda_handler(event, context):
    detail = event.get("detail", {})
    user_info = detail.get("resource", {}).get("accessKeyDetails", {})

    username = user_info.get("userName", "unknown")
    user_arn = user_info.get("userArn", "unknown")
    account_id = detail.get("accountId", "unknown")
    region = detail.get("region", "<ACCOUNT_REGION>")
    finding_id = detail.get("id", "unknown")
    severity_num = float(detail.get("severity", 5))
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
    finding_type = detail.get("type", "")
    valid_types = [
        "Persistence:IAMUser/AnomalousBehavior",
        "CredentialAccess:IAMUser/AnomalousBehavior"
    ]

    if finding_type not in valid_types:
        print(f"[!] Skipped: {finding_type}")
        return {"status": "ignored", "message": "Not part of playbook"}

    print(f"Anomalous behavior detected for IAM user: {username}")
  
    time_detected = datetime.now(timezone.utc)

    # Tag IAM user
    try:
        iam.tag_user(
            UserName=username,
            Tags=[
                {'Key': 'Status', 'Value': 'Suspicious'},
                {'Key': 'Review', 'Value': 'Required'}
            ]
        )
        print(f"Tagged user {username}")
    except Exception as e:
        print(f"Tagging failed: {str(e)}")

    # Disable console login
    try:
        iam.delete_login_profile(UserName=username)
        print(f"Disabled console login for {username}")
    except iam.exceptions.NoSuchEntityException:
        print(f"No login profile for {username}")
    except Exception as e:
        print(f"Login disable failed: {str(e)}")

    time_responded = datetime.now(timezone.utc)
    latency = Decimal(str((time_responded - time_detected).total_seconds()))
    incident_id = f"iam-anomaly-{time_detected.strftime('%Y%m%d%H%M%S')}"

    # Log to DynamoDB
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
            "resource_id": username,
            "affected_service": "IAM",
            "iam_user": username,
            "iam_user_arn": user_arn,
            "account_id": account_id,
            "action_taken": "Tagged as Suspicious, disabled console login",
            "action_status": "completed",
            "response_type": "user_tagging",
            "playbook_name": "iam_anomaly_response",
            "review_required": True,
            "sns_sent": False,
            "time_occurred": time_detected.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["iam", "anomaly", "user"]
        })
        print("[+] Logged to DynamoDB")
    except Exception as e:
        print(f"[!] DynamoDB logging failed: {str(e)}")

    # Send SNS and update sns_sent
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='SOAR Alert: IAM Anomalous Behavior',
            Message=f'IAM user {username} flagged for anomalous behavior. Tagged and login disabled.'
        )
        print("[+] SNS sent")

        table.update_item(
            Key={"id": incident_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True")
    except Exception as e:
        print(f"[!] SNS update failed: {str(e)}")

    return {"status": "success", "message": "IAM anomaly handled"}
