import boto3
from datetime import datetime, timezone
from decimal import Decimal

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

DDB_TABLE = 'RemediationLog'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'

def lambda_handler(event, context):
    time_detected = datetime.now(timezone.utc)

    detail = event.get("detail", {})
    finding_type = detail.get("type", "Policy:S3/BucketAnonymousAccessGranted")
    finding_id = detail.get("id", "unknown")
    region = detail.get("region", "<ACCOUNT_REGION>")
    account_id = detail.get("accountId", "unknown")
    severity_num = float(detail.get("severity", 9))

    if severity_num < 4:
        severity = "Low"
    elif severity_num < 7:
        severity = "Medium"
    elif severity_num < 9:
        severity = "High"
    else:
        severity = "Critical"

    bucket_detail = detail.get("resource", {}).get("s3BucketDetails", [{}])[0]
    bucket_name = bucket_detail.get("name", "unknown")
    bucket_arn = bucket_detail.get("arn", f"arn:aws:s3:::{bucket_name}")

    ip_address = (
        detail.get("service", {}).get("action", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
        detail.get("service", {}).get("action", {}).get("actionDetails", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
        "unknown"
    )

    geo_location = (
        detail.get("service", {}).get("action", {}).get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode", "unknown")
    )

    print(f"[+] S3 public policy access detected for bucket: {bucket_name}")

    # Step 1: Remove bucket policy
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
        print(f"[+] Removed bucket policy for {bucket_name}")
    except Exception as e:
        print(f"[!] Failed to remove policy: {str(e)}")

    # Step 2: Apply public access block
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"[+] Applied public access block for {bucket_name}")
    except Exception as e:
        print(f"[!] Failed to apply public access block: {str(e)}")

    # Step 3: Log to DynamoDB
    time_responded = datetime.now(timezone.utc)
    latency = Decimal(str((time_responded - time_detected).total_seconds()))
    incident_id = f"s3unauth-{time_detected.strftime('%Y%m%d%H%M%S')}"

    remediation_table = dynamodb.Table(DDB_TABLE)
    try:
        remediation_table.put_item(Item={
            "id": incident_id,
            "finding_id": finding_id,
            "timestamp": time_responded.isoformat(),
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": ip_address,
            "resource_id": bucket_name,
            "affected_service": "S3",
            "iam_user": "unknown",
            "iam_user_arn": "unknown",
            "account_id": account_id,
            "action_taken": "Removed public bucket policy and applied public access block",
            "action_status": "completed",
            "response_type": "public_access_block",
            "playbook_name": "s3_unauth_response",
            "review_required": False,
            "sns_sent": False,
            "time_occurred": time_detected.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["s3", "unauthorized", "public-access"]
        })
        print("[+] Logged remediation to DynamoDB")
    except Exception as e:
        print(f"[!] Failed to log to DynamoDB: {str(e)}")

    # Step 4: Send SNS Alert and update sns_sent
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='SOAR Alert: S3 Unauthorized Access',
            Message=(
                f"S3 bucket {bucket_name} (ARN: {bucket_arn}) was misconfigured with a public access policy.\n"
                f"Offending IP: {ip_address}\n"
                f"Policy was deleted and public access block applied."
            )
        )
        print("[+] SNS alert sent")

        remediation_table.update_item(
            Key={"id": incident_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True")
    except Exception as e:
        print(f"[!] Failed to send SNS or update sns_sent: {str(e)}")

    return {"status": "success", "message": "S3 public access remediation completed"}
