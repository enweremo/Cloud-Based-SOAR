import json
import boto3
import datetime
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

TABLE_NAME = 'ThreatMetadata'
S3_BUCKET = '<S3_BUCKET_NAME>'

def get_severity_label(rating):
    rating = float(rating)
    if rating >= 9:
        return "Critical"
    elif rating >= 7:
        return "High"
    elif rating >= 4:
        return "Medium"
    else:
        return "Low"

def lambda_handler(event, context):
    time_responded = datetime.datetime.now(datetime.timezone.utc)
    print(f"[{time_responded.isoformat()}] [+] GuardDuty Event Received")

    try:
        finding = event.get('detail', {})
        finding_id = finding.get('id', 'unknown')
        finding_type = finding.get('type', 'unknown')
        severity_rating = float(finding.get('severity', 0))
        severity_label = get_severity_label(severity_rating)
        region = finding.get('region', 'unknown')
        account_id = finding.get('accountId', 'unknown')
        created_at_str = finding.get('updatedAt', time_responded.isoformat())
        time_occurred = datetime.datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        time_detected = time_occurred

        resource_type = finding.get('resource', {}).get('resourceType', 'unknown')
        instance_id = finding.get('resource', {}).get('instanceDetails', {}).get('instanceId', 'unknown')
        iam_user = finding.get('resource', {}).get('accessKeyDetails', {}).get('userName', 'unknown')
        iam_user_arn = finding.get('resource', {}).get('accessKeyDetails', {}).get('userArn', 'unknown')

        service = finding.get('service', {})
        action_type = service.get('action', {}).get('actionType', 'unknown')
        geo_location = service.get('action', {}).get('remoteIpDetails', {}).get('geoLocation', {}).get('countryCode', 'unknown')
        malicious_ip = service.get('action', {}).get('remoteIpDetails', {}).get('ipAddressV4', 'unknown')

        latency_seconds = Decimal(str((time_responded - time_detected).total_seconds()))

        # Insert into DynamoDB
        table = dynamodb.Table(TABLE_NAME)
        table.put_item(Item={
            "incident_id": f"threat-{time_detected.strftime('%Y%m%d%H%M%S')}",
            "FindingID": finding_id,
            "timestamp": time_responded.isoformat(),
            "time_occurred": time_occurred.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency_seconds,
            "finding_type": finding_type,
            "severity_rating": Decimal(str(severity_rating)),
            "severity_label": severity_label,
            "region": region,
            "geo_location": geo_location,
            "source_ip": malicious_ip,
            "resource_id": instance_id,
            "resource_type": resource_type,
            "iam_user": iam_user,
            "iam_user_arn": iam_user_arn,
            "account_id": account_id,
            "action_type": action_type,
            "action_status": "logged",
            "response_type": "detection_log",
            "playbook_name": "guardduty_metadata_ingestion",
            "review_required": severity_rating >= 5,
            "sns_sent": False,
            "tags": ["guardduty", "metadata", "archive"]
        })

        print(f"[{time_responded.isoformat()}] [+] Metadata stored in DynamoDB")

        # Archive the full event to S3
        archive_key = f"archived-findings/{time_occurred.date()}/finding-{finding_id}.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=archive_key,
            Body=json.dumps(event, indent=2).encode('utf-8'),
            ContentType='application/json'
        )

        print(f"[{time_responded.isoformat()}] [+] Raw finding archived to S3 at {archive_key}")

        return {
            'statusCode': 200,
            'body': json.dumps('Metadata saved and archived.')
        }

    except Exception as e:
        print(f"[{time_responded.isoformat()}] [!] Error processing finding: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }
