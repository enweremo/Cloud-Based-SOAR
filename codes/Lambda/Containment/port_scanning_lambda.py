import boto3
from datetime import datetime, timezone
from decimal import Decimal

ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

DDB_TABLE = 'RemediationLog'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'

def lambda_handler(event, context):
    time_detected = datetime.now(timezone.utc)

    detail = event.get("detail", {})
    finding_id = detail.get("id", "unknown")
    region = detail.get("region", "<ACCOUNT_REGION>")
    account_id = detail.get("accountId", "unknown")
    severity_num = float(detail.get("severity", 0))
    if severity_num < 4:
        severity = "Low"
    elif severity_num < 7:
        severity = "Medium"
    elif severity_num < 9:
        severity = "High"
    else:
        severity = "Critical"
    instance_id = detail.get("resource", {}).get("instanceDetails", {}).get("instanceId", "unknown")
    source_ip = detail.get("service", {}).get("action", {}).get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("ipAddressV4", "unknown")
    geo_location = detail.get("service", {}).get("action", {}).get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode", "unknown")
    finding_type = detail.get("type", "")
    valid_types = [
        "Recon:EC2/Portscan",
        "Recon:EC2/PortProbeUnprotectedPort",
        "Impact:EC2/PortSweep"
    ]

    if finding_type not in valid_types:
        print(f"[!] Skipped: {finding_type}")
        return {"status": "ignored", "message": "Not part of playbook"}

    print(f"Detected Port Scanning on EC2 instance: {instance_id}")

    # Step 1: Get associated security groups
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        sg_ids = [sg['GroupId'] for sg in response['Reservations'][0]['Instances'][0]['SecurityGroups']]
    except Exception as e:
        print(f"Error retrieving security groups for instance {instance_id}: {str(e)}")
        return {"status": "error", "message": str(e)}

    # Step 2: Revoke non-web inbound rules (not 80 or 443)
    for sg_id in sg_ids:
        try:
            sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
            ip_permissions = sg.get('IpPermissions', [])
            revoke_rules = []

            for rule in ip_permissions:
                from_port = rule.get('FromPort')
                if from_port is not None and from_port not in [80, 443]:
                    revoke_rules.append(rule)

            if revoke_rules:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=revoke_rules
                )
                print(f"Revoked non-web inbound rules from SG {sg_id}")
            else:
                print(f"No non-web rules to revoke in SG {sg_id}")
        except Exception as e:
            print(f"Error modifying SG {sg_id}: {str(e)}")

    # Step 3: Tag instance as under probe
    try:
        ec2.create_tags(Resources=[instance_id], Tags=[{'Key': 'Status', 'Value': 'UnderProbe'}])
        print(f"Tagged instance {instance_id} as UnderProbe")
    except Exception as e:
        print(f"Failed to tag instance: {str(e)}")

    time_responded = datetime.now(timezone.utc)
    latency = Decimal(str((time_responded - time_detected).total_seconds())) 
    incident_id = f"portscan-{time_detected.strftime('%Y%m%d%H%M%S')}"

    # Step 5: Log to DynamoDB
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
            "source_ip": source_ip,
            "resource_id": instance_id,
            "affected_service": "EC2",
            "iam_user": "unknown",
            "iam_user_arn": "unknown",
            "account_id": account_id,
            "action_taken": "Non-web ports revoked from SG to quarantine instance",
            "action_status": "completed",
            "response_type": "network_restriction",
            "playbook_name": "port_scan_response",
            "review_required": True,
            "sns_sent": False,
            "time_occurred": time_detected.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["port_scan", "network_probe", "ec2"]
        })
        print("[+] Logged remediation to DynamoDB")
    except Exception as e:
        print(f"[!] Failed to log to DynamoDB: {str(e)}")

    # Step 6: Send SNS Alert and update sns_sent flag
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='SOAR Alert: Port Scanning Detected',
            Message=f'Port scanning detected on instance {instance_id}. All non-web ports revoked from its security group.'
        )
        print("[+] SNS alert sent")

        # Update sns_sent to True
        remediation_table.update_item(
            Key={"id": incident_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True") 
    except Exception as e:
        print(f"[!] Failed to send SNS or update sns_sent: {str(e)}")

    return {"status": "success", "message": "Port scan handled and logged."}
