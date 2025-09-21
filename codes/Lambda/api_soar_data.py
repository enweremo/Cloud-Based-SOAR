import boto3
import json
import decimal
from datetime import datetime, timedelta, timezone

dynamodb = boto3.resource('dynamodb')

THREAT_TABLE = 'ThreatMetadata'
REMEDIATION_TABLE = 'RemediationLog'
BLOCKLIST_TABLE = 'NACLBlockList'

def lambda_handler(event, context):
    # CORS Preflight
    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "<YOUR_GITHUB OR STATIC_WEBSITE>",
                "Access-Control-Allow-Methods": "GET,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            },
            "body": json.dumps({"message": "CORS preflight success"})
        }

    try:
        print("EVENT:", json.dumps(event))
        params = event.get("queryStringParameters", {}) or {}
        days = int(params.get("days", 7))
        print(f"[+] Days to fetch: {days}")

        now = datetime.now(timezone.utc)
        since = now - timedelta(days=days)

        print("[+] Querying DynamoDB tables...")
        threats = query_table(THREAT_TABLE, since)
        remediations = query_table(REMEDIATION_TABLE, since)
        blocked_ips = query_table(BLOCKLIST_TABLE, since)

        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "<YOUR_GITHUB OR STATIC_WEBSITE>",
                "Access-Control-Allow-Methods": "GET,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            },
            "body": json.dumps({
                "threats": threats,
                "remediations": remediations,
                "blocked_ips": blocked_ips
            }, default=str)
        }

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {
            "statusCode": 500,
            "headers": {
                "Access-Control-Allow-Origin": "<YOUR_GITHUB OR STATIC_WEBSITE>",
                "Access-Control-Allow-Methods": "GET,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            },
            "body": json.dumps({"message": "Internal server error"})
        }

def query_table(table_name, since_time):
    print(f"[Query] Table: {table_name}")
    try:
        table = dynamodb.Table(table_name)
        response = table.scan()
        items = response.get('Items', [])
        print(f"[Query] {len(items)} items fetched from {table_name}")
        return [
            item for item in items
            if 'timestamp' in item and parse_time(item['timestamp']) >= since_time
        ]
    except Exception as e:
        print(f"[Query Error] {table_name}: {str(e)}")
        return [{"error": str(e)}]

def parse_time(ts):
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception as e:
        print(f"[Parse Error] Timestamp: {ts}, Error: {str(e)}")
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
