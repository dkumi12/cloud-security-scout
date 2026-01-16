import json
import boto3
import os
from boto3.dynamodb.conditions import Key
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('FINDINGS_TABLE')
table = dynamodb.Table(TABLE_NAME) if TABLE_NAME else None


class DecimalEncoder(json.JSONEncoder):
    """Convert Decimal to float for JSON serialization"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)


def lambda_handler(event, context):
    """
    API Lambda to fetch security findings from DynamoDB
    Supports query parameters: limit, severity, resource_type
    """
    try:
        if not table:
            return response(500, {'error': 'DynamoDB table not configured'})
        
        # Parse query parameters
        params = event.get('queryStringParameters') or {}
        limit = int(params.get('limit', 100))
        severity_filter = params.get('severity', '').upper()
        resource_type_filter = params.get('resource_type', '')
        
        # Scan DynamoDB for findings
        scan_kwargs = {
            'Limit': limit
        }
        
        result = table.scan(**scan_kwargs)
        findings = result.get('Items', [])
        
        # Apply filters
        if severity_filter:
            findings = [f for f in findings if f.get('severity', '').upper() == severity_filter]
        
        if resource_type_filter:
            findings = [f for f in findings if resource_type_filter.lower() in f.get('resource_type', '').lower()]
        
        # Sort by timestamp (newest first)
        findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Calculate summary statistics
        summary = calculate_summary(findings)
        
        return response(200, {
            'summary': summary,
            'findings': findings[:limit],
            'total_count': len(findings)
        })
        
    except Exception as e:
        print(f"Error fetching findings: {str(e)}")
        return response(500, {'error': str(e)})


def calculate_summary(findings):
    """Calculate summary statistics from findings"""
    summary = {
        'total': len(findings),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'by_resource_type': {},
        'by_region': {}
    }
    
    for finding in findings:
        severity = finding.get('severity', 'UNKNOWN').upper()
        resource_type = finding.get('resource_type', 'Unknown')
        region = finding.get('region', 'Unknown')
        
        # Count by severity
        if severity == 'CRITICAL':
            summary['critical'] += 1
        elif severity == 'HIGH':
            summary['high'] += 1
        elif severity == 'MEDIUM':
            summary['medium'] += 1
        elif severity == 'LOW':
            summary['low'] += 1
        
        # Count by resource type
        summary['by_resource_type'][resource_type] = summary['by_resource_type'].get(resource_type, 0) + 1
        
        # Count by region
        summary['by_region'][region] = summary['by_region'].get(region, 0) + 1
    
    return summary


def response(status_code, body):
    """Format API Gateway response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'GET, OPTIONS'
        },
        'body': json.dumps(body, cls=DecimalEncoder)
    }
