# Cloud Security Scout - Dashboard Deployment Guide

## 🎯 New Features Added

✅ **Security Dashboard** - Real-time visualization of security findings  
✅ **REST API** - Fetch findings from DynamoDB via API Gateway  
✅ **S3 Static Hosting** - Dashboard hosted on S3  
✅ **Charts & Analytics** - Severity breakdown, resource type analysis  

---

## 📁 Project Structure (Updated)

```
cloud-security-scout/
├── app.py                          # Scanner Lambda (existing)
├── requirements.txt                # Scanner dependencies
├── api/
│   ├── get_findings.py            # NEW: API Lambda
│   └── requirements.txt           # API dependencies
├── dashboard/
│   └── index.html                 # NEW: Security dashboard
├── template-with-dashboard.yaml   # NEW: Enhanced SAM template
└── template.yaml                  # OLD: Original template
```

---

## 🚀 Deployment Steps

### 1. Build the SAM Application

```bash
sam build --template-file template-with-dashboard.yaml
```

### 2. Deploy to AWS

```bash
sam deploy \
  --template-file template-with-dashboard.yaml \
  --stack-name cloud-security-scout \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile your-profile
```

Or use guided deploy:

```bash
sam deploy --guided --template-file template-with-dashboard.yaml
```

### 3. Upload Dashboard to S3

After deployment, SAM outputs will show your S3 bucket name and API endpoint.

```bash
# Get outputs
aws cloudformation describe-stacks \
  --stack-name cloud-security-scout \
  --query 'Stacks[0].Outputs' \
  --output table

# Note these values:
# - DashboardBucket: cloud-security-scout-dashboard-ACCOUNT_ID
# - ApiEndpoint: https://xxxxx.execute-api.us-east-1.amazonaws.com/prod/findings
```

### 4. Update Dashboard with API Endpoint

Edit `dashboard/index.html` and replace:

```javascript
const API_ENDPOINT = 'YOUR_API_GATEWAY_URL/findings';
```

With your actual API endpoint from the outputs.

### 5. Upload Dashboard Files

```bash
aws s3 cp dashboard/index.html s3://cloud-security-scout-dashboard-ACCOUNT_ID/ \
  --content-type "text/html"
```

---

## 🔍 Testing

### Test the Scanner Lambda

```bash
aws lambda invoke \
  --function-name cloud-security-scout \
  --payload '{"test":"scan"}' \
  output.json
```

### Test the API

```bash
curl https://YOUR_API_GATEWAY_URL/prod/findings
```

### View Dashboard

Open: `http://cloud-security-scout-dashboard-ACCOUNT_ID.s3-website-REGION.amazonaws.com`

---

## 📊 Dashboard Features

- **Real-time Stats**: Total, Critical, High, Medium, Low findings
- **Charts**: Severity distribution, resource type breakdown
- **Findings Table**: Detailed list of recent security issues
- **Auto-refresh**: Click button to reload latest data

---

## 🔧 Configuration

### Environment Variables (Scanner)

```yaml
FINDINGS_TABLE: CloudSecurityScoutFindings
ALERT_TOPIC_ARN: arn:aws:sns:...
SCAN_REGIONS: us-east-1,us-west-2  # Optional
SLACK_WEBHOOK_URL: https://...     # Optional
```

### IAM Permissions Required

- DynamoDB: PutItem, GetItem, Scan, Query
- EC2: DescribeSecurityGroups, DescribeInstances
- S3: GetBucketAcl, GetBucketPolicy, ListAllMyBuckets
- RDS: DescribeDBInstances
- SNS: Publish

---

## 🛠️ Troubleshooting

### Dashboard shows "Error loading data"

1. Check API endpoint in dashboard HTML is correct
2. Verify API Gateway is deployed: `aws apigateway get-rest-apis`
3. Check CORS is enabled on API
4. Test API directly with curl

### Scanner not finding issues

1. Check CloudWatch Logs: `/aws/lambda/cloud-security-scout`
2. Verify IAM permissions for scanner Lambda
3. Manually invoke: `aws lambda invoke --function-name cloud-security-scout out.json`

### Empty DynamoDB table

1. Scanner may not have run yet (scheduled daily)
2. Manually trigger: `aws lambda invoke --function-name cloud-security-scout`
3. Check for IAM permission issues in logs

---

## 💰 Cost Estimate

- **Lambda**: ~$0.10/month (minimal invocations)
- **DynamoDB**: Pay-per-request (typically <$1/month)
- **S3**: <$0.50/month for dashboard hosting
- **API Gateway**: Free tier covers most usage

**Total**: ~$1-2/month

---

## 🔄 Updates

To update after code changes:

```bash
sam build --template-file template-with-dashboard.yaml
sam deploy --stack-name cloud-security-scout
aws s3 cp dashboard/index.html s3://YOUR_BUCKET/
```

---

## 📝 Next Steps

- Add email subscription to SNS topic
- Configure Slack webhook for alerts
- Expand scanner to more services (Lambda, ECS, etc.)
- Add export functionality to dashboard
- Implement remediation actions

---

**Dashboard Live!** 🎉  
Access at: `http://cloud-security-scout-dashboard-ACCOUNT_ID.s3-website-REGION.amazonaws.com`
