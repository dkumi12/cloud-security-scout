\# Cloud Security Scout (SAM starter)



Automated security scanner for AWS:

\- Scans S3 buckets for potential public exposure

\- Scans EC2 Security Groups for wide open rules (0.0.0.0/0, ::/0)

\- Scans RDS instances for `PubliclyAccessible = True`

\- Logs findings to DynamoDB and publishes alerts to SNS and optionally Slack



\## Repo structure
cloud-security-scout/
├─ template.yaml
├─ app.py
├─ requirements.txt
├─ README.md
├─ test_event.json
└─ .gitignore



