#!/bin/bash
# Runs ONCE, as root, when a new server boots.
# Terraform fills in the placeholder values before sending it to AWS.
set -euo pipefail # stop on any error (no -x: it would print the DB password to the log)
exec > /var/log/user-data.log 2>&1

# 1. Install what we need
dnf install -y python3.11 python3.11-pip unzip jq amazon-cloudwatch-agent

# 2. Download our code from S3 (allowed by the IAM role)
mkdir -p /opt/app
cd /opt/app
aws s3 cp "s3://${bucket}/${app_key}" app.zip
aws s3 cp "s3://${bucket}/requirements.txt" requirements.txt
unzip -q -o app.zip -d app

# 3. Python virtual environment + libraries
python3.11 -m venv venv
./venv/bin/pip install --quiet -r requirements.txt

# 4. Read the DB password from Secrets Manager (never stored in code or Git)
SECRET=$(aws secretsmanager get-secret-value --region "${region}" \
  --secret-id "${secret_arn}" --query SecretString --output text)
DB_USER=$(echo "$SECRET" | jq -r .username)
DB_PASS=$(echo "$SECRET" | jq -r .password)
# The password may contain symbols like @ or /, so URL-encode it
DB_PASS_ENC=$(python3.11 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$DB_PASS")

# Only root can read this file
umask 077
cat > /etc/phishing.env <<EOF
DATABASE_URL=postgresql+psycopg://$DB_USER:$DB_PASS_ENC@${db_host}:5432/${db_name}?sslmode=require
EOF
umask 022

# 5. Run the app as a service: starts on boot, restarts if it crashes
useradd --system --no-create-home --shell /sbin/nologin phishing
mkdir -p /var/log/phishing

cat > /etc/systemd/system/phishing.service <<'EOF'
[Unit]
Description=Phishing Detector API
After=network-online.target
Wants=network-online.target

[Service]
User=phishing
WorkingDirectory=/opt/app
EnvironmentFile=/etc/phishing.env
ExecStart=/opt/app/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log
Restart=always
RestartSec=3
StandardOutput=append:/var/log/phishing/app.log
StandardError=append:/var/log/phishing/app.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now phishing

# 6. CloudWatch Agent: ship the app log + memory/disk metrics to CloudWatch
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'EOF'
{
  "agent": { "metrics_collection_interval": 60 },
  "metrics": {
    "namespace": "PhishingDetector",
    "append_dimensions": {
      "AutoScalingGroupName": "$${aws:AutoScalingGroupName}",
      "InstanceId": "$${aws:InstanceId}"
    },
    "aggregation_dimensions": [["AutoScalingGroupName"]],
    "metrics_collected": {
      "mem": { "measurement": ["mem_used_percent"] },
      "disk": { "measurement": ["used_percent"], "resources": ["/"] }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/phishing/app.log",
            "log_group_name": "${log_group}",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json