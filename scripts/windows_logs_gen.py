import os
import json
import random
import requests
from datetime import datetime
from faker import Faker

# Elastic Security SIEM Configuration

ELASTIC_URL = os.environ["ELASTIC_URL"]
ELASTIC_API_KEY = os.environ["ELASTIC_API_KEY"]


# Faker instance to generate random data
faker = Faker()

# List of example user accounts and source IPs
USER_ACCOUNTS = ["admin", "john.doe", "jane.smith", "guest", "user123", "adminfake"]
SOURCE_IPS = ["192.168.1.10", "192.168.1.50", "10.0.0.100", "172.16.0.20"]

# Generate a random authentication log entry in ECS format
def generate_auth_log():
    event_outcome = random.choice(["success", "failure"])
    user_name = random.choice(USER_ACCOUNTS)
    source_ip = random.choice(SOURCE_IPS)
    timestamp = datetime.utcnow().isoformat() + "Z"

    auth_log = {
        "@timestamp": timestamp,
        "event": {
            "category": ["authentication"],
            "action": "user_login",
            "outcome": event_outcome,
            "type": ["start"],
        },
        "host": {
            "hostname": faker.hostname(),
            "ip": faker.ipv4(),
        },
        "source": {
            "ip": source_ip
        },
        "user": {
            "name": user_name
        },
        "log": {
            "level": "info" if event_outcome == "success" else "warning",
        },
        "ecs": {
            "version": "8.0.0"
        }
    }
    return auth_log

# Send logs to Elasticsearch
def send_logs_to_elastic(logs):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {ELASTIC_API_KEY}"
    }
    url = f"{ELASTIC_URL}/logs-authentication/_doc/"

    for log in logs:
        response = requests.post(url, headers=headers, data=json.dumps(log))
        if response.status_code not in [200, 201]:
            print(f"❌ Failed to send log: {response.text}")
        else:
            print(f"✅ Log sent successfully: {log}")

# Generate and send multiple logs
if __name__ == "__main__":
    logs = [generate_auth_log() for _ in range(50)]
    send_logs_to_elastic(logs)
