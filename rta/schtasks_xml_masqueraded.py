# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["windows"]
TRIGGERED_RULES = {
    "SIEM": [],
    "ENDPOINT": [
        {
            "rule_name": "Suspicious Scheduled Task Creation via Masqueraded XML File",
            "rule_id": "1efc0496-106b-4c09-b99b-91cdd17ba7b3",
        }
    ],
}
TECHNIQUES = ["T1053", "T1036"]
RTA_ID = "4bb0b65e-8e78-4680-ab37-d6c0723f97a9"


@common.requires_os(PLATFORMS)
def main():
    # Execute Command
    common.log(
        "Executing command to simulate the task creation (This will not create a task)"
    )
    common.execute(["schtasks.exe", "/CREATE", "/XML", "update", "/TN", "Test", "/F"])


if __name__ == "__main__":
    exit(main())
