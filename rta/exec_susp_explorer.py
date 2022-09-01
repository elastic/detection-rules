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
            "rule_name": "Suspicious Windows Explorer Execution",
            "rule_id": "f8ec5b76-53cf-4989-b451-7d16abec7298",
        }
    ],
}
TECHNIQUES = ["T1055", "T1036"]
RTA_ID = "76050b81-a8da-43d2-8a83-f18b31162b94"


@common.requires_os(PLATFORMS)
def main():
    explorer = "C:\\Windows\\explorer.exe"
    common.execute([explorer, "easyminerRTA"], timeout=1, kill=True)


if __name__ == "__main__":
    exit(main())
