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
            "rule_name": "Delayed Execution via Ping",
            "rule_id": "7615ca4b-c291-4f05-9488-114b6bf99157",
        }
    ],
}
TECHNIQUES = ["T1216", "T1220", "T1218", "T1059"]
RTA_ID = "48419773-64de-498a-be98-cb1f6815e80c"


@common.requires_os(PLATFORMS)
def main():
    cmd = "C:\\Windows\\System32\\cmd.exe"

    # Execute command
    common.log("Delaying rundll32 execution using ping...")
    common.execute(
        [cmd, "/c", "ping -n 3 127.0.0.1 && rundll32.exe"], timeout=5, kill=True
    )


if __name__ == "__main__":
    exit(main())
