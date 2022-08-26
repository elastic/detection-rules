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
            "rule_name": "Potential Credential Access via Rubeus",
            "rule_id": "0783f666-75ad-4015-9dd5-d39baec8f6b0",
        }
    ],
}
TACTICS = ["TA0006"]
RTA_ID = "85cf6796-5f53-4fed-a5cb-8b211882543c"


@common.requires_os(PLATFORMS)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    cmd = "Echo asreproast instead of executing it"
    # Execute command
    common.execute([powershell, "/c", "echo", cmd], timeout=10)


if __name__ == "__main__":
    exit(main())
