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
            "rule_name": "Connection to Dynamic DNS Provider by a Signed Binary Proxy",
            "rule_id": "fb6939a2-1b54-428c-92a2-3a831585af2a",
        }
    ],
}
TECHNIQUES = ["T1218", "T1071"]
RTA_ID = "95d34e55-789d-40bf-9988-dbb803c2d066"


@common.requires_os(PLATFORMS)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.log("Using PowerShell to connect to a DDNS provider website")
    common.execute(
        [powershell, "/c", "iwr", "https://www.noip.com", "-UseBasicParsing"],
        timeout=10,
    )


if __name__ == "__main__":
    exit(main())
