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
            "rule_name": "LSA Dump via SilentProcessExit",
            "rule_id": "28969fe6-0ebe-4442-b40c-dbe9b4234f5e",
        }
    ],
}
TACTICS = ["TA0006"]
RTA_ID = "bf2f893a-513a-41ea-9170-2c9b08a2a55f"


@common.requires_os(PLATFORMS)
def main():
    common.log("Temporarily creating LSA SilentProcessExit reg key...")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
    value = "lsass.exe"
    data = "0"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
