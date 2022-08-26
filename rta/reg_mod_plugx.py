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
            "rule_name": "Potential PlugX Registry Modification",
            "rule_id": "7a201712-9f3c-4f40-b4fc-2418a44b8ecb",
        }
    ],
}
TACTICS = ["TA0003", "TA0005", "TA0011"]
RTA_ID = "31fdd029-5fac-474f-9201-3b7bfb60e0cf"


@common.requires_os(PLATFORMS)
def main():
    common.log("Temporarily creating a PlugX-like reg key...")

    key = "SOFTWARE\\CLASSES\\ms-pu\\PROXY"
    value = "Test"
    data = "Test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
