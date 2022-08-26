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
            "rule_name": "Privilege Escalation via Windir or SystemRoot Environment Variable",
            "rule_id": "18ffee0c-5f40-4dd8-aa9a-28251a308dbc",
        }
    ],
}
TACTICS = ["TA0004"]
RTA_ID = "38cea037-c1a8-4749-a434-ba4c7d6e91f8"


@common.requires_os(PLATFORMS)
def main():
    key = "System\\Environment"
    value = "windir"
    data = "rta"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
