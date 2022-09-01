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
            "rule_name": "Registry Run Key Prefixed with Asterisk",
            "rule_id": "94d35931-5c48-49ed-8c18-d601c4f8aeaa",
        }
    ],
}
TECHNIQUES = ["T1547"]
RTA_ID = "13fbcfdc-ba84-414b-aaa6-49b416806c8e"


@common.requires_os(PLATFORMS)
def main():
    common.log("Writing registry key")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    value = "*test"
    data = "test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
