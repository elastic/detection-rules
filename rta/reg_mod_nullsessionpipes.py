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
            "rule_name": "Suspicious NullSessionPipe Registry Modification",
            "rule_id": "11d374d8-2dad-4d9b-83a2-ee908eac8269",
        }
    ],
}
TECHNIQUES = ["T1021", "T1112"]
RTA_ID = "a6263f00-58b4-4555-b88f-9d66a7395891"


@common.requires_os(PLATFORMS)
def main():
    common.log("Modifying NullSessionPipes reg key...")

    key = "SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters"
    value = "NullSessionPipes"
    data = "RpcServices"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
