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
            "rule_name": "Execution of a Windows Script with Unusual File Extension",
            "rule_id": "b76c0a04-b504-4a2f-a0cf-b4175a2f3eea",
        }
    ],
}
TACTICS = ["TA0002"]
RTA_ID = "04fa2fff-bbcb-4b13-ad10-33225056e34e"


@common.requires_os(PLATFORMS)
def main():
    common.log("Executing cscript against .exe")
    common.execute(
        ["cmd.exe", "/c", "cscript.exe", "/e:Vbscript", "cmd.exe"], timeout=5, kill=True
    )


if __name__ == "__main__":
    exit(main())
