# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Suspicious Emond Child Process",
            "rule_id": "3e3d15c6-1509-479a-b125-21718372157e",
        }
    ],
    "ENDPOINT": [
        {
            "rule_name": "Potential Persistence via Emond",
            "rule_id": "1cd247d8-00e8-4c62-b9ee-90cd1811460b",
        }
    ],
}
TACTICS = ["TA0003"]
RTA_ID = "58041706-c636-4043-b221-3d59f977b7e2"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/emond"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching bash from fake emond command")
    common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
