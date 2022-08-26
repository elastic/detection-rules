# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Kerberos Cached Credentials Dumping",
            "rule_id": "ad88231f-e2ab-491c-8fc6-64746da26cfe",
        }
    ],
    "ENDPOINT": [
        {
            "rule_name": "Potential Access to Kerberos Cached Credentials",
            "rule_id": "dc8fa849-efb4-45d1-be1a-9472325ff746",
        }
    ],
}
TACTICS = ["TA0006"]
RTA_ID = "2f17286a-e4a8-41de-b3fa-595a4be6fb19"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/kcc"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake kcc command to load Kerberos tickets")
    common.execute([masquerade, "copy_cred_cache"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
