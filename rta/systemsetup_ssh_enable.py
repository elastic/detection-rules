# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Remote SSH Login Enabled via systemsetup Command",
            "rule_id": "5ae4e6f8-d1bf-40fa-96ba-e29645e1e4dc",
        }
    ],
    "ENDPOINT": [],
}
TECHNIQUES = ["T1021"]
RTA_ID = "23997dfa-9e30-4091-9ee2-8bd45a2da70a"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/systemsetup"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake systemsetup command to mimic enabling remote SSH.")
    common.execute([masquerade, "-setremotelogin", "on"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
