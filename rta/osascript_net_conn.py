# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Apple Script Execution followed by Network Connection",
            "rule_id": "47f76567-d58a-4fed-b32b-21f571e28910",
        }
    ],
    "ENDPOINT": [],
}
TECHNIQUES = ["T1105", "T1059"]
RTA_ID = "66407efa-a32e-4f4d-b339-def48e23e810"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/osascript"
    common.copy_file("/usr/bin/curl", masquerade)

    # Execute command
    common.log(
        "Launching fake commands to mimic creating a network connection with osascript"
    )
    common.execute([masquerade, "portquiz.net"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
