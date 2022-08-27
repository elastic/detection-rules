# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Suspicious macOS MS Office Child Process",
            "rule_id": "66da12b1-ac83-40eb-814c-07ed1d82b7b9",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = ["TA0001"]
RTA_ID = "65ae1bcd-0b1c-4992-97c3-f40b0f92deb1"


@common.requires_os(PLATFORMS)
def main():

    # create masquerades
    masquerade = "/tmp/Microsoft Word"
    masquerade2 = "/tmp/bash"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)

    common.log("Executing fake Microsoft commands to mimic suspicious child processes.")
    common.execute([masquerade, "childprocess", masquerade2], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
