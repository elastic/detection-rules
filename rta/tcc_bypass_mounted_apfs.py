# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "TCC Bypass via Mounted APFS Snapshot Access",
            "rule_id": "b00bcd89-000c-4425-b94c-716ef67762f6",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = ["TA0005"]
RTA_ID = "4c8675a8-fbed-4f36-88e6-ffceaf82f426"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/mount_apfs"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake mount_apfs command to mount the APFS snapshot")
    common.execute(
        [masquerade, "/System/Volumes/Data", "noowners"], timeout=10, kill=True
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
