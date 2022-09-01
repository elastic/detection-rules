# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["macos"]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_name": "Attempt to Mount SMB Share via Command Line",
            "rule_id": "661545b4-1a90-4f45-85ce-2ebd7c6a15d0",
        }
    ],
    "ENDPOINT": [],
}
TECHNIQUES = ["T1021"]
RTA_ID = "d275922f-a702-4668-a77d-c60e8df58646"


@common.requires_os(PLATFORMS)
def main():

    masquerade = "/tmp/mount_smbfs"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake mount_smbfs command to mimic mounting a network share.")
    common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
