# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4406f514-0ffa-465b-9cef-2eeeb32f1096",
    platforms=["macos"],
    endpoint=[
        {
            "rule_id": "5dce3865-838f-4773-9781-87226af1fc12",
            "rule_name": "Payload Decoded and Decrypted via Built-In Utilities",
        }
    ],
    siem=[],
    techniques=["T1027", "T1140", "T1059", "T1059.004", "T1204", "T1204.002"],
)


@common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/DiskImageMounter"
    masquerade2 = "/tmp/bash"
    masquerade3 = "/tmp/openssl"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)
    common.create_macos_masquerade(masquerade3)

    # Execute command
    common.log("Launching fake bash with base64 decode commands")
    common.execute([masquerade], timeout=10, kill=True)

    command = f"{masquerade3} enc -base64 -d"
    common.execute([masquerade2, "childprocess", command, "/Volumes/test"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.remove_file(masquerade3)


if __name__ == "__main__":
    exit(main())
