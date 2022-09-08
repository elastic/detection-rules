# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="603d77bf-cdfc-44dd-94d3-5b4016caef94",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Suspicious Access to Keychain Credentials Files",
            "rule_id": "150f20b4-6b21-460b-8ae4-339695c1c86c",
        }
    ],
    siem=[
        {"rule_name": "Access to Keychain Credentials Directories", "rule_id": "96e90768-c3b7-4df6-b5d9-6237f8bc36a8"}
    ],
    techniques=["T1555"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands to access keychain creds")
    common.execute([masquerade, f"{Path.home()}/Library/Keychains/test"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
