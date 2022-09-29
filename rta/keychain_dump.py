# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f158a6dc-1974-4b98-a3e7-466f6f1afe01",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Dumping of Keychain Content via Security Command",
            "rule_id": "565d6ca5-75ba-4c82-9b13-add25353471c",
        }
    ],
    techniques=["T1555"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands to dump keychain credentials")
    common.execute([masquerade, "dump-keychain", "-d"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
