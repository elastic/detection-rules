# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f158a6dc-1974-4b98-a3e7-466f6f1afe01",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Keychain Dump via native Security tool",
            "rule_id": "549344d6-aaef-4495-9ca2-7a0b849bf571",
        }
    ],
    siem=[
        {
            "rule_name": "Dumping of Keychain Content via Security Command",
            "rule_id": "565d6ca5-75ba-4c82-9b13-add25353471c",
        }
    ],
    techniques=["T1555", "T1555.001"],
)


@common.requires_os(*metadata.platforms)
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
