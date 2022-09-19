# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="bc6130d9-f4fd-46c6-bcfe-623be6c51a3b",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "WebProxy Settings Modification", "rule_id": "10a500bb-a28f-418e-ba29-ca4c8d1a9f2f"}],
    techniques=["T1539"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/networksetup"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake networksetup commands to configure webproxy settings")
    common.execute([masquerade, "-setwebproxy"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
