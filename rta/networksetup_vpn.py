# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f9a34606-863d-46aa-b12d-eeeb68b530e3",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {"rule_name": "Virtual Private Network Connection Attempt", "rule_id": "15dacaa0-5b90-466b-acab-63435a59701a"}
    ],
    techniques=["T1021"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/networksetup"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake networksetup commands to connect to a VPN.")
    common.execute([masquerade, "-connectpppoeservice"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
