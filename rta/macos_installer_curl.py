# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="34040af5-1231-4e97-8189-a26d6622b2e5",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Initial Access via macOS Installer Package", "rule_id": "d40ffcba-b83e-4d0a-8d6d-84385def8e18"}
    ],
    siem=[],
    techniques=["T1105", "T1543", "T1082", "T1566", "T1204", "T1547", "T1569", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/Installer"
    masquerade2 = "/tmp/curl"
    common.create_macos_masquerade(masquerade)
    common.create_macos_masquerade(masquerade2)

    # Execute command
    common.log("Launching fake macOS installer commands to download payload")
    common.execute([masquerade], timeout=10, kill=True)

    command = f"{masquerade2} test.amazonaws.comtest "
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
