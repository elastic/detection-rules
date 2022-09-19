# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7548a786-50f7-40e5-8f8a-b005e9e8d864",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Launch Agent Creation or Modification and Immediate Loading",
            "rule_id": "082e3f8c-6f80-485c-91eb-5b112cb79b28",
        }
    ],
    techniques=["T1543"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/launchctl"
    common.create_macos_masquerade(masquerade)

    plist = f"{Path.home()}/Library/LaunchAgents/test.plist"
    common.temporary_file_helper("testing", file_name=plist)

    # Execute command
    common.log("Launching fake launchctl command to mimic plist loading")
    common.execute([masquerade, "load"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
