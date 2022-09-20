# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ce87d15a-9b72-42c4-8721-ae4bcff86a05",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Screensaver Plist File Modified by Unexpected Process",
            "rule_id": "ebae5222-71ba-4b73-afe9-8e034f8b4a04",
        }
    ],
    siem=[
        {
            "rule_name": "Screensaver Plist File Modified by Unexpected Process",
            "rule_id": "e6e8912f-283f-4d0d-8442-e0dcaf49944b",
        }
    ],
    techniques=["T1546"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/killall"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake file screensaver plist modification commands")
    common.temporary_file_helper(
        "testing",
        file_name="/Library/Managed Preferences/com.apple.screensaver.test.plist",
    )
    common.execute([masquerade, "cfprefsd"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
