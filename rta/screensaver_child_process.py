# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="adc70542-4d6e-4449-bf96-4cd44367bfbb",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Unexpected Child Process of macOS Screensaver Engine",
            "rule_id": "fba012f6-7aa8-448e-8f59-cdecce2845b5",
        }
    ],
    siem=[
        {
            "rule_name": "Unexpected Child Process of macOS Screensaver Engine",
            "rule_id": "48d7f54d-c29e-4430-93a9-9db6b5892270",
        }
    ],
    techniques=["T1546"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/ScreenSaverEngine"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands to spawn bash from screensaver engine")
    common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
