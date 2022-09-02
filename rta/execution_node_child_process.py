# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="20631e46-d3c4-45c0-bfa8-37f6b287db36",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Execution via Electron Child Process Node.js Module",
            "rule_id": "1d43f87d-2466-4714-8fef-d52816cc25fb",
        }
    ],
    siem=[
        {
            "rule_name": "Execution via Electron Child Process Node.js Module",
            "rule_id": "35330ba2-c859-4c98-8b7f-c19159ea0e58",
        }
    ],
    techniques=["T1548", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/node"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Spawning fake node commands to mimic Electon child process.")
    common.execute(
        [masquerade, "-e", "const { fork } = require('child_process');"],
        timeout=10,
        kill=True,
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
