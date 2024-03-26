# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="8d6f2979-747a-42d9-813a-ddadd90650d2",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "7b9ddfc8-8ea8-45d5-b62f-3fbd142c8f08",
            "rule_name": "Behavior Protection - Cloud Reputation EICAR",
        },
    ],
    siem=[],
    techniques=["TA0002"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/bash"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching Behavior Protection - Cloud Reputation EICAR")
    common.execute([masquerade, "test-cloudreputationrule-5020a0031cad"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
