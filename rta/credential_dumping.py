# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="43ce7648-d48a-4609-80a5-f68384e498d3",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "05f95917-6942-4aab-a904-37c6db906503",
            "rule_name": "Potential Linux Credential Dumping via Unshadow",
        },
    ],
    siem=[],
    techniques=["T1003"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/unshadow"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Executing Fake commands to test Credential Dumping via Unshadow")
    common.execute([masquerade, "shadow password"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
