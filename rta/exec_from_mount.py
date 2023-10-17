# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="21d1d048-b8c9-4b6d-9748-44f8af1b444d",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Shell Script Execution from abnormal Volume Mount Path",
            "rule_id": "87def154-004d-4d3a-8224-591e41804454",
        }
    ],
    techniques=["T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/Volumes/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching bash commands to simulate execution from mounted volume")
    common.execute([masquerade, "/Volumes/*/Contents/*"], timeout=10, kill=True)


if __name__ == "__main__":
    exit(main())
