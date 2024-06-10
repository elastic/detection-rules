# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="83b04be5-ed0f-4efd-a7fd-d5db2b8ab62f",
    platforms=["macos", "linux"],
    endpoint=[
        {
            "rule_name": "Potential Reverse Shell Activity via Terminal",
            "rule_id": "d0e45f6c-1f83-4d97-a8d9-c8f9eb61c15c",
        },
    ],
    siem=[],
    techniques=["T1071", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/bash"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    common.log("Executing command to simulate reverse shell execution")
    common.execute([masquerade, "/dev/tcp/127.0.0.1/4444"], timeout=5, kill=True, shell=True)  # noqa: S604


if __name__ == "__main__":
    sys.exit(main())
