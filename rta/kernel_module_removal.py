# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="9885fd40-d51c-4706-8958-4143ea762302",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "e80ba5e4-b6c6-4534-87b0-8c0f4e1d97e7",
            "rule_name": "Kernel Module Removal",
        },
    ],
    siem=[],
    techniques=["T1562", "T1562.001", "T1547", "T1547.006"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/bash"
    masquerade2 = "/tmp/rmmod"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    common.copy_file(source, masquerade)
    common.copy_file(source, masquerade2)

    # Execute command
    common.log("Executing Fake Commands to simulate Kernel Module Removal")
    command = f"{masquerade2}"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)  # noqa: S604

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
