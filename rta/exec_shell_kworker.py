# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="f8c314b7-453b-4b12-95ff-e905b92be4e2",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "94943f02-5580-4d1d-a763-09e958bd0f57",
            "rule_name": "Shell Command Execution via Kworker",
        },
    ],
    siem=[],
    techniques=["T1036", "T1059", "T1059.004"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/kworker"
    masquerade2 = "/tmp/bash"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    common.copy_file(source, masquerade)
    common.copy_file(source, masquerade2)

    # Execute command
    common.log("Executing Fake Commands to simulate Shell Command Execution via Kworker")
    command = f"{masquerade2} -c test test1"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)  # noqa: S604

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
