# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="432b8bb0-03e2-4618-bda9-77c0cef7eef8",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "22145fc0-dc4c-4187-8397-4d20162fc391",
            "rule_name": "CVE-2023-0386 Exploitation Attempt",
        },
    ],
    siem=[],
    techniques=["T1068"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/fuse"
    masquerade2 = "/tmp/fusermount"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    common.copy_file(source, masquerade)
    common.copy_file(source, masquerade2)

    # Execute command
    common.log("Executing Fake Commands to simulate CVE-2023-0386 Exploitation Attempt")
    command = f"{masquerade2} -o rw,nosuid,nodev ./* "
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)  # noqa: S604

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
