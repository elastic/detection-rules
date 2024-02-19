# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import pathlib
import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="5fce12c8-642a-49ad-9a94-e21d23149afb",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "0b206183-7f90-461d-80b3-8a147147ae78",
            "rule_name": "Suspicious Kibana Child Process",
        },
    ],
    siem=[],
    techniques=["T1190", "T1059", "T1059.004"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/kibana/node/bin/node"
    executable_dir = "/tmp/kibana/node/bin/"
    pathlib.Path(executable_dir).mkdir(parents=True, exist_ok=True)
    masquerade2 = "/tmp/bash"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    common.copy_file(source, masquerade)
    common.copy_file(source, masquerade2)

    # Execute command
    common.log("Executing Fake Commands to simulate Shell Command Execution via Kworker")
    command = (
        f"{masquerade2} /bin/sh -c lsb_release -a , "
        f"/bin/sh -c git rev-parse --short HEAD echo --unhandled-rejections=warn"
    )
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)  # noqa: S604

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
