# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="0612b920-62d8-4e1c-81c6-e6583571fc49",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Kill Command Executed from Binary in Unusual Location",
            "rule_id": "b9935dcc-e885-4954-9999-3c016b990737",
        },
    ],
    techniques=["T1059", "T1562"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Path for the fake kill script
    kill_script = "/dev/shm/rta"

    # Create fake executable
    masquerade = "/tmp/kill"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.execute(["chmod", "+x", masquerade])

    # Create a fake script that executes the fake binary
    with Path(kill_script).open("w", encoding="utf-8") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/kill\n")

    # Make the script executable
    common.execute(["chmod", "+x", kill_script])

    # Execute the fake script
    common.log("Launching fake kill script")
    common.execute([kill_script], timeout=5, kill=True, shell=True)  # noqa: S604

    # Cleanup
    common.remove_file(kill_script)
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
