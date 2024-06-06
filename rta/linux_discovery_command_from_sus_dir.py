# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="be8c9227-8266-4d91-931e-c53e07731d07",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Linux User Discovery Command Execution from Suspicious Directory",
            "rule_id": "c932c9f0-76ed-4d78-a242-cfaade43080c",
        },
    ],
    techniques=["T1059", "T1033"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Path for the fake executable
    fake_executable = "/dev/shm/evil"

    # Create fake whoami executable
    masquerade = "/dev/shm/whoami"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Create a fake executable that launches whoami
    with Path(fake_executable).open("w") as script:
        script.write("#!/bin/bash\n")
        script.write("/dev/shm/whoami\n")

    # Make the script executable
    common.execute(["chmod", "+x", fake_executable])

    # Execute the fake executable
    common.log("Launching whoami as a child of fake executable")
    common.execute([fake_executable], timeout=5, kill=True, shell=True)  # noqa: S604

    # Cleanup
    common.remove_file(fake_executable)
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
