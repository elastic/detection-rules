# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import subprocess
import sys
import time

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="65978ab7-37d2-4542-8e03-50b3d408ff42",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Linux Powershell Egress Network Connection",
            "rule_id": "1471cf36-7e5c-47cc-bf39-2234df0e676a",
        },
    ],
    techniques=["T1203"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    parent_process_path = "/tmp/pwsh"
    child_script_path = "/tmp/sh"
    network_command = "exec 3<>/dev/tcp/8.8.8.8/53"

    # Create the fake parent process script
    with open(parent_process_path, "w") as parent_script:  # noqa: PTH123
        parent_script.write("#!/bin/bash\n")
        parent_script.write(f"{child_script_path}\n")

    # Create the child script that will make the network connection
    with open(child_script_path, "w") as child_script:  # noqa: PTH123
        child_script.write("#!/bin/bash\n")
        child_script.write(f"{network_command}\n")

    # Make the scripts executable
    common.execute(["chmod", "+x", parent_process_path])
    common.execute(["chmod", "+x", child_script_path])

    # Execute the parent process script
    common.log("Executing the fake parent process script")
    subprocess.Popen([parent_process_path])  # noqa: S603

    # Allow some time for the network connection to be attempted
    time.sleep(5)
    common.log("RTA execution completed.")

    # Cleanup
    common.remove_file(parent_process_path)
    common.remove_file(child_script_path)


if __name__ == "__main__":
    sys.exit(main())
