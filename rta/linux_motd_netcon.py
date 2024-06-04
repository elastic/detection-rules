# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

import subprocess
import time

metadata = RtaMetadata(
    uuid="6a3d9ca4-d010-42c7-b75a-7dc8ce347e59",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Message of the Day Execution Followed by Network Connection",
            "rule_id": "a18e57c9-5627-4535-b994-64febc67c1e8"
        }
    ],
    techniques=["T1037", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    parent_process_path = "/etc/update-motd.d/rta"
    child_script_path = "/etc/update-motd.d/child.sh"
    network_command = "exec 3<>/dev/tcp/8.8.8.8/53"

    # Create the fake parent process script
    with open(parent_process_path, "w") as parent_script:
        parent_script.write("#!/bin/bash\n")
        parent_script.write(f"{child_script_path}\n")

    # Create the child script that will make the network connection
    with open(child_script_path, "w") as child_script:
        child_script.write("#!/bin/bash\n")
        child_script.write(f"{network_command}\n")

    # Make the scripts executable
    common.execute(['chmod', '+x', parent_process_path])
    common.execute(['chmod', '+x', child_script_path])

    # Execute the parent process script
    common.log("Executing the fake parent process script")
    subprocess.Popen([parent_process_path])

    # Allow some time for the network connection to be attempted
    time.sleep(5)
    common.log("RTA execution completed.")

    # Cleanup
    common.remove_file(parent_process_path)
    common.remove_file(child_script_path)


if __name__ == "__main__":
    exit(main())
