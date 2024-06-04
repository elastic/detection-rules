# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="0c55d2bd-924b-44a0-8f75-8fb6fc2427bf",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Scheduled Task Unusual Command Execution",
            "rule_id": "46b142a6-3d54-45e7-ad8a-7a4bc9bfe01c"
        }
    ],
    techniques=["T1053", "T1543", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Path for the fake systemd script
    fake_systemd = "/tmp/systemd"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Create a fake cron script that launches sh
    with open(fake_systemd, 'w') as script:
        script.write('#!/bin/bash\n')
        script.write('/tmp/sh -c "echo /dev/tcp/8.8.8.8/53"\n')

    # Make the script executable
    common.execute(['chmod', '+x', fake_systemd])

    # Execute the fake cron script
    common.log("Launching a shell that executes a payload as a child of fake systemd")
    common.execute([fake_systemd], timeout=5, kill=True, shell=True)

    # Cleanup
    common.remove_file(fake_systemd)


if __name__ == "__main__":
    exit(main())
