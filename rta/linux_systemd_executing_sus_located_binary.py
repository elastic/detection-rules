# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="5b277316-4584-4e4f-8a71-6c7d833e2c30",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Scheduled Job Executing Binary in Unusual Location",
            "rule_id": "f2a52d42-2410-468b-9910-26823c6ef822"
        }
    ],
    techniques=["T1543", "T1053"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Path for the fake systemd script
    fake_systemd = "/tmp/systemd"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Create a fake systemd script that launches sh
    with open(fake_systemd, 'w') as script:
        script.write('#!/bin/bash\n')
        script.write('/tmp/sh\n')

    # Make the script executable
    common.execute(['chmod', '+x', fake_systemd])
    common.execute(['chmod', '+x', masquerade])

    # Execute the fake systemd script
    common.log("Launching a shell that executes a payload as a child of fake systemd")
    common.execute([fake_systemd], timeout=5, kill=True, shell=True)

    # Cleanup
    common.remove_file(fake_systemd)


if __name__ == "__main__":
    exit(main())
