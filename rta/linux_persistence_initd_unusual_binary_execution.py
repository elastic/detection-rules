# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="0560d795-bdd6-4a91-97ad-8e2c2d8143ef",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "System V Init (init.d) Executed Binary from Unusual Location",
            "rule_id": "879c083c-e2d9-4f75-84f2-0f1471d915a8"
        }
    ],
    techniques=["T1037"],
)


@common.requires_os(*metadata.platforms)
def main():

    # Path for the fake initd script
    initd_script = "/etc/init.d/rta"

    # Create fake executable
    masquerade = "/dev/shm/evil"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Create a fake script that executes the fake binary
    with open(initd_script, 'w') as script:
        script.write('#!/bin/bash\n')
        script.write('/dev/shm/evil\n')

    # Make the script executable
    common.execute(['chmod', '+x', initd_script])

    # Execute the fake script
    common.log("Launching fake initd script")
    common.execute([initd_script], timeout=5, kill=True, shell=True)

    # Cleanup
    common.remove_file(initd_script)
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
