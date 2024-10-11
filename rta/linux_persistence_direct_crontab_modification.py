# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a1286125-bf4b-40bb-819a-b7c5de83fafb",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Persistence via Direct Crontab Modification",
            "rule_id": "b3bcbab6-e216-4d70-bdee-2b69affbb386",
        },
    ],
    techniques=["T1053"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Path for the fake script
    rta_script = "/dev/shm/rta"

    # Create fake executable
    masquerade = "/tmp/crontab"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.execute(["chmod", "+x", masquerade])

    # Create a fake script that executes the fake binary
    with Path(rta_script).open("w", encoding="utf-8") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/crontab -\n")

    # Make the script executable
    common.execute(["chmod", "+x", rta_script])

    # Execute the fake script
    common.log("Launching fake script")
    common.execute([rta_script], timeout=5, kill=True, shell=True)  # noqa: S604

    # Cleanup
    common.remove_file(rta_script)
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
