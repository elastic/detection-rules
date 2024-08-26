# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="c2b89791-5c51-4965-a440-cd9905bfbe55",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Hidden Payload Executed via Cron",
            "rule_id": "e8b2afe5-37a9-468c-a6fb-f178d46cb698",
        },
    ],
    techniques=["T1053"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Path for the fake cron script
    fake_cron = "/tmp/cron"

    # Create fake sh executable
    masquerade = "/tmp/sh"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Create a fake cron script that launches sh
    with Path(fake_cron).open("w", encoding="utf-8") as script:
        script.write("#!/bin/bash\n")
        script.write("/tmp/sh -c '/dev/shm/.foo'\n")

    # Make the script executable
    common.execute(["chmod", "+x", fake_cron])

    # Execute the fake cron script
    common.log("Launching a shell that executes a hidden payload as a child of fake cron")
    common.execute([fake_cron], timeout=5, kill=True, shell=True)  # noqa: S604

    # Cleanup
    common.remove_file(fake_cron)


if __name__ == "__main__":
    sys.exit(main())
