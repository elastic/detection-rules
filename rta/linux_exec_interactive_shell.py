# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="94366604-8f84-448e-9761-0eb7b45bc2fa",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Linux Suspicious Child Process Execution via Interactive Shell",
            "rule_id": "aa02591f-c9e6-4317-841e-0b075b9515ff",
        },
    ],
    siem=[],
    techniques=["T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/bash"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    commands = [masquerade, "-i"]

    # Execute command
    common.log("Launching fake command to simulate an interactive shell process")
    common.execute([*commands], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
