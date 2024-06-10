# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import pathlib
import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="fb5cd755-cc31-4142-969a-cd14d3142b36",
    platforms=["linux"],
    endpoint=[
        {"rule_id": "aec74eb4-9618-42ff-96eb-2d13e6959d47", "rule_name": "Potential VScode Remote Tunnel Established"},
    ],
    siem=[],
    techniques=["T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "code_tunnel.json"
    working_dir = "/tmp/fake_folder/code"
    source = common.get_path("bin", "linux.ditto_and_spawn")

    # Execute command
    common.log("Executing Fake commands to test Potential VScode Remote Tunnel Established")
    pathlib.Path(working_dir).mkdir(parents=True, exist_ok=True)
    os.chdir(working_dir)
    common.copy_file(source, masquerade)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
