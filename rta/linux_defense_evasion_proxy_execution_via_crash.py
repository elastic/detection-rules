# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="fa40fdc4-23bf-491c-bc55-6a6848c5b6da",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Proxy Execution via Crash",
            "rule_id": "995c8bdb-5ebb-4c5b-9a03-4d39b52c0ff3",
        },
    ],
    techniques=["T1218", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/crash"
    masquerade2 = "/tmp/sh"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade2)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade2])

    commands = [masquerade, '-h', masquerade, '-c', 'whoami']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
