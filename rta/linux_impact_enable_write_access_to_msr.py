# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="cf8104ca-bd23-4652-b1f7-b63e3d92bc66",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "MSR Write Access Enabled",
            "rule_id": "4342c282-ee21-4140-8e27-4e0f551489ef",
        },
    ],
    techniques=["T1496", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/modprobe"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, 'msr', "allow_writes=on"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
