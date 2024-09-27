# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a2217fc5-7105-4457-98fe-1cd5f810dc1a",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Suspicious Echo Execution",
            "rule_id": "a13c8f01-36a5-4ad7-a282-8d297cf62860",
        },
    ],
    techniques=["T1543", "T1053", "T1037", "T1546"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/sh"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "-c", "echo /dev/tcp/foo"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
