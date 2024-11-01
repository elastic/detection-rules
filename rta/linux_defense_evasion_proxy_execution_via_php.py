# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="4b186cd2-eebf-4a93-b85d-ba3b3746bf50",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Proxy Execution via PHP",
            "rule_id": "dd914805-e99b-4ff6-b445-775c53d44e10",
        },
    ],
    techniques=["T1218", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/php"
    masquerade2 = "/tmp/sh"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade2)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade2])

    commands = [masquerade, "-r", masquerade2, "-c", "whoami"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
