# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="4f705092-fae2-4455-94ab-e42fb13496e7",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Proxy Execution via Pidstat",
            "rule_id": "436e12a8-7a03-4f6f-a3b2-3fe8b8f4c474",
        },
    ],
    techniques=["T1218", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/pidstat"
    masquerade2 = "/tmp/sh"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade2)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade2])

    commands = [masquerade, "-e", masquerade, "-c", "whoami"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
