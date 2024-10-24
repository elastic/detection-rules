# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="1843a19e-1016-4784-a175-e9fdf26f4b8f",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Shared Object Load via LoLBin",
            "rule_id": "42c2e98b-b757-423f-ac25-8183d8c76b97",
        },
    ],
    techniques=["T1218", "T1574", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/gdb"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, 'cdll.LoadLibrary.so']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
