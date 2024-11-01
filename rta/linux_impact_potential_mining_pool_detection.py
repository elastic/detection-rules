# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="5abebdea-b42e-4401-8838-15f19d11401f",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential Mining Pool Command Detection",
            "rule_id": "fcc42a61-4507-4918-867b-d673e5b065dc",
        },
    ],
    techniques=["T1496", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/dev/shm/evil"

    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "crypto-pool.info"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
