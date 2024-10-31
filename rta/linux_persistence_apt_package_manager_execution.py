# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="305b2daa-2ef4-4cdd-8ed2-d751174cbdcc",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "APT Package Manager Command Execution",
            "rule_id": "cd0844ea-6112-453f-a836-cc021a2b6afb",
        },
    ],
    techniques=["T1543", "T1059", "T1546"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake apt executable..")
    masquerade = "/tmp/apt"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    common.log("Creating a fake openssl executable..")
    masquerade2 = "/tmp/openssl"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade2)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade2])

    commands = [masquerade, "exec", "-c", "/tmp/openssl"]
    common.execute([*commands], timeout=5, kill=True)

    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.remove_file(masquerade2)

    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
