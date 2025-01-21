# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="1b24ddc7-c01c-4d24-a00e-0738a40b6dd6",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Network Connection Followed by Command Execution",
            "rule_id": "8c2977dd-07ce-4a8e-8ccd-5e4183138675",
        },
    ],
    techniques=["T1071", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/dev/shm/netcon"
    masquerade2 = "/dev/shm/bash"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    source2 = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.copy_file(source2, masquerade2)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])
    common.execute(["chmod", "+x", masquerade2])

    commands = [masquerade2, masquerade, "chain", "-h", "8.8.8.8", "-p", "53", "-c", "whoami"]
    common.execute([*commands], timeout=5, kill=True, shell=True)  # noqa: S604
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
