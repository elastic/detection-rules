# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="00a75607-9f1d-45c1-a9d8-41229cdb561f",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Suspicious Execution from Foomatic-rip or Cupsd Parent",
            "rule_id": "7c4d6361-3e7f-481a-9313-d1d1c0e5a3a9",
        },
    ],
    techniques=["T1203"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/foomatic-rip"

    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "/dev/tcp"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
