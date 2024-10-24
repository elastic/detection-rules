# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="9e7ec69a-50cb-4bce-8ace-50e4e6f0199d",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Renice or Ulimit Execution",
            "rule_id": "57ed0e43-643a-47f3-936e-138dc6f480da",
        },
    ],
    techniques=["T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/dev/shm/evil"

    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.execute(["chmod", "+x", masquerade])

    masquerade2 = "/dev/shm/renice"
    common.copy_file(source, masquerade2)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade2])

    commands = [masquerade, "exec", "-c", "/dev/shm/renice"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
