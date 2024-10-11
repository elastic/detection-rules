# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="96afe4b1-d8f3-4f95-b92b-645a39508174",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Hidden Executable Initiated Egress Network Connection",
            "rule_id": "c14705f7-ebd3-4cf7-88b3-6bff2d832f1b",
        },
    ],
    techniques=["T1564"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "netcon", "-h", "8.8.8.8", "-p", "53"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
