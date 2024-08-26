# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="ac1f9204-f612-4d50-9de0-6dabcd589816",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "System V Init (init.d) Egress Network Connection",
            "rule_id": "b38eb534-230c-45f4-93ba-fc516ac51630",
        },
    ],
    techniques=["T1037", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Path for the fake initd executable
    masquerade = "/etc/init.d/rta"
    source = common.get_path("bin", "netcon_exec_chain.elf")

    common.log("Creating a fake initd executable..")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    # Execute the fake initd executable
    common.log("Executing the fake initd executable..")
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "53", "-c", "/etc/init.d/rta netcon -h 8.8.8.8 -p 53"]
    common.execute([*commands], timeout=5, kill=True)

    # Cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
