# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="8c634401-fd71-475e-b449-41b776b2b8c9",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Network Connection by Foomatic-rip Child",
            "rule_id": "93d7b72d-3914-44fb-92bf-63675769ef12",
        },
    ],
    techniques=["T1203"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Path for the fake motd executable
    masquerade = "/tmp/foomatic-rip"
    source = common.get_path("bin", "netcon_exec_chain.elf")

    common.log("Creating a fake motd executable..")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    # Execute the fake motd executable
    common.log("Executing the fake motd executable..")
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "53", "-c", "/tmp/foomatic-rip netcon -h 8.8.8.8 -p 53"]
    common.execute([*commands], timeout=5, kill=True)

    # Cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
