# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="fcd2d0fe-fed2-424a-bdc5-e9bef5031344",
    platforms=["linux"],
    endpoint=[{"rule_name": "Network Activity Detected via cat", "rule_id": "25ae94f5-0214-4bf1-b534-33d4ffc3d41c"}],
    siem=[{"rule_name": "Network Activity Detected via cat", "rule_id": "afd04601-12fc-4149-9b78-9c3f8fe45d39"}],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    common.log("Creating a fake cat executable..")
    masquerade = "/tmp/cat"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])
    common.log("Simulating cat network activity..")
    common.execute([masquerade, "netcon", "-h", "8.8.8.8", "-p", "53"], timeout=10, kill=True, shell=True)  # noqa: S604
    common.log("Cat network simulation successful!")
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("RTA completed!")


if __name__ == "__main__":
    sys.exit(main())
