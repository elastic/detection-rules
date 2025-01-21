# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="5282c9a4-4ce9-48b8-863a-ff453143635a",
    platforms=["linux"],
    endpoint=[],
    siem=[{"rule_name": "Suspicious File Creation via kworker", "rule_id": "ae343298-97bc-47bc-9ea2-5f2ad831c16e"}],
    techniques=["T1547", "T1014"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/kworker"
    source = common.get_path("bin", "create_file.elf")
    common.copy_file(source, masquerade)

    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "/tmp/evil"]

    common.log("Simulating file creation activity..")
    common.execute([*commands], timeout=5)
    common.log("File creation simulation successful!")
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("RTA completed!")


if __name__ == "__main__":
    sys.exit(main())
