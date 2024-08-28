# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="3d387400-3fc4-457f-92cd-8ba77271b348",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Egress Network Connection from Default DPKG Directory",
            "rule_id": "947b70bb-8e01-4f1b-994d-5af9488556bb",
        },
    ],
    techniques=["T1546", "T1543", "T1574", "T1195", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    # Ensure the /var/lib/dpkg/info/ directory exists
    dpkg_info_dir = "/var/lib/dpkg/info/"
    if not Path(dpkg_info_dir).exists():
        common.log(f"Creating directory {dpkg_info_dir}")
        Path(dpkg_info_dir).mkdir(parents=True, exist_ok=True)

    # Path for the fake DPKG package executable
    masquerade = str(Path(dpkg_info_dir) / "rta")
    source = common.get_path("bin", "netcon_exec_chain.elf")

    common.log("Creating a fake DPKG package..")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    # Execute the fake DPKG package
    common.log("Executing the fake DPKG package..")
    commands = [
        masquerade,
        "chain",
        "-h",
        "8.8.8.8",
        "-p",
        "53",
        "-c",
        "/var/lib/dpkg/info/rta netcon -h 8.8.8.8 -p 53",
    ]
    common.execute([*commands], timeout=5, kill=True)

    # Cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
