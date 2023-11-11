# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="900e8599-1d5f-4522-9aed-6eab82de2bad",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Kernel Module Removal",
            "rule_id": "e80ba5e4-b6c6-4534-87b0-8c0f4e1d97e7",
        }
    ],
    siem=[
        {
            "rule_name": "Kernel Module Removal",
            "rule_id": "cd66a5af-e34b-4bb0-8931-57d0a043f2ef"
        }
    ],
    techniques=["T1562", "T1562.001", "T1547", "T1547.006"],
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/rmmod"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake commands to remove Kernel Module")
    common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
