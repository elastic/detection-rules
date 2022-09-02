# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="54be1902-0608-49df-8053-40020d8a9210",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Potential Defense Evasion via Filter Manager Control Program",
            "rule_id": "5b39f347-077c-4a1e-8d3c-6f7789ca09e8",
        }
    ],
    siem=[],
    techniques=["T1562"],
)


@common.requires_os(metadata.platforms)
def main():

    # Execute command
    common.log("Executing ftlmc unload on non-exisiting driver")
    common.execute(["fltmc.exe", "unload", "ElasticNonExisting"], timeout=10)


if __name__ == "__main__":
    exit(main())
