# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9d02871f-6338-47aa-84c4-7d622692319f",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Modification of Safari Settings via Defaults Command",
            "rule_id": "396e1138-243c-4215-a8ed-be303204710d",
        }
    ],
    siem=[
        {
            "rule_name": "Modification of Safari Settings via Defaults Command",
            "rule_id": "6482255d-f468-45ea-a5b3-d3a7de1331ae",
        }
    ],
    techniques=["T1562"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/defaults"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching commands to mimic defaults modifying safari configurations.")
    common.execute([masquerade, "write", "com.apple.Safari", "JavaScript"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
