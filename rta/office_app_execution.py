# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1a483c55-443d-4d01-a9de-e2c69df744f3",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Initial Access or Execution via Microsoft Office Application",
            "rule_id": "64021ef9-19d3-4797-ac3c-79e38d5e5a5a",
        }
    ],
    siem=[],
    techniques=["T1105", "T1140", "T1027", "T1566", "T1547", "T1204", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/Microsoft PowerPoint"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake Microsoft Office process")
    common.execute([masquerade], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
