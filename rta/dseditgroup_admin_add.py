# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d5643e8a-c3f5-48a7-9f64-7255f603a24a",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Potential Admin Group Account Addition", "rule_id": "565c2b44-7a21-4818-955f-8d4737967d2e"}],
    techniques=["T1078"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/dseditgroup"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake dseditgroup commands to mimic adding a user to an admin group")
    common.execute([masquerade, "admin", "-append"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
