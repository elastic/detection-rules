# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="057f2c1b-28cc-4286-92ce-75e789aa8e74",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Potential Kerberos Attack via Bifrost", "rule_id": "fecebe4f-2d28-46e7-9bc1-71cdd8ecdd60"}
    ],
    siem=[{"rule_name": "Potential Kerberos Attack via Bifrost", "rule_id": "16904215-2c95-4ac8-bf5c-12354e047192"}],
    techniques=["T1558", "T1550"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/bifrost"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake bifrost attack with kerberoast commands")
    common.execute([masquerade, "-action", "-kerberoast"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
