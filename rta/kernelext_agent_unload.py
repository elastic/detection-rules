# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="61f308d8-40c5-4c46-9181-e993cf07e92b",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Attempt to Unload Elastic Endpoint Security Kernel Extension",
            "rule_id": "a412fd9b-2a06-49ff-a073-8eb313c2d930",
        }
    ],
    siem=[
        {
            "rule_name": "Attempt to Unload Elastic Endpoint Security Kernel Extension",
            "rule_id": "70fa1af4-27fd-4f26-bd03-50b6af6b9e24",
        }
    ],
    techniques=["T1547", "T1562"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/kextunload"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake kernel ext commands to unload elastic agent")
    common.execute([masquerade, "EndpointSecurity.kext"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
