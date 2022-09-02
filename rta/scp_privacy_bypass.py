# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="75fec962-54a4-4bb1-80ea-995269e90b30",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Potential Privacy Control Bypass via Localhost Secure Copy",
            "rule_id": "55df8e91-fd3c-4cc1-b36f-f01ded8c6da3",
        }
    ],
    siem=[
        {
            "rule_name": "Potential Privacy Control Bypass via Localhost Secure Copy",
            "rule_id": "c02c8b9f-5e1d-463c-a1b0-04edcdfe1a3d",
        }
    ],
    techniques=["T1548"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/scp"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake commands to bypass privacy controls")
    common.execute(
        [masquerade, "StrictHostKeyChecking=no", "/tmp/scp test@localhost:/test"],
        timeout=10,
        kill=True,
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
