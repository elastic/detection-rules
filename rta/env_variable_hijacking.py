# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a18454da-5f28-4223-95d6-5dc1f58c861a",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Modification of Environment Variable via Launchctl",
            "rule_id": "7453e19e-3dbf-4e4e-9ae0-33d6c6ed15e1",
        }
    ],
    techniques=["T1574"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/launchctl"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake launchctl command to mimic env variable hijacking")
    common.execute([masquerade, "setenv"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
