# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d00ef4d9-4690-4eb1-aa60-7ff3ce3bd75b",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Creation of Hidden Login Item via Apple Script",
            "rule_id": "f24bcae1-8980-4b30-b5dd-f851b055c9e7",
        }
    ],
    techniques=["T1547", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/bash"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake osascript commands to mimic hidden file creation")
    common.execute(
        [masquerade, "childprocess", "osascript login item hidden:true"],
        shell=True,
        timeout=5,
        kill=True,
    )

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
