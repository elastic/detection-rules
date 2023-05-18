# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d64b9c0c-d4be-4af2-b820-233493fb7d75",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Inhibit System Recovery via Windows Command Shell",
            "rule_id": "d3588fad-43ae-4f2d-badd-15a27df72133",
        }
    ],
    siem=[],
    techniques=["T1490", "T1047", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    vssadmin = "C:\\Windows\\System32\\vssadmin.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"

    # Execute command
    common.log("Deleting Shadow Copies using Vssadmin spawned by cmd")
    common.execute([cmd, "/c", vssadmin, "delete", "shadows", "/For=C:"], timeout=10)


if __name__ == "__main__":
    exit(main())
