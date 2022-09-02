# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="245fcf03-6df8-4731-af94-f2ba4ed60670",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Unusual File Written or Modified in Startup Folder",
            "rule_id": "30a90136-7831-41c3-a2aa-1a303c1186ac",
        },
        {"rule_name": "Network Connection via Startup Item", "rule_id": "0b33141a-3f73-4414-ba90-d8410e6ab176"},
    ],
    siem=[],
    techniques=["T1547", "T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    posh = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\posh.exe"
    common.copy_file(EXE_FILE, posh)

    common.execute(
        [
            posh,
            "/c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout=10,
    )
    common.remove_files(posh)


if __name__ == "__main__":
    exit(main())
