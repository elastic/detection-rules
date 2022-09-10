# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1ccbd3c6-69c8-4476-b5e5-da3d167a09f1",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Suspicious Windows Defender Exclusions Added via PowerShell",
            "rule_id": "2ad8b514-baf0-4e29-a712-d6734868aa57",
        }
    ],
    siem=[],
    techniques=["T1562", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, posh)

    cmd = "powershell -c Add-MpPreference -ExclusionPath"
    # Execute command
    common.execute([posh, "/c", cmd], timeout=10)
    common.remove_file(posh)


if __name__ == "__main__":
    exit(main())
