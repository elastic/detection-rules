# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="83332fb4-2299-4584-b5f3-7e0264d034f7",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '2c3c29a4-f170-42f8-a3d8-2ceebc18eb6a',
        'rule_name': 'Suspicious Microsoft Diagnostics Wizard Execution'
    }],
    techniques=['T1218'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    msdt = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, msdt)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, msdt, "--set-version-string", "OriginalFilename", "msdt.exe"])

    common.execute([msdt], timeout=2, kill=True)

    common.remove_files(rcedit, msdt)


if __name__ == "__main__":
    exit(main())
