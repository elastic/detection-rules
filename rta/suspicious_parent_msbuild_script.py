# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="aafeb270-4704-4b5f-aa1b-1286dc14c5a9",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae2',
        'rule_name': 'Microsoft Build Engine Started by a Script Process'
    }],
    techniques=['T1127', 'T1127.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Users\\Public\\powershell.exe"
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    common.copy_file(EXE_FILE, powershell)
    common.copy_file(EXE_FILE, msbuild)

    # Execute command
    common.execute([powershell, "/c", msbuild], timeout=2, kill=True)
    common.remove_files(powershell, msbuild)


if __name__ == "__main__":
    exit(main())
