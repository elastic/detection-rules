# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="465eb9a9-2f8b-458b-9ea4-e50912ce1b89",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae4',
        'rule_name': 'Microsoft Build Engine Using an Alternate Name'
    }],
    techniques=['T1036', 'T1036.003'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    msbuild = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, msbuild)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, msbuild, "--set-version-string", "OriginalFilename", "MSBuild.exe"])

    common.execute([msbuild], timeout=2, kill=True)

    common.remove_files(rcedit, msbuild)


if __name__ == "__main__":
    exit(main())
