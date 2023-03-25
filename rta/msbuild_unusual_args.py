# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="511278ac-4996-438e-ba03-bef8f10665b5",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution via Renamed Signed Binary Proxy", "rule_id": "b0207677-5041-470b-981d-13ab956cf5b4"},
        {"rule_name": "MSBuild with Unusual Arguments", "rule_id": "6518cdaf-e6cd-4cf9-a51e-043117c3dbeb"},
    ],
    siem=[],
    techniques=["T1127", "T1218"],
)

RENAMER = common.get_path("bin", "rcedit-x64.exe")
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    msbuild = "C:\\Users\\Public\\posh.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, msbuild)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, msbuild, "--set-version-string", "OriginalFilename", "MSBuild.exe"])

    common.log("Executing modified binary with extexport.exe original file name")
    common.execute([msbuild, "-Version"], timeout=10, kill=True)

    common.remove_files(msbuild, rcedit)


if __name__ == "__main__":
    exit(main())
