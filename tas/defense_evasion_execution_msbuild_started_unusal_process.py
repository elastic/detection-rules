# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7fadb6f4-a7e6-40c3-b8d7-1d731b46c406",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae6', 'rule_name': 'Microsoft Build Engine Started an Unusual Process'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    msbuild = "C:\\Users\\Public\\msbuild.exe"
    csc = "C:\\Users\\Public\\csc.exe"
    common.copy_file(EXE_FILE, msbuild)
    common.copy_file(EXE_FILE, csc)

    # Execute command
    common.execute([msbuild, "/c", csc], timeout=2, kill=True)
    common.remove_files(msbuild, csc)


if __name__ == "__main__":
    exit(main())
