# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4ad6b308-f457-4805-89b9-43b99e32b24f",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Microsoft Office Loaded a Dropped Executable File",
            "rule_id": "a0a82ad6-98ed-4426-abd8-52e7b052e297",
        }
    ],
    siem=[],
    techniques=["T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\a.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    common.copy_file(EXE_FILE, winword)
    common.copy_file(PS1_FILE, ps1)

    common.log("Droping and Loading a.dll into fake winword")
    common.execute(
        [
            winword,
            "-c",
            f"Copy-Item {user32} {dll}; Import-Module {ps1}; Invoke-ImageLoad {dll}",
        ],
        timeout=10,
    )

    common.remove_files(winword, dll, ps1)


if __name__ == "__main__":
    exit(main())
