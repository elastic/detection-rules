# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="cd549ba9-63be-4eff-ab6c-f567445e1977",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Script Execution via MSXSL", "rule_id": "de3615bc-4e50-485e-b3b5-8548ef6faa3d"},
    ],
    siem=[],
    techniques=["T1220", "T1218", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    msxsl = "C:\\Users\\Public\\msxsl.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\scrobj.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, msxsl)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, msxsl, "--set-version-string", "OriginalFilename", "msxsl.exe"])

    common.log("Loading scrobj.dll into fake msxsl")
    common.execute([msxsl, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(msxsl, dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
