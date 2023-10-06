# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="bbad34f5-3542-4484-9b23-5ef05af94c0f",
    platforms=["windows"],
    endpoint=[{'rule_id': '08fba401-b76f-4c7b-9a88-4f3b17fe00c1', 'rule_name': 'DLL Loaded from an Archive File'}],
    siem=[],
    techniques=['T1204', 'T1204.002', 'T1574', 'T1574.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Users\\Public\\Temp\\7z\\"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = "C:\\Users\\Public\\Temp\\7z\\file.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\Temp\\7z\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    common.copy_file(user32, dll)
    common.copy_file(EXE_FILE, file)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    common.log("Modifying the OriginalFileName attribute to invalidate the signature")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.dll"])

    common.log("Loading unsigned DLL into fake taskhost")
    common.execute([file, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(dll, ps1, rcedit, file)


if __name__ == "__main__":
    exit(main())
