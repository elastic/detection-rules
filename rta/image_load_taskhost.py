# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9cca3284-848f-483a-9241-48562eee0605",
    platforms=["windows"],
    endpoint=[{
        'rule_id': '4b4ba027-151f-40e4-99ba-a386735c27e4',
        'rule_name': 'Unsigned DLL Loaded by Windows Tasks Host'
    }],
    siem=[],
    techniques=['T1053', 'T1053.005'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    taskhost1 = "C:\\Users\\Public\\taskhost1.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(user32, dll)
    common.copy_file(EXE_FILE, taskhost1)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.dll"])

    common.log("Loading unsigned DLL into fake taskhost")
    common.execute([taskhost1, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
