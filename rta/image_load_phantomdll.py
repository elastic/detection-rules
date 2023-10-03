# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="dabd91c9-101e-475d-b2f2-ca255abda003",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'bfeaf89b-a2a7-48a3-817f-e41829dc61ee',
        'rule_name': 'Suspicious DLL Loaded for Persistence or Privilege Escalation'
    }],
    techniques=['T1574', 'T1574.002', 'T1574', 'T1574.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wlbsctrl.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, proc)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "wlbsctrl.dll"])

    common.log("Loading wlbsctrl.dll into fake proc")
    common.execute([proc, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    common.remove_files(proc, dll, ps1)


if __name__ == "__main__":
    exit(main())
