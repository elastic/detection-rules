# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import time


metadata = RtaMetadata(
    uuid="c80653a4-26fa-4a9e-b06c-12d12680c4e7",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': '68218637-3940-42cb-b2b7-0610fc1dde56',
            'rule_name': 'DLL Side Loading of a file dropped by Microsoft Office'
        },
        {
            'rule_id': '37c54ca7-e96d-4fd5-92d3-08cab38516b7',
            'rule_name': 'Suspicious Executable File Creation'
        }
    ],
    siem=[],
    techniques=[
        'T1574', 'T1574.001', 'T1574.002', 'T1566', 'T1566.001', 'T1105', 'T1059', 'T1059.005', 'T1059.007'
    ],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\targetdll.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    common.copy_file(EXE_FILE, winword)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    common.execute([winword, "/c", f"Copy-Item {user32} '{dll}'"])

    common.log("Modifying the OriginalFileName attribute to invalidate the signature")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.dll"])

    common.log("Loading targetdll.dll into fake proc")
    common.execute([powershell, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    time.sleep(3)
    common.remove_files(rcedit, dll, ps1, winword)


if __name__ == "__main__":
    exit(main())
