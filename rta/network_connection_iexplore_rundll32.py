# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="9182299f-cebf-4d8b-97a8-15ec5e11fe14",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'acd611f3-2b93-47b3-a0a3-7723bcc46f6d',
        'rule_name': 'Potential Command and Control via Internet Explorer'
    }],
    techniques=['T1071', 'T1559', 'T1559.001'],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    iexplore = "C:\\Users\\Public\\iexplore.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\IEProxy.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, rundll32)
    common.copy_file(EXE_FILE, iexplore)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "IEProxy.dll"])

    common.log("Loading IEProxy.dll")
    common.execute([rundll32, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.execute([iexplore, "/c", "echo", "-Embedding", f";{iexplore}"], timeout=2, kill=True)
    common.execute([iexplore, "/c", "Test-NetConnection -ComputerName google.com -Port 443"], timeout=10)

    common.remove_files(dll, ps1, rcedit, rundll32, iexplore)


if __name__ == "__main__":
    exit(main())
