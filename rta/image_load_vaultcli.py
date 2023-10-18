# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2145af1a-0781-47ab-8d73-2d50e93b5ff7",
    platforms=["windows"],
    endpoint=[
        {'rule_id': '048737fe-80d6-4462-aa80-ffeed853103e', 'rule_name': 'Suspicious Vault Client Image Load'},
        {'rule_id': '65784f6e-247a-466b-bbfb-cd92024f7e82', 'rule_name': 'Suspicious PowerShell Execution'}
    ],
    siem=[],
    techniques=['T1555', 'T1555.004', 'T1059', 'T1059.001'],
)
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\vaultcli.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "vaultcli.dll"])

    common.log("Loading vaultcli.dll")
    common.execute([powershell, "-c", f"echo downloadstring; Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
