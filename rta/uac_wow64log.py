# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ab957b94-2c39-49dd-93cf-f1e40394ff1b",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "UAC Bypass Attempt via WOW64 Logger DLL Side-Loading",
            "rule_id": "28a39a43-e850-4941-8605-ffa23dcfd25a",
        }
    ],
    siem=[],
    techniques=["T1574", "T1548"],
)

PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wow64log.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    common.log("Modifying the OriginalFileName attribute to invalidate the signature")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "wow64log.dll"])

    common.log("Loading wow64log.dll and spawning a high integrity process")
    common.execute(
        [powershell, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}; powershell"],
        timeout=10,
    )

    common.remove_files(dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
