# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="aa6bf766-db74-4db5-8eec-f91386b1285b",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "Scriptlet Execution via CMSTP", "rule_id": "8adfa9ad-0ed2-4b1b-bdad-f2c52e1d2a00"},
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    cmstp = "C:\\Users\\Public\\cmstp.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\scrobj.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, cmstp)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, cmstp, "--set-version-string", "OriginalFilename", "CMSTP.EXE"])

    common.log("Loading scrobj.dll into fake cmstp")
    common.execute([cmstp, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(cmstp, dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
