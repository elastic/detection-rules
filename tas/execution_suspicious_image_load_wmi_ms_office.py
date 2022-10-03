# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6b2a89eb-9c8a-4fa3-b4ac-900df6a0dc76",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '891cb88e-441a-4c3e-be2d-120d99fe7b0d', 'rule_name': 'Suspicious WMI Image Load from MS Office'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wmiutils.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(user32, dll)
    common.copy_file(EXE_FILE, winword)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "wmiutils.dll"])

    common.log("Loading System.DirectoryServices.Protocols.test.dll")
    common.execute([winword, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(dll, ps1, rcedit, winword)


if __name__ == "__main__":
    exit(main())
