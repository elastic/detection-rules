# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="804463e7-b146-41ba-a757-d131d0a021ac",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Scheduled Task Creation via Microsoft Office",
            "rule_id": "f9fd002c-0dab-42ec-8675-0cf5af6b4a85",
        },
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "Potential Masquerading as SVCHOST", "rule_id": "5b00c9ba-9546-47cc-8f9f-1c1a3e95f65c"},
    ],
    siem=[],
    techniques=["T1036", "T1053", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    svchost = "C:\\Users\\Public\\svchost.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\taskschd.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    task = "C:\\Windows\\System32\\Tasks\\a.xml"
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, winword)
    common.copy_file(EXE_FILE, svchost)

    common.log("Modifying the OriginalFileName")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "taskschd.dll"])

    common.log("Loading taskschd.dll")
    common.execute([winword, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    common.execute([svchost, "-c", f"New-Item -Path {task} -Type File"], timeout=10)
    common.remove_files(dll, ps1, rcedit, task, winword, svchost)


if __name__ == "__main__":
    exit(main())
