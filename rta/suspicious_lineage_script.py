# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7961c43d-4dd8-45ec-b237-a940bf55d114",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'e7125cea-9fe1-42a5-9a05-b0792cf86f5a',
        'rule_name': 'Execution of Persistent Suspicious Program'
    }],
    techniques=['T1547', 'T1547.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    cscript = "C:\\Users\\Public\\cscript.exe"
    explorer = "C:\\Users\\Public\\explorer.exe"
    userinit = "C:\\Users\\Public\\userinit.exe"
    winlogon = "C:\\Users\\Public\\winlogon.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, cscript)
    common.copy_file(EXE_FILE, explorer)
    common.copy_file(EXE_FILE, userinit)
    common.copy_file(EXE_FILE, winlogon)
    common.copy_file(RENAMER, rcedit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, cscript, "--set-version-string", "OriginalFilename", "cscript.exe"])

    common.execute([winlogon, "/c", userinit], timeout=5, kill=True)
    common.execute([explorer, "/c", cscript], timeout=5, kill=True)
    common.remove_files(cscript, explorer, userinit, winlogon)


if __name__ == "__main__":
    exit(main())
