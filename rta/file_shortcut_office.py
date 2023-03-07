# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="3c4e5e5a-a6c2-4a78-b679-fd4a5781cfff",
    platforms=["windows"],
    endpoint=[{
        'rule_id': '9b13e135-51b4-4e4d-ac46-bb2e479438a6',
        'rule_name': 'Suspicious Shortcut File Creation by Microsoft Office'
    }],
    siem=[],
    techniques=['T1566', 'T1566.001', 'T1566.002', 'T1204', 'T1204.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    path = "C:\\Users\\Public\\Desktop"
    lnk = path + "\\a.lnk"
    os.makedirs(path, exist_ok=True)
    common.copy_file(EXE_FILE, winword)

    # Execute command
    common.execute([winword, "/c", f"Copy-Item {EXE_FILE} {lnk}"], timeout=10)
    common.remove_files(winword, lnk)


if __name__ == "__main__":
    exit(main())
