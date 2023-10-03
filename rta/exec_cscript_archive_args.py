# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4aa158f6-39ed-456f-9d8a-849052cce2f5",
    platforms=["windows"],
    endpoint=[
        {'rule_id': '816e1e39-e1a3-4935-9b7b-18395d244670', 'rule_name': 'Windows Script Execution from Archive File'},
        {'rule_id': '16c84e67-e5e7-44ff-aefa-4d771bcafc0c', 'rule_name': 'Execution from Unusual Directory'},
        {'rule_id': '35dedf0c-8db6-4d70-b2dc-a133b808211f', 'rule_name': 'Binary Masquerading via Untrusted Path'},
        {'rule_id': '23e29d07-7584-465e-8a6d-912d9ea254a6', 'rule_name': 'Suspicious Image Load via Windows Scripts'}
    ],
    siem=[],
    techniques=['T1059', 'T1059.007', 'T1566', 'T1566.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    cscript = "C:\\Users\\Public\\cscript.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, cscript)
    common.copy_file(RENAMER, rcedit)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, cscript, "--set-version-string", "OriginalFilename", "cscript.exe"])

    common.execute([cscript, "/c", "echo", "C:\\Users\\A\\Temp\\7zip"], timeout=5, kill=True)
    common.remove_files(cscript)


if __name__ == "__main__":
    exit(main())
