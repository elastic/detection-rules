# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c5a8bbf2-0920-40ee-a08f-f897c2895eba",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '1160dcdb-0a0a-4a79-91d8-9b84616edebd',
        'rule_name': 'Potential DLL SideLoading via Trusted Microsoft Programs'
    }],
    techniques=['T1036'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, winword)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, winword, "--set-version-string", "OriginalFilename", "WinWord.exe"])

    common.execute([winword], timeout=2, kill=True)

    common.remove_files(rcedit, winword)


if __name__ == "__main__":
    exit(main())
