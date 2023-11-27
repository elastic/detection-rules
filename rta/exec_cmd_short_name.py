# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="f62ebacb-5d53-4f74-ae72-b64b8b6c899f",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '17c7f6a5-5bc9-4e1f-92bf-13632d24384d',
        'rule_name': 'Suspicious Execution - Short Program Name'
    }],
    techniques=['T1036', 'T1036.003'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    rta = "C:\\Users\\Public\\a.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, rta)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, rta, "--set-version-string", "OriginalFilename", "rta.exe"])

    common.execute([rta], timeout=2, kill=True)

    common.remove_files(rcedit, rta)


if __name__ == "__main__":
    exit(main())
